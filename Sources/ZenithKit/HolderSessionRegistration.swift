#if os(macOS)
import Darwin
import Foundation

/// Separate descriptor from the legacy owner-bootstrap provider. Its presence
/// selects the member path explicitly; a failed member request never falls back.
public struct HolderSessionRegistration: Decodable, Sendable {
  public struct Agent: Decodable, Sendable { let binary: SessionProviderRegistration.FilePin; let profile: SessionProviderRegistration.FilePin }
  public let schema: String, mode: String, profile_digest_sha256: String
  public let provider: HolderIssuerPin, context: HolderSessionContext
  public let launch: SessionProviderRegistration.Launch
  public let agent: Agent
  private var descriptorFile: URL?
  private var descriptorDigest: String?
  private func url(_ pin: SessionProviderRegistration.FilePin) -> URL { URL(fileURLWithPath: pin.path) }
  public static func loadIfPresent(directory: URL) throws -> Self? {
    let file = directory.appendingPathComponent("holder-session-provider.json")
    let fd = open(file.path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
    if fd < 0 { if errno == ENOENT { return nil }; throw HolderSessionError.invalid }
    let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true); var info = stat()
    guard fstat(fd, &info) == 0, info.st_uid == getuid(), info.st_mode & S_IFMT == S_IFREG,
      info.st_nlink == 1, info.st_mode & 0o077 == 0, info.st_size > 0, info.st_size <= 524288,
      let bytes = try handle.readToEnd(), bytes.count <= 524288 else { throw HolderSessionError.invalid }
    var value = try decode(bytes); value.descriptorFile = file; value.descriptorDigest = HS.digest(bytes); return value
  }
  public static func decode(_ bytes: Data) throws -> Self {
    var strict = HolderSessionJSON(bytes, maximumBytes: 524288, maximumKeys: 32, maximumArray: 1024, maximumDepth: 12); try strict.validate()
    guard let v = try JSONSerialization.jsonObject(with: bytes) as? [String: Any] else { throw HolderSessionError.invalid }
    try HS.keys(v, "schema mode provider context profile_digest_sha256 launch agent")
    let value = try JSONDecoder().decode(Self.self, from: bytes)
    guard value.schema == "zenith.holder-session-provider-registration.v1", ["disposable", "production"].contains(value.mode),
      value.context.origin == "app://zenith-transfer", value.context.audience == "devgraph",
      value.profile_digest_sha256 == value.launch.profile.sha256 else { throw HolderSessionError.changed }
    _ = try HS.pin(v["provider"]); _ = try HS.hex(value.profile_digest_sha256, 64)
    guard let launch = v["launch"] as? [String: Any], let agent = v["agent"] as? [String: Any], let context = v["context"] as? [String: Any] else { throw HolderSessionError.invalid }
    try HS.keys(launch, "interpreter script profile sources"); try HS.keys(agent, "binary profile"); try HS.keys(context, "origin audience")
    let pins = [value.launch.interpreter, value.launch.script, value.launch.profile, value.agent.binary, value.agent.profile] + value.launch.sources
    guard !value.launch.sources.isEmpty, value.launch.sources.count < 1024, Set(value.launch.sources.map(\.path)).count == value.launch.sources.count else { throw HolderSessionError.invalid }
    for pin in pins {
      guard pin.path.hasPrefix("/"), !pin.path.utf8.contains(0), URL(fileURLWithPath: pin.path).standardizedFileURL.path == pin.path else { throw HolderSessionError.invalid }
      _ = try HS.hex(pin.sha256, 64)
    }
    return value
  }
  private func process() throws -> SessionProviderProcess {
    var sources = Dictionary(uniqueKeysWithValues: launch.sources.map { (url($0), $0.sha256) })
    if let descriptorFile, let descriptorDigest { sources[descriptorFile] = descriptorDigest }
    let config = SessionProviderLaunch(interpreter: url(launch.interpreter), script: url(launch.script), profile: url(launch.profile),
      interpreterSHA256: launch.interpreter.sha256, scriptSHA256: launch.script.sha256, profileSHA256: launch.profile.sha256, sources: sources)
    try config.validate()
    let raw = try Data(contentsOf: url(launch.profile)), p = try HS.object(raw)
    guard HS.digest(raw) == profile_digest_sha256, try HS.pin(p["provider"]) == provider,
      let context = p["context"] as? [String: Any], context["origin"] as? String == self.context.origin,
      context["audience"] as? String == self.context.audience else { throw HolderSessionError.changed }
    return SessionProviderProcess(launch: config)
  }
  public func maximumLifetime() throws -> UInt64 {
    let selected = HolderSessionAgentLaunch(executable: url(agent.binary), profileFile: url(agent.profile), executableSHA256: agent.binary.sha256, profileSHA256: agent.profile.sha256)
    let p = try selected.validate()
    guard p.provider == provider, p.context == context else { throw HolderSessionError.changed }
    return p.maximumSessionSeconds
  }
  public func services() async throws -> [SessionReviewService] {
    let process = try process(); let client = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
    let issuer = try LocalHolderSessionIssuer(process: process, clientID: client, pin: provider, context: context)
    do { let values = try await issuer.services(); await process.stop(); return values.map { .init(service: $0.service, name: $0.name, readAvailable: true, writeAvailable: false) } }
    catch { await process.stop(); throw error }
  }
  public func flow(client: String, wallet: any WalletSession, directory: URL) throws -> HolderSessionFlow {
    let profile = HolderSessionAgentLaunch(executable: url(agent.binary), profileFile: url(agent.profile), executableSHA256: agent.binary.sha256, profileSHA256: agent.profile.sha256)
    let checked = try profile.validate()
    guard checked.provider == provider, checked.context == context else { throw HolderSessionError.changed }
    let issuer = try LocalHolderSessionIssuer(process: process(), clientID: client, pin: provider, context: context)
    return try HolderSessionFlow(clientID: client, requestID: UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased(),
      service: provider.service, context: context, wallet: NativeHolderSessionWalletPort(wallet: wallet),
      custody: HolderSessionAgentProcess(launch: profile), issuer: issuer, journal: HolderSessionJournal(directory: directory))
  }
}
#endif
