#if os(macOS)
import Darwin
import Foundation

/// Reviewed application configuration, never an MCP request or Wallet backup.
/// Loading verifies the descriptor and source bytes; it does not start a child.
public struct SessionProviderRegistration: Decodable, Sendable {
  public struct FilePin: Decodable, Sendable {
    public let path: String, sha256: String
    fileprivate var url: URL { URL(fileURLWithPath: path) }
  }
  public struct Launch: Decodable, Sendable {
    public let interpreter: FilePin, script: FilePin, profile: FilePin
    public let sources: [FilePin]
  }
  public let schema: String, mode: String, profile_digest_sha256: String
  public let provider: HolderIssuerPin
  public let receiver_pin: ReadAuthorityPin
  public let launch: Launch

  public static func loadIfPresent(directory: URL) throws -> LocalSessionReviewProvider? {
    let file = directory.appendingPathComponent("provider.json")
    var info = stat()
    guard lstat(file.path, &info) == 0 else {
      if errno == ENOENT { return nil }; throw SessionReviewBridgeError.unavailable
    }
    guard lstat(directory.path, &info) == 0, info.st_mode & S_IFMT == S_IFDIR,
      info.st_uid == getuid(), info.st_mode & 0o077 == 0 else { throw SessionReviewBridgeError.unauthorized }
    let fd = open(file.path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
    guard fd >= 0 else { throw SessionReviewBridgeError.unauthorized }
    let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
    guard fstat(fd, &info) == 0, info.st_uid == getuid(), info.st_mode & S_IFMT == S_IFREG,
      info.st_mode & 0o077 == 0, info.st_nlink == 1, info.st_size > 0, info.st_size <= 524288,
      let bytes = try handle.readToEnd(), bytes.count <= 524288 else { throw SessionReviewBridgeError.unauthorized }
    let value = try decode(bytes)
    var sources = Dictionary(uniqueKeysWithValues: value.launch.sources.map { ($0.url, $0.sha256) })
    // Editing the registration invalidates this running adapter too.
    sources[file] = OwnerSetupPlan.sha256(bytes)
    let launch = SessionProviderLaunch(interpreter: value.launch.interpreter.url,
      script: value.launch.script.url, profile: value.launch.profile.url,
      interpreterSHA256: value.launch.interpreter.sha256, scriptSHA256: value.launch.script.sha256,
      profileSHA256: value.launch.profile.sha256, sources: sources)
    try launch.validate()
    return LocalSessionReviewProvider(process: SessionProviderProcess(launch: launch), pin: value.provider,
      authority: value.receiver_pin, profileDigest: value.profile_digest_sha256, expectedMode: value.mode)
  }

  public static func decode(_ bytes: Data) throws -> Self {
    var strict = OwnerPlanJSON(bytes, maximumBytes: 524288, maximumKeys: 16, maximumArray: 1024, maximumDepth: 8)
    try strict.validate()
    guard let raw = try JSONSerialization.jsonObject(with: bytes) as? [String: Any],
      Set(raw.keys) == ["schema", "mode", "profile_digest_sha256", "provider", "receiver_pin", "launch"],
      let provider = raw["provider"] as? [String: Any], Set(provider.keys) == ["issuer", "key_id", "public_key", "service"],
      let receiver = raw["receiver_pin"] as? [String: Any], Set(receiver.keys) == ["issuer", "key_id", "public_key", "receiver", "audience"],
      let launch = raw["launch"] as? [String: Any], Set(launch.keys) == ["interpreter", "script", "profile", "sources"],
      let imported = launch["sources"] as? [[String: Any]] else { throw SessionReviewBridgeError.invalid }
    let value = try JSONDecoder().decode(Self.self, from: bytes)
    guard value.schema == "zenith.session-provider-registration.v1", ["disposable", "production"].contains(value.mode),
      hex(value.profile_digest_sha256), hex(value.provider.public_key), !value.provider.service.isEmpty,
      !value.provider.issuer.isEmpty, !value.provider.key_id.isEmpty,
      value.receiver_pin.issuer == value.provider.issuer, value.receiver_pin.key_id == value.provider.key_id,
      value.receiver_pin.public_key == value.provider.public_key, value.receiver_pin.audience == "devgraph",
      let receiverURL = URL(string: value.receiver_pin.receiver), receiverURL.scheme == "https", receiverURL.host != nil,
      receiverURL.user == nil, receiverURL.password == nil, receiverURL.fragment == nil, receiverURL.query == nil,
      receiverURL.path.isEmpty || receiverURL.path == "/",
      !value.launch.sources.isEmpty, value.launch.sources.count < 1024,
      Set(value.launch.sources.map(\.path)).count == value.launch.sources.count else { throw SessionReviewBridgeError.invalid }
    let fileObjects = [launch["interpreter"], launch["script"], launch["profile"]].compactMap { $0 as? [String: Any] } + imported
    guard fileObjects.count == value.launch.sources.count + 3,
      fileObjects.allSatisfy({ Set($0.keys) == ["path", "sha256"] }) else { throw SessionReviewBridgeError.invalid }
    for pin in [value.launch.interpreter, value.launch.script, value.launch.profile] + value.launch.sources {
      guard pin.path.hasPrefix("/"), pin.url.standardizedFileURL.path == pin.path, !pin.path.utf8.contains(0),
        hex(pin.sha256) else { throw SessionReviewBridgeError.invalid }
    }
    return value
  }
  private static func hex(_ value: String) -> Bool { value.range(of: "\\A[0-9a-f]{64}\\z", options: .regularExpression) != nil }
}
#endif
