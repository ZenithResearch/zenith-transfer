import Foundation
import Darwin

public enum IdentityProvider: String, Codable, CaseIterable, Identifiable, Sendable {
  case matrix, nostr, tailscale
  public var id: String { rawValue }
  public var title: String { switch self { case .matrix: return "Matrix"; case .nostr: return "Nostr"; case .tailscale: return "Tailscale" } }
  public var symbol: String { switch self { case .matrix: return "bubble.left.and.bubble.right"; case .nostr: return "antenna.radiowaves.left.and.right"; case .tailscale: return "network" } }
}

public enum IdentityAccountError: LocalizedError {
  case invalid, changed, storage
  public var errorDescription: String? {
    switch self {
    case .invalid: return "Check the public account identifier and server. Do not enter passwords, tokens or private keys here."
    case .changed: return "This account changed in another window. Reload before saving."
    case .storage: return "Account records could not be read or saved safely. Existing records were preserved."
    }
  }
}

/// Public local association only. No secret, authentication assertion or authority.
public struct IdentityAccount: Codable, Equatable, Identifiable, Sendable {
  public let schema: String
  public let id: UUID
  public let walletPublicKey: String
  public let provider: IdentityProvider
  public let label: String
  public let identifier: String
  public let server: String
  public init(id: UUID = UUID(), walletPublicKey: String, provider: IdentityProvider,
    label: String, identifier: String, server: String) throws {
    self.schema = "zenith.identity-account.v1"; self.id = id
    self.walletPublicKey = walletPublicKey; self.provider = provider
    self.label = label.trimmingCharacters(in: .whitespacesAndNewlines)
    self.identifier = identifier.trimmingCharacters(in: .whitespacesAndNewlines)
    self.server = server.trimmingCharacters(in: .whitespacesAndNewlines)
    try validate()
  }
  public func validate() throws {
    func matches(_ s: String, _ pattern: String) -> Bool { s.range(of: pattern, options: .regularExpression) != nil }
    guard schema == "zenith.identity-account.v1", matches(walletPublicKey, "^[a-f0-9]{64}$"),
      !label.isEmpty, label.utf8.count <= 100, identifier.utf8.count <= 320, server.utf8.count <= 500,
      [label, identifier, server].allSatisfy({ !$0.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) })
    else { throw IdentityAccountError.invalid }
    func endpoint(_ scheme: String, originOnly: Bool) -> Bool {
      guard let u = URLComponents(string: server), u.scheme == scheme,
        let host = u.host, !host.isEmpty, u.user == nil, u.password == nil,
        u.query == nil, u.fragment == nil, u.port.map({ (1...65535).contains($0) }) ?? true
      else { return false }
      return !originOnly || u.path.isEmpty || u.path == "/"
    }
    switch provider {
    case .matrix:
      guard matches(identifier, "^@[^\\s:@/]+:[a-zA-Z0-9.-]+(?::[0-9]{1,5})?$"), endpoint("https", originOnly: true) else { throw IdentityAccountError.invalid }
    case .nostr:
      guard matches(identifier, "^[a-f0-9]{64}$"), server.isEmpty || endpoint("wss", originOnly: false) else { throw IdentityAccountError.invalid }
    case .tailscale:
      guard matches(identifier, "^[a-zA-Z0-9][a-zA-Z0-9@._+ -]{0,199}$"),
        !identifier.hasPrefix("tskey-"), !identifier.hasPrefix("nsec1"),
        matches(server, "^[a-z0-9][a-z0-9-]*\\.ts\\.net$"), server.count <= 253 else { throw IdentityAccountError.invalid }
    }
  }
  public static func decode(_ data: Data) throws -> Self {
    guard data.count <= 4096 else { throw IdentityAccountError.invalid }
    var strict = OwnerPlanJSON(data, maximumBytes: 4096, maximumKeys: 20)
    try strict.validate()
    guard let raw = try JSONSerialization.jsonObject(with: data) as? [String: Any],
      Set(raw.keys) == ["schema", "id", "walletPublicKey", "provider", "label", "identifier", "server"]
    else { throw IdentityAccountError.invalid }
    let record = try JSONDecoder().decode(Self.self, from: data)
    try record.validate(); return record
  }
}

/// Reuses the existing coordinated public registry pattern; never loads custody.
public final class IdentityAccountRegistry {
  private let directory: URL
  public init(directory: URL) throws {
    self.directory = directory
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    let v = try directory.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
    guard v.isDirectory == true, v.isSymbolicLink != true else { throw IdentityAccountError.storage }
  }
  private func file(_ id: UUID) -> URL { directory.appendingPathComponent(id.uuidString.lowercased() + ".json") }
  private func read(_ url: URL) throws -> IdentityAccount {
    let descriptor = Darwin.open(url.path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK)
    guard descriptor >= 0 else { throw IdentityAccountError.storage }
    let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
    defer { try? handle.close() }
    var info = stat()
    guard fstat(descriptor, &info) == 0, info.st_mode & S_IFMT == S_IFREG,
      info.st_uid == getuid(), info.st_nlink == 1, info.st_mode & 0o077 == 0,
      info.st_size <= 4096 else { throw IdentityAccountError.storage }
    let value = try IdentityAccount.decode(handle.read(upToCount: 4097) ?? Data())
    guard url.lastPathComponent == file(value.id).lastPathComponent else { throw IdentityAccountError.storage }
    return value
  }
  public func load(wallet: String) throws -> [IdentityAccount] {
    let urls = try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil).filter { $0.pathExtension == "json" }
    guard urls.count <= 100 else { throw IdentityAccountError.storage }
    return try urls.map(read).filter { $0.walletPublicKey == wallet }.sorted { $0.label.localizedStandardCompare($1.label) == .orderedAscending }
  }
  public func save(_ value: IdentityAccount?, replacing expected: IdentityAccount?) throws {
    guard let id = value?.id ?? expected?.id,
      expected == nil || value == nil || (value?.id == expected?.id && value?.walletPublicKey == expected?.walletPublicKey)
    else { throw IdentityAccountError.changed }
    try value?.validate()
    let url = file(id)
    var coordinationError: NSError?
    var result: Result<Void, Error> = .failure(IdentityAccountError.storage)
    NSFileCoordinator().coordinate(writingItemAt: url, options: .forMerging, error: &coordinationError) { target in
      result = Result {
        let current = FileManager.default.fileExists(atPath: target.path) ? try read(target) : nil
        guard current == expected else { throw IdentityAccountError.changed }
        if let value {
          if current == nil {
            let count = try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil).filter { $0.pathExtension == "json" }.count
            guard count < 100 else { throw IdentityAccountError.storage }
          }
          try JSONEncoder().encode(value).write(to: target, options: .atomic)
          try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: target.path)
        } else if current != nil { try FileManager.default.removeItem(at: target) }
      }
    }
    guard coordinationError == nil else { throw IdentityAccountError.storage }
    try result.get()
  }
}
