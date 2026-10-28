import CryptoKit
import Foundation

/// Public original-action recovery only. It never contains a signature or key.
public final class OperatorJournal {
  // Keep the closed set in sync with the supported operator actions. v12/v13
  // carry scoped resource rules; they need the same durable recovery as v1-v11.
  private static let actionSchemas = Set((1...13).map { "devgraph.access-operator-action.v\($0)" })
  private let file: URL
  private let origin: String
  public init(directory: URL, origin: String) throws {
    _ = try WorkServerSettings.address(origin); self.origin = origin
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
      attributes: [.posixPermissions: 0o700])
    let hash = SHA256.hash(data: Data(origin.utf8)).map { String(format: "%02x", $0) }.joined()
    file = directory.appendingPathComponent(hash + ".json")
  }
  private func checked(_ data: Data) throws -> [String: Any] {
    guard data.count <= 131_072,
      let p = try JSONSerialization.jsonObject(with: data) as? [String: Any],
      Set(p.keys) == ["schema","origin","identity","action","assignment_digest","dispatched"],
      p["schema"] as? String == "devgraph.operator-pending.v1", p["origin"] as? String == origin,
      let identity = p["identity"] as? [String: String], Set(identity.keys) == ["subject_public_key","installation_id"],
      identity["subject_public_key"]?.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil,
      identity["installation_id"]?.range(of: "^[a-f0-9]{32}$", options: .regularExpression) != nil,
      let action = p["action"] as? [String: Any],
      (action["action_id"] as? String)?.range(of: "^[a-f0-9]{32}$", options: .regularExpression) != nil,
      ["inbox","review","approve","deny","revoke","upgrade_arena_policy","create_arena"].contains(action["action"] as? String ?? ""),
      Self.actionSchemas.contains(action["schema"] as? String ?? ""),
      (action["action"] as? String == "upgrade_arena_policy") == (action["schema"] as? String == "devgraph.access-operator-action.v10"),
      (action["action"] as? String == "create_arena") == (action["schema"] as? String == "devgraph.access-operator-action.v11"),
      p["dispatched"] is Bool,
      p["assignment_digest"] is NSNull || (p["assignment_digest"] as? String)?.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil
    else { throw WalletFailure.core("invalid_operator_recovery") }
    return p
  }
  public func load() throws -> Data? {
    guard FileManager.default.fileExists(atPath: file.path) else { return nil }
    let attrs = try file.resourceValues(forKeys: [.isSymbolicLinkKey, .isRegularFileKey, .fileSizeKey])
    guard attrs.isRegularFile == true, attrs.isSymbolicLink != true, (attrs.fileSize ?? Int.max) <= 131_072 else { throw WalletFailure.invalidFile }
    let data = try Data(contentsOf: file); _ = try checked(data); return data
  }
  /// Once dispatch is possible only the same original action may be retained.
  private func coordinated(_ action: () throws -> Void) throws {
    var error: NSError?
    var result: Result<Void, Error> = .failure(WalletFailure.conflict)
    NSFileCoordinator().coordinate(writingItemAt:file,options:.forMerging,error:&error) { _ in
      result = Result { try action() }
    }
    if error != nil { throw WalletFailure.conflict }
    try result.get()
  }
  public func save(_ data: Data) throws {
    try coordinated { try saveCoordinated(data) }
  }
  private func saveCoordinated(_ data: Data) throws {
    let value = try checked(data)
    if let old = try load(), let previous = try JSONSerialization.jsonObject(with: old) as? [String: Any], previous["dispatched"] as? Bool == true {
      for key in ["origin","identity","action","assignment_digest"] {
        let a = try JSONSerialization.data(withJSONObject: previous[key]!, options: [.fragmentsAllowed,.sortedKeys])
        let b = try JSONSerialization.data(withJSONObject: value[key]!, options: [.fragmentsAllowed,.sortedKeys])
        guard a == b else { throw WalletFailure.core("recover_original_action_first") }
      }
      guard value["dispatched"] as? Bool == true else { throw WalletFailure.core("recover_original_action_first") }
    }
    try data.write(to: file, options: .atomic)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
  }
  /// The caller must validate the original result or cancel an unsigned action.
  public func clear(matching expected: Data) throws {
    try coordinated {
      guard let saved = try load(), saved == expected else { throw WalletFailure.conflict }
      try FileManager.default.removeItem(at: file)
    }
  }
}
