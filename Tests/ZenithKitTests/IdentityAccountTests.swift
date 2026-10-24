import Foundation
import XCTest
@testable import ZenithKit

final class IdentityAccountTests: XCTestCase {
  private let owner = String(repeating: "a", count: 64)
  private func record(id: UUID = UUID(), label: String = "Chat") throws -> IdentityAccount {
    try IdentityAccount(id: id, walletPublicKey: owner, provider: .matrix, label: label,
      identifier: "@owner:matrix.example", server: "https://matrix.example")
  }
  func testRoundtripAndClosedSecretFreeShape() throws {
    let original = try record()
    let data = try JSONEncoder().encode(original)
    XCTAssertEqual(try IdentityAccount.decode(data), original)
    var raw = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
    for forbidden in ["password", "token", "privateKey", "authentication", "secretReference"] {
      var extra = raw; extra[forbidden] = "must-not-be-accepted"
      XCTAssertThrowsError(try IdentityAccount.decode(JSONSerialization.data(withJSONObject: extra)))
    }
    raw["schema"] = "zenith.identity-account.v2"
    XCTAssertThrowsError(try IdentityAccount.decode(JSONSerialization.data(withJSONObject: raw)))
    XCTAssertThrowsError(try IdentityAccount.decode(Data(repeating: 32, count: 4097)))
  }
  func testProviderValidationRejectsPrivateKeysAndCredentialURLs() throws {
    XCTAssertNoThrow(try IdentityAccount(walletPublicKey: owner, provider: .nostr, label: "Nostr", identifier: owner, server: "wss://relay.example"))
    XCTAssertNoThrow(try IdentityAccount(walletPublicKey: owner, provider: .tailscale, label: "Tailnet", identifier: "owner@example.org", server: "tail-example.ts.net"))
    for key in ["nsec1secret", "tskey-auth-secret", "invalid"] {
      XCTAssertThrowsError(try IdentityAccount(walletPublicKey: owner, provider: .nostr, label: "Nostr", identifier: key, server: ""))
    }
    for url in ["http://matrix.example", "https://user:password@matrix.example", "https://matrix.example?token=secret", "https://matrix.example/path", "https://matrix.example#secret"] {
      XCTAssertThrowsError(try IdentityAccount(walletPublicKey: owner, provider: .matrix, label: "Chat", identifier: "@owner:matrix.example", server: url))
    }
    XCTAssertThrowsError(try record(label: "line\nbreak"))
    XCTAssertThrowsError(try record(label: String(repeating: "x", count: 101)))
  }
  func testPartitioningCompareAndSwapRemovalAndPermissions() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    let first = try IdentityAccountRegistry(directory: root)
    let second = try IdentityAccountRegistry(directory: root)
    let original = try record()
    try first.save(original, replacing: nil)
    XCTAssertEqual(try second.load(wallet: owner), [original])
    XCTAssertEqual(try second.load(wallet: String(repeating: "b", count: 64)), [])
    let edited = try record(id: original.id, label: "Renamed")
    try second.save(edited, replacing: original)
    XCTAssertThrowsError(try first.save(original, replacing: original))
    XCTAssertThrowsError(try first.save(nil, replacing: original))
    let path = root.appendingPathComponent(original.id.uuidString.lowercased() + ".json")
    let permissions = try XCTUnwrap(FileManager.default.attributesOfItem(atPath: path.path)[.posixPermissions] as? NSNumber)
    XCTAssertEqual(permissions.intValue & 0o777, 0o600)
    try first.save(nil, replacing: edited)
    XCTAssertEqual(try second.load(wallet: owner), [])
  }
  func testApplicationEditingPreservesLegacyFilesAndOnlyChangesTailscale() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    let registry = try IdentityAccountRegistry(directory: root)
    let matrix = try record()
    let nostr = try IdentityAccount(walletPublicKey: owner, provider: .nostr, label: "Nostr", identifier: owner, server: "")
    for original in [matrix, nostr] {
      // Seed a historical file through the compatibility storage, not app editing.
      try registry.save(original, replacing: nil)
      let path = root.appendingPathComponent(original.id.uuidString.lowercased() + ".json")
      let bytes = try Data(contentsOf: path)
      let changed = try IdentityAccount(id: original.id, walletPublicKey: owner, provider: original.provider,
        label: "Changed", identifier: original.identifier, server: original.server)
      XCTAssertThrowsError(try registry.saveApplicationRecord(changed, replacing: original))
      XCTAssertThrowsError(try registry.saveApplicationRecord(nil, replacing: original))
      let fresh = try IdentityAccount(walletPublicKey: owner, provider: original.provider,
        label: original.label, identifier: original.identifier, server: original.server)
      XCTAssertThrowsError(try registry.saveApplicationRecord(fresh, replacing: nil))
      let replacement = try IdentityAccount(id: original.id, walletPublicKey: owner, provider: .tailscale,
        label: "Network", identifier: "member", server: "example.ts.net")
      XCTAssertThrowsError(try registry.saveApplicationRecord(replacement, replacing: original))
      XCTAssertEqual(try Data(contentsOf: path), bytes)
    }
    XCTAssertEqual(try registry.load(wallet: owner).count, 2)
    let tailnet = try IdentityAccount(walletPublicKey: owner, provider: .tailscale,
      label: "Network", identifier: "member", server: "example.ts.net")
    try registry.saveApplicationRecord(tailnet, replacing: nil)
    let renamed = try IdentityAccount(id: tailnet.id, walletPublicKey: owner, provider: .tailscale,
      label: "Renamed network", identifier: "member", server: "example.ts.net")
    try registry.saveApplicationRecord(renamed, replacing: tailnet)
    XCTAssertThrowsError(try registry.saveApplicationRecord(tailnet, replacing: tailnet), "CAS still rejects stale forms")
    try registry.saveApplicationRecord(nil, replacing: renamed)
    XCTAssertEqual(Set(try registry.load(wallet: owner).map(\.id)), Set([matrix.id, nostr.id]))
  }
  func testRejectsLinkedRecordAndOverLimitCatalog() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    let registry = try IdentityAccountRegistry(directory: root)
    let original = try record()
    let target = root.appendingPathComponent("source.data")
    try JSONEncoder().encode(original).write(to: target)
    let link = root.appendingPathComponent(original.id.uuidString.lowercased() + ".json")
    try FileManager.default.createSymbolicLink(at: link, withDestinationURL: target)
    XCTAssertThrowsError(try registry.load(wallet: owner))
    try FileManager.default.removeItem(at: link)
    for _ in 0..<101 {
      try Data().write(to: root.appendingPathComponent(UUID().uuidString + ".json"))
    }
    XCTAssertThrowsError(try registry.load(wallet: owner))
  }
}
