import Foundation
import XCTest
@testable import ZenithKit

final class WalletIdentityTests: XCTestCase {
  let owner = String(repeating: "a", count: 64)
  let first = "11111111-1111-4111-8111-111111111111"
  let second = "22222222-2222-4222-8222-222222222222"
  func account(_ id: String? = nil, kind: WalletIdentityKind = .matrix, identifier: String = "@member:chat.example", server: String = "https://chat.example", label: String = "Chat") throws -> WalletIdentity {
    try WalletIdentity(accountId: id ?? first, kind: kind, label: label, identifier: identifier, server: server)
  }
  func testCanonicalRoundTripAndClosedShapeRejectsCredentials() throws {
    let section = try WalletIdentitySection(ownerMemberKey: owner, accounts: [account(second, kind: .nostr, identifier: owner, server: "wss://relay.example"), account()])
    XCTAssertEqual(section.accounts.map(\.accountId), [first, second])
    XCTAssertEqual(try WalletIdentitySection.decode(JSONEncoder().encode(section)), section)
    var raw = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(section)) as? [String: Any])
    for key in ["token", "privateKey", "authKey", "session"] {
      var changed = raw; changed[key] = "forbidden"
      XCTAssertThrowsError(try WalletIdentitySection.decode(JSONSerialization.data(withJSONObject: changed)))
    }
    raw["ownerMemberKey"] = "not-a-wallet"
    XCTAssertThrowsError(try WalletIdentitySection.decode(JSONSerialization.data(withJSONObject: raw)))
  }
  func testStableProviderIDsAndURLsAreValidatedWithoutClaimingOwnership() throws {
    XCTAssertNoThrow(try account(kind: .github, identifier: "12345", server: ""))
    XCTAssertNoThrow(try account(kind: .x, identifier: String(repeating: "9", count: 40), server: ""))
    for identifier in ["0", "001", "username", "-12", String(repeating: "9", count: 41)] {
      XCTAssertThrowsError(try account(kind: .github, identifier: identifier, server: ""))
    }
    for server in ["http://chat.example", "https://user:password@chat.example", "https://chat.example?token=private", "https://chat.example/path"] {
      XCTAssertThrowsError(try account(server: server))
    }
    XCTAssertNoThrow(try account(server: "https://chat.example/"))
    XCTAssertThrowsError(try account(kind: .nostr, identifier: "nsec1private", server: ""))
    XCTAssertThrowsError(try account(kind: .nostr, identifier: owner.uppercased(), server: ""))
    XCTAssertThrowsError(try account(kind: .x, identifier: "123", server: "https://x.example"))
  }
  func testBoundsBidiAndCanonicalNonNilIDs() throws {
    for label in ["", "line\nbreak", "a\u{202E}b", String(repeating: "é", count: 51)] {
      XCTAssertThrowsError(try account(label: label))
    }
    XCTAssertThrowsError(try account("00000000-0000-0000-0000-000000000000"))
    XCTAssertThrowsError(try account("ABCDEFAB-1111-4111-8111-111111111111"))
    XCTAssertThrowsError(try account("not-a-uuid"))
    XCTAssertThrowsError(try WalletIdentitySection(ownerMemberKey: owner, accounts: [account(), account()]))
    XCTAssertThrowsError(try WalletIdentitySection(ownerMemberKey: owner, accounts: [account(), account(second)]))
  }
  func testLegacyMigrationIsExplicitIdempotentPreservesIDsAndLeavesTailscaleOut() throws {
    let original = try IdentityAccount(id: UUID(uuidString: first)!, walletPublicKey: owner, provider: .matrix, label: "Chat", identifier: "@member:chat.example", server: "https://chat.example")
    let tailnet = try IdentityAccount(walletPublicKey: owner, provider: .tailscale, label: "Network", identifier: "member", server: "example.ts.net")
    let empty = try WalletIdentitySection(ownerMemberKey: owner, accounts: [])
    let plan = try WalletIdentityMigration.prepare(existing: empty, legacy: [original, tailnet])
    XCTAssertEqual(plan.added.map(\.accountId), [first])
    XCTAssertEqual(plan.applicationOnlyCount, 1)
    XCTAssertEqual(plan.proposed.accounts.count, 1)
    XCTAssertEqual(original.schema, "zenith.identity-account.v1")
    XCTAssertTrue(try WalletIdentityMigration.prepare(existing: plan.proposed, legacy: [original, tailnet]).added.isEmpty)
    let other = try IdentityAccount(walletPublicKey: String(repeating: "b", count: 64), provider: .matrix, label: "Other", identifier: "@other:chat.example", server: "https://chat.example")
    XCTAssertThrowsError(try WalletIdentityMigration.prepare(existing: empty, legacy: [other]))
  }
  func testMigrationConflictsNeverOverwriteOrMatchByDisplayName() throws {
    let existing = try WalletIdentitySection(ownerMemberKey: owner, accounts: [account()])
    let renamed = try IdentityAccount(id: UUID(uuidString: first)!, walletPublicKey: owner, provider: .matrix, label: "Different", identifier: "@member:chat.example", server: "https://chat.example")
    XCTAssertThrowsError(try WalletIdentityMigration.prepare(existing: existing, legacy: [renamed]))
    let duplicateProvider = try IdentityAccount(id: UUID(uuidString: second)!, walletPublicKey: owner, provider: .matrix, label: "Chat", identifier: "@member:chat.example", server: "https://chat.example")
    XCTAssertThrowsError(try WalletIdentityMigration.prepare(existing: existing, legacy: [duplicateProvider]))
    XCTAssertEqual(existing.accounts.count, 1)
  }
  func testV2EnvelopeReaderRequiresMatchingContentsVersionAndCatalogLabelsIt() throws {
    let base: [String: Any] = ["schema":"castalia.castaway.v2", "contentsSchema":"castalia.castaway-contents.v2", "ownerPublicKey":owner, "exportedAt":1000,
      "kdf":["name":"Argon2id","version":19,"salt":RecoveryQR.encode(Data(repeating:1,count:16)),"memoryKiB":65536,"iterations":3,"parallelism":1,"derivedKeyBytes":32],
      "aead":["name":"AES-256-GCM","nonce":RecoveryQR.encode(Data(repeating:2,count:12)),"tagBits":128], "ciphertext":RecoveryQR.encode(Data(repeating:3,count:32))]
    let data = try JSONSerialization.data(withJSONObject: base)
    XCTAssertNoThrow(try EncryptedImportFile.validateEnvelope(data))
    XCTAssertEqual(try RecoveryFileFormat.inspect(data, filename: "vault.castaway").version, "v2")
    for version in ["castalia.castaway-contents.v1", "castalia.castaway-contents.v3"] {
      var changed = base; changed["contentsSchema"] = version
      XCTAssertThrowsError(try EncryptedImportFile.validateEnvelope(JSONSerialization.data(withJSONObject: changed)))
    }
  }
}
