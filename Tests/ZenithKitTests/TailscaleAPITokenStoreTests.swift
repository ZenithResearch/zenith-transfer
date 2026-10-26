#if os(macOS)
import Foundation
import Security
import XCTest
@testable import ZenithKit

final class TailscaleAPITokenStoreTests: XCTestCase {
  // Deterministic offline input, never issued by a provider.
  private var token: String { "tskey-api-" + String(repeating: "a", count: 40) }
  func testSaveListReopenAndReadKeepSecretsOutOfMetadata() throws {
    let backend = TokenKeychainDouble(), store = TailscaleAPITokenStore(operations: backend.operations)
    let profile = try store.save(name: " Personal network ", tailnet: " - ", token: token)
    XCTAssertEqual(profile.name, "Personal network"); XCTAssertEqual(profile.tailnet, "-")
    XCTAssertFalse(String(data: try JSONEncoder().encode(profile), encoding: .utf8)!.contains(token))
    let reopened = TailscaleAPITokenStore(operations: backend.operations)
    XCTAssertEqual(try reopened.profiles(), [profile])
    let listing = try XCTUnwrap(backend.copies.last)
    XCTAssertEqual(listing[kSecReturnAttributes as String] as? Bool, true)
    XCTAssertNil(listing[kSecReturnData as String], "Listing does not retrieve secrets")
    XCTAssertEqual(try reopened.token(for: profile), token)
    let read = try XCTUnwrap(backend.copies.last)
    XCTAssertEqual(read[kSecAttrAccount as String] as? String, profile.id.uuidString)
    XCTAssertEqual(read[kSecMatchLimit as String] as? String, kSecMatchLimitOne as String)
    let saved = try XCTUnwrap(backend.adds.first)
    XCTAssertEqual(saved[kSecAttrSynchronizable as String] as? Bool, false)
    XCTAssertEqual(saved[kSecUseDataProtectionKeychain as String] as? Bool, false)
    XCTAssertNil(saved[kSecAttrAccessGroup as String])
    XCTAssertEqual(saved[kSecValueData as String] as? Data, Data(token.utf8))
    XCTAssertFalse(String(data: saved[kSecAttrGeneric as String] as! Data, encoding: .utf8)!.contains(token))
  }
  func testInvalidInputCannotWriteAnyKeychainRecord() throws {
    let backend = TokenKeychainDouble(), store = TailscaleAPITokenStore(operations: backend.operations)
    for (name, tailnet, secret) in [("", "-", token), ("a\nb", "-", token), ("Label", "../bad", token), ("Label", "-", "tskey-auth-" + String(repeating: "a", count: 40)), ("Label", "-", token + "\nInjected")] {
      XCTAssertThrowsError(try store.save(name: name, tailnet: tailnet, token: secret))
    }
    XCTAssertTrue(backend.adds.isEmpty); XCTAssertTrue(backend.records.isEmpty)
  }
  func testMultipleProfilesReplacementAndStaleReview() throws {
    let backend = TokenKeychainDouble(), store = TailscaleAPITokenStore(operations: backend.operations)
    let first = try store.save(name: "First", tailnet: "example.test", token: token)
    let second = try store.save(name: "Second", tailnet: "-", token: token)
    let replacementToken = "tskey-api-" + String(repeating: "b", count: 40)
    let updated = try store.save(name: "First updated", tailnet: "other.test", token: replacementToken, replacing: first)
    XCTAssertEqual(updated.id, first.id)
    XCTAssertEqual(try store.profiles().count, 2)
    XCTAssertEqual(try store.token(for: updated), replacementToken)
    XCTAssertThrowsError(try store.token(for: first), "A review of an old profile cannot read a replacement token")
    XCTAssertEqual(try store.token(for: second), token)
    XCTAssertEqual(backend.updates.first?[kSecAttrAccount as String] as? String, first.id.uuidString)
  }
  func testRemoveTargetsOnlyTheSelectedProfileAndMissingIsIdempotent() throws {
    let backend = TokenKeychainDouble(), store = TailscaleAPITokenStore(operations: backend.operations)
    let first = try store.save(name: "First", tailnet: "-", token: token)
    let second = try store.save(name: "Second", tailnet: "-", token: token)
    try store.remove(first); try store.remove(first)
    XCTAssertEqual(try store.profiles(), [second])
    XCTAssertEqual(backend.deletes.last?[kSecAttrAccount as String] as? String, first.id.uuidString)
    XCTAssertThrowsError(try store.token(for: first))
    XCTAssertThrowsError(try store.save(name: "Missing", tailnet: "-", token: token, replacing: first))
    XCTAssertEqual(try store.profiles(), [second], "Missing replacements must not create another record")
  }
  func testKeychainFailuresAreGenericAndDoNotFallBack() throws {
    let backend = TokenKeychainDouble(), store = TailscaleAPITokenStore(operations: backend.operations)
    let profile = try store.save(name: "First", tailnet: "-", token: token)
    backend.failure = errSecAuthFailed
    for action in [ { _ = try store.profiles() }, { _ = try store.token(for: profile) },
      { _ = try store.save(name: "Other", tailnet: "-", token: self.token) }, { try store.remove(profile) } ] {
      XCTAssertThrowsError(try action()) { error in
        XCTAssertFalse(error.localizedDescription.contains(self.token))
        XCTAssertTrue(error.localizedDescription.contains("Keychain"))
      }
    }
    XCTAssertEqual(backend.records.count, 1)
  }
  func testCorruptMetadataOrWrongSecretKindFailsClosed() throws {
    let backend = TokenKeychainDouble(), store = TailscaleAPITokenStore(operations: backend.operations)
    let profile = try store.save(name: "First", tailnet: "-", token: token)
    var saved = backend.records[profile.id.uuidString]!
    saved[kSecValueData as String] = Data(("tskey-auth-" + String(repeating: "a", count: 40)).utf8)
    backend.records[profile.id.uuidString] = saved
    XCTAssertThrowsError(try store.token(for: profile))
    saved[kSecAttrGeneric as String] = Data(repeating: 65, count: 2049)
    backend.records[profile.id.uuidString] = saved
    XCTAssertThrowsError(try store.profiles())
    XCTAssertThrowsError(try store.token(for: profile))
  }
  func testMacKeychainRoundTripInAnIsolatedSyntheticNamespace() throws {
    guard ProcessInfo.processInfo.environment["TRANSFER_TEST_KEYCHAIN"] == "1" else {
      throw XCTSkip("Opt in to the real Mac Keychain test; uses only a fresh synthetic namespace")
    }
    let service = "ca.zenith.tests.tailscale-api." + UUID().uuidString
    let store = TailscaleAPITokenStore(operations: .system, service: service)
    XCTAssertTrue(try store.profiles().isEmpty)
    let profile = try store.save(name: "Synthetic test", tailnet: "-", token: token)
    defer { try? store.remove(profile) }
    let reopened = TailscaleAPITokenStore(operations: .system, service: service)
    XCTAssertEqual(try reopened.profiles(), [profile])
    XCTAssertEqual(try reopened.token(for: profile), token)
    let replacement = try reopened.save(name: "Replacement", tailnet: "example.test", token: token, replacing: profile)
    XCTAssertThrowsError(try reopened.token(for: profile))
    XCTAssertEqual(try reopened.token(for: replacement), token)
    try reopened.remove(replacement)
    XCTAssertTrue(try store.profiles().isEmpty)
  }
}

private final class TokenKeychainDouble {
  var records: [String: [String: Any]] = [:]
  var copies: [[String: Any]] = [], adds: [[String: Any]] = [], updates: [[String: Any]] = [], deletes: [[String: Any]] = []
  var failure: OSStatus?
  var operations: TailscaleAPITokenStore.Operations {
    .init(copy: { [unowned self] query in
      copies.append(query); if let failure { return (failure, nil) }
      if let account = query[kSecAttrAccount as String] as? String {
        guard let record = records[account] else { return (errSecItemNotFound, nil) }
        return (errSecSuccess, record)
      }
      let values = records.values.map { record in record.filter { $0.key != kSecValueData as String } }
      return values.isEmpty ? (errSecItemNotFound, nil) : (errSecSuccess, values)
    }, add: { [unowned self] record in
      adds.append(record); if let failure { return failure }
      let key = record[kSecAttrAccount as String] as! String
      guard records[key] == nil else { return errSecDuplicateItem }
      records[key] = record; return errSecSuccess
    }, update: { [unowned self] query, values in
      updates.append(query); if let failure { return failure }
      let key = query[kSecAttrAccount as String] as! String
      guard let prior = records[key] else { return errSecItemNotFound }
      records[key] = prior.merging(values) { _, new in new }; return errSecSuccess
    }, delete: { [unowned self] query in
      deletes.append(query); if let failure { return failure }
      let key = query[kSecAttrAccount as String] as! String
      return records.removeValue(forKey: key) == nil ? errSecItemNotFound : errSecSuccess
    })
  }
}
#endif
