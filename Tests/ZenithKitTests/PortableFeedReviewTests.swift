import Foundation
import XCTest
@testable import ZenithKit

/// Presentation consumes a Rust-validated preview. It never rebuilds a vault or
/// interprets the saved enabled preference as permission to fetch a feed.
final class PortableFeedReviewTests: XCTestCase {
  func testFeedFailuresHaveExplicitClosedMessagesWithoutChangingImportOrExportPolicy() {
    let messages = [
      "feed_conflict": "A feed conflicts with a saved record. Nothing was overwritten; review the subscriptions and collections separately.",
      "feed_writer_not_qualified": "This version cannot export feed configuration yet. Keep the original data file. Your saved wallet is unchanged.",
      "feed_limit": "Feed configuration supports up to 256 subscriptions, 64 collections and 16 collection references per subscription. Nothing was saved.",
      "feeds_too_large": "The combined feed configuration exceeds the 256 KiB limit. Nothing was saved.",
      "file_too_large": "This change would exceed the 1 MiB Castaway file limit. Nothing was saved."
    ]
    for (code, message) in messages {
      XCTAssertEqual(WalletFailure.core(code).errorDescription, message)
    }
    XCTAssertFalse(WalletFailure.core("unknown synthetic password and https://secret.invalid").errorDescription?.contains("synthetic") == true)
  }
  func testV3TransportAdmissionCatalogAndReviewContextAgree() throws {
    let file = try envelope(version: 3)
    XCTAssertNoThrow(try EncryptedImportFile.validateEnvelope(file))
    let format = try RecoveryFileFormat.inspect(file, filename: "renamed.castalia-recovery")
    XCTAssertEqual(format.kind, .castaway)
    XCTAssertEqual(format.version, "v3")
    XCTAssertEqual(format.contentsSchema, "castalia.castaway-contents.v3")
    XCTAssertFalse(format.legacyFilename)
    XCTAssertEqual(try WalletImportReview.Context.dataFile(file, recovering: false), .castaway(.v3))
    XCTAssertEqual(try WalletImportReview.Context.dataFile(file, recovering: true), .recoveryAndCastaway(.v3))
    var scanner = RecoveryQRAssembler()
    var received: Data?
    for frame in try RecoveryQR.frames(for: file).reversed() {
      received = try scanner.accept(frame).file ?? received
    }
    XCTAssertEqual(received, file)
  }

  func testTransportVersionsMustMatchAndUnknownVersionsRemainUnsupported() throws {
    for outer in 1...4 {
      for inner in 1...4 {
        let file = try envelope(version: outer, contentsVersion: inner)
        if outer == inner && outer <= 3 {
          XCTAssertNoThrow(try EncryptedImportFile.validateEnvelope(file))
        } else {
          XCTAssertThrowsError(try EncryptedImportFile.validateEnvelope(file))
        }
      }
    }
    var value = try XCTUnwrap(JSONSerialization.jsonObject(with: envelope(version: 3)) as? [String: Any])
    value["ownerPublicKey"] = String(repeating: "A", count: 64)
    XCTAssertThrowsError(try EncryptedImportFile.validateEnvelope(JSONSerialization.data(withJSONObject: value)))
    value["ownerPublicKey"] = String(repeating: "a", count: 64)
    value["feeds"] = ["must": "remain encrypted"]
    XCTAssertThrowsError(try EncryptedImportFile.validateEnvelope(JSONSerialization.data(withJSONObject: value)))
  }

  func testOneMiBBoundAndFileReadKeepExactOriginalBytes() throws {
    var raw = try envelope(version: 3)
    raw.append(Data("\r\n ".utf8))
    raw.append(Data(repeating: 32, count: EncryptedImportFile.maximumBytes - raw.count))
    XCTAssertNoThrow(try EncryptedImportFile.validateEnvelope(raw))
    let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: dir) }
    let url = dir.appendingPathComponent("inert.castaway")
    try raw.write(to: url)
    XCTAssertEqual(try EncryptedImportFile.read(url), raw)
    raw.append(32)
    XCTAssertThrowsError(try EncryptedImportFile.validateEnvelope(raw))
    try raw.write(to: url)
    XCTAssertThrowsError(try EncryptedImportFile.read(url))
  }

  func testPortableFeedDTOIsDecodableOnlyAndPreservesValuesAndOrder() throws {
    let preview = try fixture()
    let section = try XCTUnwrap(preview.memberships?.feeds)
    XCTAssertEqual(section.schema, "castalia.feeds-section.v1")
    XCTAssertEqual(section.version, 1)
    XCTAssertEqual(section.subscriptions.map(\.id), [id(3), id(1), id(2)])
    XCTAssertEqual(section.subscriptions.map(\.title), ["Café Ω 🧑‍🎨", "  ", ""])
    XCTAssertEqual(section.subscriptions[0].url, "https://example.org/path%2ffeed.xml")
    XCTAssertEqual(section.subscriptions[0].format, "atom")
    XCTAssertEqual(section.subscriptions[0].collectionIds, [id(5), id(4)])
    XCTAssertEqual(section.subscriptions[0].disclosure, "selected")
    XCTAssertTrue(section.subscriptions[0].enabled)
    XCTAssertFalse(section.subscriptions[1].enabled)
    XCTAssertEqual(section.collections.map(\.title), ["  Essays  ", ""])
    XCTAssertEqual(section.preferences.order, "newest-first")
    XCTAssertEqual(section.subscriptions[1].reviewTitle, "Untitled subscription")
    XCTAssertEqual(section.collections[1].reviewTitle, "Untitled collection")
    XCTAssertEqual(section.collections[0].reviewTitle, "  Essays  ")
    // A portable profile, feed section or preview is never a persistence encoder.
    XCTAssertFalse((section as Any) is any Encodable)
    XCTAssertFalse((preview as Any) is any Encodable)
    XCTAssertFalse((try XCTUnwrap(preview.profile) as Any) is any Encodable)
  }

  func testSharedSectionFixtureDecodesWithoutChangingLabelsOrReferences() throws {
    let url = try XCTUnwrap(Bundle.module.url(forResource: "feeds-v1", withExtension: "json"))
    let raw = try Data(contentsOf: url)
    let section = try JSONDecoder().decode(PortableFeedSection.self, from: raw)
    XCTAssertEqual(RecoveryQR.hash(raw), "eff3c3c4b15743661c2628d504052211f54c0ec2ab220d6d1d103218569c0ec2")
    XCTAssertEqual(section.subscriptions[0].title, "Café Ω 🧑‍🎨")
    XCTAssertEqual(section.collections[0].title, "  Essays  ")
    XCTAssertEqual(section.subscriptions[0].collectionIds, [section.collections[0].id])
  }

  func testV3ReviewShowsIncomingCountsSeparatelyFromResultAndSavedIdentities() throws {
    let review = WalletImportReview(preview: try fixture(), context: .castaway(.v3))
    XCTAssertEqual(review.feedsAfterImport?.subscriptions.count, 3)
    XCTAssertEqual(review.feedsAfterImport?.collections.count, 2)
    XCTAssertEqual(review.importedFeedSubscriptions, 2)
    XCTAssertEqual(review.importedFeedCollections, 1)
    XCTAssertEqual(review.feedImportNote, "This file contains 2 feed subscription(s) and 1 collection(s). Existing nonconflicting feeds are preserved; the review shows the result after import.")
    XCTAssertEqual(review.feedActivationNote, "Feed configuration is saved only. Importing does not fetch content, sign in to a provider, activate subscriptions or grant access.")
    XCTAssertEqual(review.savedIdentities?.accounts.count, 0)
    XCTAssertNotNil(review.identityImportNote)
    XCTAssertFalse(review.recoversWallet)
    let combined = WalletImportReview(preview: try fixture(), context: .recoveryAndCastaway(.v3))
    XCTAssertTrue(combined.recoversWallet)
    XCTAssertEqual(combined.feedsAfterImport?.subscriptions.count, 3)
  }

  func testLegacyDataShowsPreservedFeedsWithoutInventingIncomingCounts() throws {
    for version: WalletImportReview.DataVersion in [.v1, .v2] {
      let review = WalletImportReview(preview: try fixture(), context: .castaway(version))
      XCTAssertEqual(review.feedsAfterImport?.subscriptions.count, 3)
      XCTAssertNil(review.importedFeedSubscriptions)
      XCTAssertNil(review.importedFeedCollections)
      XCTAssertEqual(review.feedImportNote, "This older Castaway file has no feeds. Existing feed subscriptions and collections are preserved.")
      XCTAssertNotNil(review.feedActivationNote)
    }
    let recovery = WalletImportReview(preview: try fixture(), context: .recovery)
    XCTAssertNil(recovery.feedsAfterImport)
    XCTAssertNil(recovery.feedImportNote)
    XCTAssertNil(recovery.feedActivationNote)
  }

  func testEmptyAndUnavailableIncomingCountsAreNotMergedResultCounts() throws {
    let empty = WalletImportReview(preview: try fixture(imported: 0), context: .castaway(.v3))
    XCTAssertEqual(empty.importedFeedSubscriptions, 0)
    XCTAssertEqual(empty.feedsAfterImport?.subscriptions.count, 3)
    XCTAssertTrue(try XCTUnwrap(empty.feedImportNote).contains("0 feed subscription(s)"))
    let absent = WalletImportReview(preview: try fixture(imported: nil), context: .castaway(.v3))
    XCTAssertNil(absent.importedFeedSubscriptions)
    XCTAssertEqual(absent.feedImportNote, "This file contains feed configuration. Existing nonconflicting feeds are preserved; the review shows the result after import.")
    let noFeeds = WalletImportReview(preview: try fixture(feeds: false), context: .castaway(.v2))
    XCTAssertNil(noFeeds.feedsAfterImport)
    XCTAssertNil(noFeeds.feedImportNote)
    let withoutIdentities = WalletImportReview(preview: try fixture(identities: false), context: .castaway(.v3))
    XCTAssertNil(withoutIdentities.savedIdentities, "v3 permits feeds without a walletIdentities section")
    XCTAssertNotNil(withoutIdentities.feedsAfterImport)
  }

  private func id(_ number: Int) -> String {
    String(format: "018d0000-0000-4000-8000-%012d", number)
  }
  private func fixture(imported: Int? = 2, feeds: Bool = true, identities: Bool = true) throws -> RestorePreview {
    let owner = String(repeating: "a", count: 64)
    let subscriptions: [[String: Any]] = [3, 1, 2].enumerated().map { index, number in
      ["id": id(number), "url": "https://example.org/path%2ffeed.xml",
       "format": "atom", "title": ["Café Ω 🧑‍🎨", "  ", ""][index], "enabled": index != 1,
       "collectionIds": index == 0 ? [id(5), id(4)] : [], "disclosure": "selected"]
    }
    var sections: [String: Any] = [:]
    if feeds {
      sections["feeds"] = ["schema": "castalia.feeds-section.v1", "version": 1,
        "subscriptions": subscriptions, "collections": [["id": id(5), "title": "  Essays  "], ["id": id(4), "title": ""]],
        "preferences": ["order": "newest-first"]]
    }
    var value: [String: Any] = ["token": "feed-preview", "expected_revision": 7,
      "public_key": owner, "backup_verified": true, "memberships": sections,
      "profile": ["subject": ["memberKey": owner, "fields": [:]]],
      "wallet_identities": ["schema": "castalia.wallet-identities.v1", "version": 1,
        "ownerMemberKey": owner, "authority": "descriptor-only", "accounts": []],
      "imported_wallet_identities": 0]
    if let imported {
      value["imported_feed_subscriptions"] = imported
      value["imported_feed_collections"] = imported == 0 ? 0 : 1
    }
    if !identities { value.removeValue(forKey: "wallet_identities") }
    return try JSONDecoder().decode(RestorePreview.self, from: JSONSerialization.data(withJSONObject: value))
  }
  private func envelope(version: Int, contentsVersion: Int? = nil) throws -> Data {
    try JSONSerialization.data(withJSONObject: [
      "schema": "castalia.castaway.v\(version)",
      "contentsSchema": "castalia.castaway-contents.v\(contentsVersion ?? version)",
      "ownerPublicKey": String(repeating: "a", count: 64), "exportedAt": 1,
      "kdf": ["name": "Argon2id", "version": 19, "salt": RecoveryQR.encode(Data(repeating: 1, count: 16)),
        "memoryKiB": 65_536, "iterations": 3, "parallelism": 1, "derivedKeyBytes": 32],
      "aead": ["name": "AES-256-GCM", "nonce": RecoveryQR.encode(Data(repeating: 2, count: 12)), "tagBits": 128],
      "ciphertext": RecoveryQR.encode(Data(repeating: 3, count: 32))])
  }
}
