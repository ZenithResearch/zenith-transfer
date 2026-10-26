import Foundation
import XCTest
@testable import ZenithKit

final class WalletImportReviewTests: XCTestCase {
  func testRecoveryNeverTreatsSynthesizedOrExistingDataAsAnImportedDataFile() throws {
    let preview = try fixture()
    for context: WalletImportReview.Context in [.recovery, .olderRecoveryKey] {
      let review = WalletImportReview(preview: preview, context: context)
      XCTAssertEqual(review.id, preview.token)
      XCTAssertTrue(review.recoversWallet)
      XCTAssertEqual(review.derivedAccounts.count, 4)
      XCTAssertFalse(review.hasCastawayData)
      XCTAssertNil(review.savedIdentities)
      XCTAssertNil(review.profile)
      XCTAssertTrue(review.proofs.isEmpty)
      XCTAssertTrue(review.savedAccounts.isEmpty)
      XCTAssertNil(review.identityImportNote)
    }
  }

  func testCombinedV2KeepsBothGroupsAndReplacementWarnings() throws {
    let review = WalletImportReview(preview: try fixture(), context: .recoveryAndCastaway(.v2))
    XCTAssertTrue(review.recoversWallet)
    XCTAssertTrue(review.hasCastawayData)
    XCTAssertEqual(review.derivedAccounts.count, 4)
    XCTAssertEqual(review.savedAccounts.map(\.networkId), ["eip155:1"])
    XCTAssertEqual(review.savedIdentities?.accounts.map(\.kind), [.matrix])
    XCTAssertEqual(review.profile?.subject.fields["displayName"]?.value, "Fixture")
    XCTAssertEqual(review.proofs.count, 1)
    XCTAssertTrue(review.replacesProfile)
    XCTAssertEqual(review.replacedProofCount, 1)
    XCTAssertTrue(try XCTUnwrap(review.identityImportNote).contains("1"))
  }

  func testDataOnlyShowsMatchingWalletAndSavedDescriptorsNotAllDerivedAddresses() throws {
    let review = WalletImportReview(preview: try fixture(), context: .castaway(.v2))
    XCTAssertFalse(review.recoversWallet)
    XCTAssertTrue(review.derivedAccounts.isEmpty)
    XCTAssertEqual(review.savedAccounts.count, 1)
    XCTAssertEqual(review.savedIdentities?.accounts.count, 1)
  }

  func testV1DoesNotPresentPreservedIdentitiesAsIncomingRecords() throws {
    let review = WalletImportReview(preview: try fixture(), context: .castaway(.v1))
    XCTAssertNil(review.savedIdentities)
    XCTAssertEqual(review.identityImportNote, "This older Castaway file has no saved account identities. Existing identities are preserved.")
  }

  func testEmptyV2IsDifferentFromAbsentV1AndDoesNotImplyDeletion() throws {
    let review = WalletImportReview(preview: try fixture(empty: true), context: .castaway(.v2))
    XCTAssertEqual(review.savedIdentities?.accounts.count, 0)
    XCTAssertEqual(review.identityImportNote, "This file contains 0 saved account identities. Existing nonconflicting identities are preserved; the review shows the result after import.")
  }

  func testDataContextUsesValidatedEnvelopeRatherThanPreviewIdentityCount() throws {
    for version in ["v1", "v2"] {
      let file = try envelope(schema: "castalia.castaway.\(version)")
      XCTAssertEqual(try WalletImportReview.Context.dataFile(file, recovering: false), .castaway(version == "v1" ? .v1 : .v2))
      XCTAssertEqual(try WalletImportReview.Context.dataFile(file, recovering: true), .recoveryAndCastaway(version == "v1" ? .v1 : .v2))
    }
    XCTAssertThrowsError(try WalletImportReview.Context.dataFile(envelope(schema: "castalia.wallet-custody.v1"), recovering: false))
    XCTAssertThrowsError(try WalletImportReview.Context.dataFile(Data("{}".utf8), recovering: true))
  }

  private func fixture(empty: Bool = false) throws -> RestorePreview {
    let owner = String(repeating: "a", count: 64)
    let account: [String: Any] = ["accountId": "018d0000-0000-4000-8000-000000000001", "kind": "matrix", "label": "Chat", "identifier": "@fixture:example.test", "server": "https://matrix.example.test"]
    let identities: [String: Any] = ["schema": "castalia.wallet-identities.v1", "version": 1, "ownerMemberKey": owner, "authority": "descriptor-only", "accounts": empty ? [] : [account]]
    let derived = (0..<4).map { ["accountId": "derived-\($0)", "networkId": "network-\($0)", "address": "address-\($0)"] }
    let value: [String: Any] = ["token": "prepared-token", "expected_revision": 7, "public_key": owner, "backup_verified": true,
      "chain_accounts": ["accounts": derived], "wallet_identities": identities, "imported_wallet_identities": empty ? 0 : 1,
      "profile": ["subject": ["memberKey": owner, "fields": ["displayName": ["value": "Fixture", "disclosure": "private"]]]],
      "memberships": ["memberships": [["membershipId": "proof", "issuerId": "issuer"]], "chainAccounts": ["accounts": [["accountId": "saved", "networkId": "eip155:1", "address": "saved-address"]]]],
      "replaces_profile": true, "replaced_proofs": ["proof"]]
    return try JSONDecoder().decode(RestorePreview.self, from: JSONSerialization.data(withJSONObject: value))
  }

  private func envelope(schema: String) throws -> Data {
    // The presentation only inspects the already validated public envelope.
    var value: [String: Any] = ["schema": schema,
      "kdf": ["name": "Argon2id", "version": 19, "salt": RecoveryQR.encode(Data(repeating: 1, count: 16)), "memoryKiB": 65_536, "iterations": 3, "parallelism": 1, "derivedKeyBytes": 32],
      "aead": ["name": "AES-256-GCM", "nonce": RecoveryQR.encode(Data(repeating: 2, count: 12)), "tagBits": 128],
      "ciphertext": RecoveryQR.encode(Data(repeating: 3, count: 32))]
    if schema == "castalia.wallet-custody.v1" {
      value["keySuite"] = "Ed25519"; value["publicKey"] = String(repeating: "a", count: 64); value["createdAt"] = 1
    } else {
      value["contentsSchema"] = schema.replacingOccurrences(of: "castaway.", with: "castaway-contents.")
      value["ownerPublicKey"] = String(repeating: "a", count: 64); value["exportedAt"] = 1
    }
    return try JSONSerialization.data(withJSONObject: value)
  }
}
