@testable import CastaliaCustody
import Foundation
import SQLite3
import XCTest
@testable import ZenithKit

/// Real native Core + encrypted SQLite lifecycle; all inputs are public test custody.
final class PortableFeedIntegrationTests: XCTestCase {
  private struct Fixture: Decodable {
    struct Inputs: Decodable { let custodyFile: String; let custodyPassword: String; let dataPassword: String }
    struct Vector: Decodable { let id: String; let valid: Bool; let contentsRaw: String; let envelope: String }
    let inputs: Inputs
    let cases: [Vector]
  }
  private let localPassword = "Synthetic native feed local password"
  private func fixture() throws -> Fixture {
    let url = try XCTUnwrap(Bundle.module.url(forResource: "feeds-encrypted-v3", withExtension: "json"))
    return try JSONDecoder().decode(Fixture.self, from: Data(contentsOf: url))
  }
  private func vector(_ fixture: Fixture, _ id: String) throws -> Fixture.Vector {
    try XCTUnwrap(fixture.cases.first { $0.id == id })
  }
  private func restore(_ fixture: Fixture, at directory: URL, data: Data? = nil) async throws -> WalletRepository {
    let repo = try WalletRepository(directory: directory)
    let review = try await repo.prepareRestore(file: Data(fixture.inputs.custodyFile.utf8), filePassword: fixture.inputs.custodyPassword,
      password: localPassword, dataFile: data, dataPassword: data == nil ? nil : fixture.inputs.dataPassword)
    _ = try await repo.commit(review)
    return repo
  }
  private func feeds(_ repo: WalletRepository) async throws -> NSDictionary? {
    let raw = try await repo.dataSummary()
    let summary = try XCTUnwrap(JSONSerialization.jsonObject(with: raw) as? [String: Any])
    let contents = summary["contents"] as? [String: Any]
    let sections = contents?["sections"] as? [String: Any]
    return sections?["feeds"] as? NSDictionary
  }
  private func expectedFeeds(_ fixture: Fixture) throws -> NSDictionary {
    let raw = try vector(fixture, "populated").contentsRaw
    let value = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(raw.utf8)) as? [String: Any])
    let sections = try XCTUnwrap(value["sections"] as? [String: Any])
    return try XCTUnwrap(sections["feeds"] as? NSDictionary)
  }
  private func stored(_ directory: URL) throws -> SnapshotStore.Stored {
    try XCTUnwrap(SnapshotStore(directory: directory).read())
  }
  /// The caller supplies only a fresh synthetic test directory. Failure injection
  /// uses an actual SQLite trigger; no production hook or storage code changes.
  private func sql(_ statement: String, in directory: URL) throws {
    var database: OpaquePointer?
    XCTAssertEqual(sqlite3_open_v2(directory.appendingPathComponent("wallet.sqlite").path,
      &database, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX, nil), SQLITE_OK)
    let opened = try XCTUnwrap(database)
    defer { sqlite3_close(opened) }
    XCTAssertEqual(sqlite3_exec(opened, statement, nil, nil, nil), SQLITE_OK)
  }
  private func probeCount(_ directory: URL) throws -> Int {
    var database: OpaquePointer?
    XCTAssertEqual(sqlite3_open_v2(directory.appendingPathComponent("wallet.sqlite").path,
      &database, SQLITE_OPEN_READONLY, nil), SQLITE_OK)
    let opened = try XCTUnwrap(database)
    defer { sqlite3_close(opened) }
    var statement: OpaquePointer?
    XCTAssertEqual(sqlite3_prepare_v2(opened, "SELECT COUNT(*) FROM feed_failure_probe",
      -1, &statement, nil), SQLITE_OK)
    defer { sqlite3_finalize(statement) }
    XCTAssertEqual(sqlite3_step(statement), SQLITE_ROW)
    return Int(sqlite3_column_int64(statement, 0))
  }
  func testStaleRepositoryCannotOverwriteAConcurrentFeedSnapshot() async throws {
    let f = try fixture(), root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    let first = try await restore(f, at: root, data: Data(try vector(f, "populated").envelope.utf8))
    let second = try WalletRepository(directory: root)
    _ = try await second.unlock(password: localPassword)
    let stale = try await first.prepareData(file: Data(try vector(f, "empty").envelope.utf8),
      password: f.inputs.dataPassword)
    let identities = try await second.walletIdentitySnapshot()
    let added = try WalletIdentity(kind: .github, label: "Concurrent synthetic account", identifier: "87654", server: "")
    let proposed = try WalletIdentitySection(ownerMemberKey: identities.section.ownerMemberKey,
      accounts: identities.section.accounts + [added])
    let winning = try await second.prepareWalletIdentities(proposed, expectedRevision: identities.revision)
    let winner = try await second.commit(winning)
    XCTAssertEqual(winner.revision, stale.expectedRevision + 1)
    let committed = try stored(root)
    do { _ = try await first.commit(stale); XCTFail("Stale repository overwrote the newer snapshot") }
    catch { XCTAssertEqual(error as? WalletFailure, .conflict) }
    let after = try stored(root), staleState = try await first.state()
    XCTAssertEqual(after.snapshot, committed.snapshot)
    XCTAssertEqual(after.revision, committed.revision)
    XCTAssertEqual(staleState.revision, stale.expectedRevision, "Failed storage CAS must not acknowledge the candidate in Core")
    do { _ = try await first.commit(stale); XCTFail("Failed candidate remained reusable") }
    catch { XCTAssertEqual(error as? WalletFailure, .conflict) }
    let reopened = try WalletRepository(directory: root)
    _ = try await reopened.unlock(password: localPassword)
    let saved = try await reopened.walletIdentitySnapshot(), actual = try await feeds(reopened)
    XCTAssertEqual(saved.section, proposed)
    XCTAssertEqual(actual, try expectedFeeds(f))
    XCTAssertEqual(saved.revision, winner.revision)
    let refreshed = try await reopened.prepareData(file: Data(try vector(f, "empty").envelope.utf8),
      password: f.inputs.dataPassword)
    _ = try await reopened.commit(refreshed)
    let final = try await reopened.walletIdentitySnapshot()
    XCTAssertEqual(final.section, proposed, "Retry after reopening must preserve the competing identity change")
  }
  func testSQLiteWriteFailureRollsBackCandidateAndInvalidatesReviewWithoutInstallingFeeds() async throws {
    let f = try fixture(), root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    let repo = try await restore(f, at: root)
    let before = try stored(root), beforeState = try await repo.state()
    try sql("""
      CREATE TABLE feed_failure_probe(marker INTEGER NOT NULL);
      CREATE TRIGGER fail_feed_candidate AFTER INSERT ON snapshot BEGIN
        INSERT INTO feed_failure_probe VALUES(1);
        SELECT RAISE(FAIL, 'synthetic feed storage failure');
      END;
      """, in: root)
    let prepared = try await repo.prepareData(file: Data(try vector(f, "populated").envelope.utf8),
      password: f.inputs.dataPassword)
    XCTAssertEqual(prepared.importedFeedSubscriptions, 1)
    do { _ = try await repo.commit(prepared); XCTFail("SQLite trigger failure was ignored") }
    catch { XCTAssertEqual(error as? WalletFailure, .storage) }
    // RAISE(FAIL) preserves partial statement changes until the store rolls the
    // transaction back. Both the candidate row and trigger side effect must go.
    let rolledBack = try stored(root), failedState = try await repo.state()
    XCTAssertEqual(rolledBack.snapshot, before.snapshot)
    XCTAssertEqual(rolledBack.revision, before.revision)
    XCTAssertEqual(try probeCount(root), 0)
    XCTAssertEqual(failedState.revision, beforeState.revision)
    let uninstalled = try await feeds(repo)
    XCTAssertNil(uninstalled, "Failed storage must not install feed contents in Core")
    try sql("DROP TRIGGER fail_feed_candidate", in: root)
    do { _ = try await repo.commit(prepared); XCTFail("Failed review was reusable after storage recovered") }
    catch { XCTAssertEqual(error as? WalletFailure, .conflict) }
    let reopenedBefore = try WalletRepository(directory: root)
    _ = try await reopenedBefore.unlock(password: localPassword)
    let stillAbsent = try await feeds(reopenedBefore)
    XCTAssertNil(stillAbsent)
    let fresh = try await repo.prepareData(file: Data(try vector(f, "populated").envelope.utf8),
      password: f.inputs.dataPassword)
    let recoveredState = try await repo.commit(fresh)
    XCTAssertEqual(recoveredState.revision, beforeState.revision + 1)
    let reopenedAfter = try WalletRepository(directory: root)
    _ = try await reopenedAfter.unlock(password: localPassword)
    let durable = try await feeds(reopenedAfter)
    XCTAssertEqual(durable, try expectedFeeds(f))
    XCTAssertEqual(try probeCount(root), 0)
  }
  func testNativeV3ReviewCancellationLegacyImportsEditsAndReopenPreserveExactFeeds() async throws {
    let f = try fixture(), root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    let repo = try await restore(f, at: root)
    let legacy = try await repo.exportData(password: f.inputs.dataPassword)
    let file = Data(try vector(f, "populated").envelope.utf8)
    let database = root.appendingPathComponent("wallet.sqlite")
    let before = try Data(contentsOf: database)
    let canceled = try await repo.prepareData(file: file, password: f.inputs.dataPassword)
    XCTAssertEqual(canceled.importedFeedSubscriptions, 1)
    XCTAssertEqual(canceled.importedFeedCollections, 1)
    let review = WalletImportReview(preview: canceled, context: try .dataFile(file, recovering: false))
    XCTAssertEqual(review.feedsAfterImport?.subscriptions.count, 1)
    XCTAssertEqual(review.savedIdentities?.accounts.count, 1)
    XCTAssertEqual(try Data(contentsOf: database), before)
    await repo.cancel()
    do { _ = try await repo.commit(canceled); XCTFail("Canceled feed candidate committed") } catch { }
    XCTAssertEqual(try Data(contentsOf: database), before)
    let prepared = try await repo.prepareData(file: file, password: f.inputs.dataPassword)
    _ = try await repo.commit(prepared)
    let expected = try expectedFeeds(f), stored = try await feeds(repo)
    XCTAssertEqual(stored, expected)
    XCTAssertNil(try Data(contentsOf: database).range(of: Data("Reading essays".utf8)))
    for incoming in [legacy, Data(try vector(f, "empty").envelope.utf8)] {
      let preview = try await repo.prepareData(file: incoming, password: f.inputs.dataPassword)
      XCTAssertEqual(preview.memberships?.feeds?.subscriptions.count, 1)
      _ = try await repo.commit(preview)
      let preserved = try await feeds(repo)
      XCTAssertEqual(preserved, expected)
    }
    let snapshot = try await repo.walletIdentitySnapshot()
    let extra = try WalletIdentity(kind: .github, label: "Another synthetic account", identifier: "67890", server: "")
    let identities = try WalletIdentitySection(ownerMemberKey: snapshot.section.ownerMemberKey, accounts: snapshot.section.accounts + [extra])
    let edit = try await repo.prepareWalletIdentities(identities, expectedRevision: snapshot.revision)
    _ = try await repo.commit(edit)
    let edited = try await feeds(repo)
    XCTAssertEqual(edited, expected)
    let unchanged = try Data(contentsOf: database)
    do { _ = try await repo.prepareData(file: Data(try vector(f, "conflicting-title").envelope.utf8), password: f.inputs.dataPassword); XCTFail("Conflicting feed values accepted") } catch { }
    XCTAssertEqual(try Data(contentsOf: database), unchanged)
    do { _ = try await repo.exportData(password: f.inputs.dataPassword); XCTFail("Unqualified v3 writer enabled") }
    catch { XCTAssertEqual(error as? WalletFailure, .core("feed_writer_not_qualified")) }
    await repo.lock()
    let reopened = try WalletRepository(directory: root)
    _ = try await reopened.unlock(password: localPassword)
    let recovered = try await feeds(reopened)
    XCTAssertEqual(recovered, expected)
  }
  func testCombinedRecoveryPreviewAndAuthenticatedInvalidVectorsNeverCommit() async throws {
    let f = try fixture(), root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    let repo = try WalletRepository(directory: root)
    let data = Data(try vector(f, "populated").envelope.utf8)
    let prepared = try await repo.prepareRestore(file: Data(f.inputs.custodyFile.utf8), filePassword: f.inputs.custodyPassword,
      password: localPassword, dataFile: data, dataPassword: f.inputs.dataPassword)
    XCTAssertEqual(prepared.importedFeedSubscriptions, 1)
    XCTAssertEqual(prepared.importedFeedCollections, 1)
    let pendingState = try await repo.state()
    XCTAssertFalse(pendingState.configured)
    _ = try await repo.commit(prepared)
    let expected = try expectedFeeds(f), actual = try await feeds(repo)
    XCTAssertEqual(actual, expected)
    let database = root.appendingPathComponent("wallet.sqlite"), before = try Data(contentsOf: root.appendingPathComponent("wallet.sqlite"))
    for invalid in f.cases where !invalid.valid {
      do { _ = try await repo.prepareData(file: Data(invalid.envelope.utf8), password: f.inputs.dataPassword); XCTFail("Invalid vector accepted: " + invalid.id) } catch { }
      XCTAssertEqual(try Data(contentsOf: database), before, invalid.id)
    }
    let after = try await feeds(repo)
    XCTAssertEqual(after, expected)
  }
}
