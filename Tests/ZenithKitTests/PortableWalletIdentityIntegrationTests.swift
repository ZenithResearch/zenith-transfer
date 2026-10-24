import Foundation
import XCTest
@testable import ZenithKit

final class PortableWalletIdentityIntegrationTests: XCTestCase {
  func testSharedProducerFixtureDecodesExactly() throws {
    let file = try XCTUnwrap(Bundle.module.url(forResource: "wallet-identities-v1", withExtension: "json"))
    let value = try WalletIdentitySection.decode(Data(contentsOf: file))
    XCTAssertEqual(value.accounts.map(\.kind), [.matrix, .nostr, .github, .x])
    let roundtrip = try JSONSerialization.jsonObject(with: JSONEncoder().encode(value)) as! NSDictionary
    XCTAssertEqual(roundtrip, try JSONSerialization.jsonObject(with: Data(contentsOf: file)) as! NSDictionary)
  }
  func testExplicitMigrationEncryptedV2RoundTripAndOldV1PreservesNewRecords() async throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    let repo = try WalletRepository(directory: root.appendingPathComponent("source"))
    let created = try await repo.create(password: "disposable identity local password")
    let owner = try XCTUnwrap(created.publicKey)
    let recovery = try await repo.exportRecovery(password: "disposable recovery password")
    let oldV1 = try await repo.exportData(password: "disposable data password")
    let registry = try IdentityAccountRegistry(directory: root.appendingPathComponent("legacy"))
    let record = try IdentityAccount(walletPublicKey: owner, provider: .matrix, label: "My chat", identifier: "@migration:example.test", server: "https://matrix.example.test")
    let tailscale = try IdentityAccount(walletPublicKey: owner, provider: .tailscale, label: "Network", identifier: "member", server: "example.ts.net")
    try registry.save(record, replacing: nil); try registry.save(tailscale, replacing: nil)
    let sourceURL = root.appendingPathComponent("legacy").appendingPathComponent(record.id.uuidString.lowercased() + ".json")
    let originalBytes = try Data(contentsOf: sourceURL)
    let original = try await repo.walletIdentitySnapshot()
    let plan = try WalletIdentityMigration.prepare(existing: original.section, legacy: registry.load(wallet: owner))
    let preview = try await repo.prepareWalletIdentities(plan.proposed, expectedRevision: original.revision)
    XCTAssertEqual(preview.walletIdentities, plan.proposed)
    let uncommitted = try await repo.walletIdentitySnapshot()
    XCTAssertEqual(uncommitted.section.accounts.count, 0, "Review must not write")
    _ = try await repo.commit(preview)
    let persisted = try await repo.walletIdentitySnapshot()
    XCTAssertEqual(persisted.section, plan.proposed)
    XCTAssertEqual(try Data(contentsOf: sourceURL), originalBytes)
    XCTAssertEqual(try registry.load(wallet: owner).count, 2)
    let stored = try Data(contentsOf: root.appendingPathComponent("source/wallet.sqlite"))
    XCTAssertNil(stored.range(of: Data(record.identifier.utf8)), "Wallet descriptors must be encrypted at rest")
    let v2 = try await repo.exportData(password: "disposable data password")
    XCTAssertEqual(try RecoveryFileFormat.inspect(v2, filename: "wallet.castaway").version, "v2")
    let restored = try WalletRepository(directory: root.appendingPathComponent("restored"))
    let restore = try await restored.prepareRestore(file: recovery, filePassword: "disposable recovery password", password: "new disposable local password", dataFile: v2, dataPassword: "disposable data password")
    XCTAssertEqual(restore.walletIdentities, plan.proposed)
    _ = try await restored.commit(restore)
    let reopened = try await restored.walletIdentitySnapshot()
    XCTAssertEqual(reopened.section, plan.proposed)
    XCTAssertEqual(reopened.chainAccounts?.accounts.map(\.address), original.chainAccounts?.accounts.map(\.address))
    let oldImport = try await restored.prepareData(file: oldV1, password: "disposable data password")
    XCTAssertEqual(oldImport.walletIdentities, plan.proposed)
    _ = try await restored.commit(oldImport)
    let after = try await restored.walletIdentitySnapshot()
    XCTAssertEqual(after.section, plan.proposed)
    let again = try await restored.exportData(password: "disposable data password")
    XCTAssertEqual(try RecoveryFileFormat.inspect(again, filename: "wallet.castaway").version, "v2")
  }
  func testLockAndStaleRevisionRejectIdentityChangesWithoutDurableWrites() async throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    let repo = try WalletRepository(directory: root)
    _ = try await repo.create(password: "disposable locking identity password")
    let original = try await repo.walletIdentitySnapshot()
    let identity = try WalletIdentity(kind: .github, label: "Gallery", identifier: "12345", server: "")
    let section = try WalletIdentitySection(ownerMemberKey: original.section.ownerMemberKey, accounts: [identity])
    let preview = try await repo.prepareWalletIdentities(section, expectedRevision: original.revision)
    await repo.lock()
    do { _ = try await repo.commit(preview); XCTFail("Locked preview must not commit") } catch { }
    _ = try await repo.unlock(password: "disposable locking identity password")
    let unchanged = try await repo.walletIdentitySnapshot()
    XCTAssertTrue(unchanged.section.accounts.isEmpty)
    do { _ = try await repo.prepareWalletIdentities(section, expectedRevision: original.revision + 1); XCTFail("Stale revision accepted") } catch { }
    let stillUnchanged = try await repo.walletIdentitySnapshot()
    XCTAssertEqual(unchanged.revision, stillUnchanged.revision)
    XCTAssertTrue(stillUnchanged.section.accounts.isEmpty)
  }
}
