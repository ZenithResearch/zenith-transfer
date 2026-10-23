import XCTest

@testable import ZenithKit

final class WalletRepositoryTests: XCTestCase {
  func testNativeMemberConsentCannotBeUsedForOperatorDecisions() async throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: directory) }
    let repository = try WalletRepository(directory: directory)
    _ = try await repository.create(password: "disposable boundary password")
    let recovery = try await repository.exportRecovery(password: "disposable backup password")
    _ = try await repository.verifyBackup(file: recovery, password: "disposable backup password")
    let identity = try JSONSerialization.jsonObject(with: await repository.graphAccessIdentityV2()) as! [String: String]
    let pin = try WorkAccessConfiguration(name: "Operator boundary", receiver: URL(string: "https://work.example")!,
      issuer: "example-issuer", keyID: "example-key", publicKey: String(repeating: "12", count: 32)).authority
    let now = UInt64(Date().timeIntervalSince1970)
    func challenge(_ operation: String) throws -> Data {
      try JSONSerialization.data(withJSONObject: ["schema":"castalia.access-request-challenge.v1",
        "challenge_id":String(repeating:"aa",count:16),"nonce":String(repeating:"A",count:43),
        "issuer":pin.issuer,"receiver":pin.receiver,"subject_public_key":identity["subject_public_key"]!,
        "installation_id":identity["installation_id"]!,"operation":operation,"issued_at":now,"expires_at":now+120,
        "details":["action":["action":"inbox"]]])
    }
    // A valid member-consent challenge succeeds, so failures below are not
    // explained by a locked Wallet, malformed nonce, clock or issuer pin.
    _ = try await repository.prepareGraphAccessRequestV2(challenge("access.request"), pin: pin, now: now)
    for operation in ["access.inbox", "access.review", "access.decide"] {
      do {
        _ = try await repository.prepareGraphAccessRequestV2(challenge(operation), pin: pin, now: now)
        XCTFail("Native member consent must not authorize \(operation)")
      } catch { }
    }
  }
  func testServerSetupClearsAbsentReadAccessWithoutChangingCustody() async throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: directory) }
    let repository = try WalletRepository(directory: directory)
    let created = try await repository.create(password: "disposable setup password")
    try await repository.forgetReadAccess(receiver: "https://devgraph.example")
    let after = try await repository.state()
    XCTAssertEqual(after.publicKey, created.publicKey)
    XCTAssertFalse(after.backupVerified)
    XCTAssertFalse(after.membershipActive)
    await repository.lock()
    let reopened = try await repository.unlock(password: "disposable setup password")
    XCTAssertEqual(reopened.publicKey, created.publicKey)
  }
  func testNativeCoreRecoveryAndDurableBackupGate() async throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: directory) }
    let repository = try WalletRepository(directory: directory)
    let created = try await repository.create(password: "local password 123")
    XCTAssertTrue(created.unlocked)
    XCTAssertFalse(created.backupVerified)
    let file = try await repository.exportRecovery(password: "backup password 123")
    let verified = try await repository.verifyBackup(file: file, password: "backup password 123")
    XCTAssertTrue(verified.backupVerified)
    await repository.lock()
    let reopened = try WalletRepository(directory: directory)
    let locked = try await reopened.state()
    XCTAssertFalse(locked.unlocked)
    let unlocked = try await reopened.unlock(password: "local password 123")
    XCTAssertEqual(unlocked.publicKey, created.publicKey)
    XCTAssertTrue(unlocked.backupVerified)
  }
}
