import XCTest
@testable import ZenithKit

@MainActor private final class TestBiometricStore: BiometricCredentialStore {
  var credential: BiometricCredential?
  var isEnabled: Bool { credential != nil }
  var onRead: (() throws -> Void)?
  var onSave: (() throws -> Void)?
  var saves = 0
  func save(_ credential: BiometricCredential) async throws {
    saves += 1
    self.credential = credential
    try onSave?()
  }
  func read() async throws -> BiometricCredential {
    try onRead?()
    guard let credential else { throw BiometricUnlockError.missing }
    return credential
  }
  func remove() throws { credential = nil }
  func cancel() {}
}

@MainActor final class BiometricUnlockTests: XCTestCase {
  func testAutomaticTouchIDWaitsForReadyEnrolledIPadAndPromptsOnlyOnce() {
    var policy = AutomaticBiometricUnlock()
    XCTAssertFalse(policy.claim(isPad: true, touchID: true, enabled: false, ready: true))
    XCTAssertFalse(policy.claim(isPad: true, touchID: true, enabled: true, ready: false))
    XCTAssertTrue(policy.claim(isPad: true, touchID: true, enabled: true, ready: true))
    // A cancelled/failed prompt or a foreground cycle cannot prompt again.
    XCTAssertFalse(policy.claim(isPad: true, touchID: true, enabled: true, ready: false))
    XCTAssertFalse(policy.claim(isPad: true, touchID: true, enabled: true, ready: true))
  }
  func testIPhoneAndFaceIDKeepExplicitUnlock() {
    var policy = AutomaticBiometricUnlock()
    XCTAssertFalse(policy.claim(isPad: false, touchID: true, enabled: true, ready: true))
    XCTAssertFalse(policy.claim(isPad: false, touchID: false, enabled: true, ready: true))
    XCTAssertFalse(policy.claim(isPad: true, touchID: false, enabled: true, ready: true))
  }
  func testManualLockSuppressesAutomaticPromptUntilNewProcess() {
    var policy = AutomaticBiometricUnlock()
    policy.suppress()
    XCTAssertFalse(policy.claim(isPad: true, touchID: true, enabled: true, ready: true))
    var freshLaunch = AutomaticBiometricUnlock()
    XCTAssertTrue(freshLaunch.claim(isPad: true, touchID: true, enabled: true, ready: true))
  }
  private let password = "disposable biometric test password"
  private func wallet() throws -> (WalletRepository, URL) {
    let path = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    return (try WalletRepository(directory: path), path)
  }
  func testPasswordValidationBeforeSavingAndRealCoreUnlock() async throws {
    let (repository, directory) = try wallet()
    defer { try? FileManager.default.removeItem(at: directory) }
    let original = try await repository.create(password: password)
    let store = TestBiometricStore()
    let unlock = BiometricUnlock(store: store)
    await repository.lock()
    do { _ = try await unlock.enable(password: "incorrect password", repository: repository); XCTFail("Accepted wrong password") } catch {}
    XCTAssertEqual(store.saves, 0)
    _ = try await unlock.enable(password: password, repository: repository)
    XCTAssertTrue(unlock.isEnabled)
    await repository.lock()
    let restored = try await unlock.unlock(repository: repository)
    XCTAssertEqual(restored.publicKey, original.publicKey)
    XCTAssertFalse(restored.backupVerified)
    XCTAssertFalse(restored.membershipActive)
    try unlock.disable()
    XCTAssertFalse(unlock.isEnabled)
  }
  func testCancelledAndStaleBiometricReadsCannotUnlock() async throws {
    let (repository, directory) = try wallet()
    defer { try? FileManager.default.removeItem(at: directory) }
    _ = try await repository.create(password: password)
    let store = TestBiometricStore()
    let unlock = BiometricUnlock(store: store)
    _ = try await unlock.enable(password: password, repository: repository)
    await repository.lock()
    store.onRead = { throw BiometricUnlockError.cancelled }
    do { _ = try await unlock.unlock(repository: repository); XCTFail("Cancelled unlock succeeded") } catch {}
    var state = try await repository.state()
    XCTAssertFalse(state.unlocked)
    XCTAssertTrue(unlock.isEnabled)
    store.onRead = { repository.invalidatePendingWork() }
    do { _ = try await unlock.unlock(repository: repository); XCTFail("Stale unlock succeeded") } catch {}
    state = try await repository.state()
    XCTAssertFalse(state.unlocked)
  }
  func testWrongIdentityFailsClosedEvenWithCorrectPassword() async throws {
    let (repository, directory) = try wallet()
    defer { try? FileManager.default.removeItem(at: directory) }
    _ = try await repository.create(password: password)
    await repository.lock()
    let store = TestBiometricStore()
    store.credential = BiometricCredential(identity: "another-wallet", password: password)
    let unlock = BiometricUnlock(store: store)
    do { _ = try await unlock.unlock(repository: repository); XCTFail("Accepted different identity") } catch {}
    let state = try await repository.state()
    XCTAssertFalse(state.unlocked)
  }
  func testInterruptedEnrollmentRemovesSecretAndRetainsPasswordFallback() async throws {
    let (repository, directory) = try wallet()
    defer { try? FileManager.default.removeItem(at: directory) }
    let original = try await repository.create(password: password)
    let store = TestBiometricStore()
    let unlock = BiometricUnlock(store: store)
    store.onSave = { repository.invalidatePendingWork() }
    do { _ = try await unlock.enable(password: password, repository: repository); XCTFail("Stale enrollment succeeded") } catch {}
    XCTAssertFalse(unlock.isEnabled)
    let locked = try await repository.state()
    XCTAssertFalse(locked.unlocked)
    let restored = try await repository.unlock(password: password)
    XCTAssertEqual(restored.publicKey, original.publicKey)
    store.onSave = { throw BiometricUnlockError.storage }
    do { _ = try await unlock.enable(password: password, repository: repository); XCTFail("Failed save succeeded") } catch {}
    XCTAssertFalse(unlock.isEnabled)
  }
}
