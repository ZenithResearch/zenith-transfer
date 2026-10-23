#if os(macOS)
import Foundation
import XCTest
import ZenithKit
@testable import ZenithTransfer

final class TransferUnlockPolicyTests:XCTestCase {
  func testDefaultIsOneHourAndOnlySupportedSettingsAreRestored() {
    let name="TransferUnlockPolicyTests."+UUID().uuidString
    let defaults=UserDefaults(suiteName:name)!
    defer { defaults.removePersistentDomain(forName:name) }
    XCTAssertEqual(TransferUnlockDuration.load(defaults),.oneHour)
    defaults.set(-1,forKey:TransferUnlockDuration.settingKey)
    XCTAssertEqual(TransferUnlockDuration.load(defaults),.oneHour)
    for policy in TransferUnlockDuration.allCases {
      defaults.set(policy.rawValue,forKey:TransferUnlockDuration.settingKey)
      XCTAssertEqual(TransferUnlockDuration.load(defaults),policy)
    }
  }
  func testReadsDoNotExtendHourAndClockRollbackCannotExtendIt() {
    var timer=TransferUnlockTimer()
    timer.observe(unlocked:true,now:Date(timeIntervalSince1970:1000),uptime:10)
    timer.observe(unlocked:true,now:Date(timeIntervalSince1970:4500),uptime:3510)
    XCTAssertEqual(timer.deadline(.oneHour),Date(timeIntervalSince1970:4600))
    XCTAssertFalse(timer.expired(.oneHour,now:Date(timeIntervalSince1970:4599),uptime:3609))
    XCTAssertTrue(timer.expired(.oneHour,now:Date(timeIntervalSince1970:4600),uptime:3610))
    XCTAssertTrue(timer.expired(.oneHour,now:Date(timeIntervalSince1970:1),uptime:3610))
    XCTAssertTrue(timer.expired(.oneHour,now:Date(timeIntervalSince1970:4600),uptime:20),"Sleep still counts via wall time")
    XCTAssertFalse(timer.expired(.untilLocked,now:Date.distantFuture,uptime:1_000_000))
    timer.observe(unlocked:false,now:Date(),uptime:20)
    XCTAssertNil(timer.started)
  }
  @MainActor func testModelLocksAtHourPreservesIdentityAndStartsLockedAfterRelaunch() async throws {
    let root=FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at:root) }
    let name="TransferUnlockModelTests."+UUID().uuidString,defaults=UserDefaults(suiteName:name)!
    defer { defaults.removePersistentDomain(forName:name) }
    var seconds:TimeInterval=1000
    let model=TransferModel(directory:root,defaults:defaults,clock:{(Date(timeIntervalSince1970:seconds),seconds)})
    let repo=try XCTUnwrap(model.repository)
    _ = try await repo.create(password:"disposable unlock policy password")
    await model.refresh()
    let key=try XCTUnwrap(model.wallet?.publicKey)
    let ticket=repo.lifecycleTicket()
    XCTAssertTrue(model.walletUnlocked)
    seconds += 3599
    await model.refresh();model.expire()
    XCTAssertTrue(model.walletUnlocked,"Reading state must not lock early or extend the period")
    seconds += 1;model.expire()
    XCTAssertFalse(model.walletUnlocked,"Signing UI disables synchronously")
    XCTAssertThrowsError(try repo.checkLifecycle(ticket),"Old consent invalidates immediately")
    for _ in 0..<100 { if !model.locking { break };try await Task.sleep(nanoseconds:1_000_000) }
    let lockedState=try await repo.state()
    XCTAssertFalse(lockedState.unlocked)
    XCTAssertEqual(model.displayPublicKey,key)
    let second=TransferModel(directory:root,defaults:defaults)
    await second.refresh()
    XCTAssertFalse(second.walletUnlocked)
    XCTAssertEqual(second.displayPublicKey,key)
  }
  @MainActor func testDurationChangePersistsAndUntilLockedStillAllowsManualLock() async throws {
    let root=FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at:root) }
    let name="TransferUnlockSelectionTests."+UUID().uuidString,defaults=UserDefaults(suiteName:name)!
    defer { defaults.removePersistentDomain(forName:name) }
    var seconds:TimeInterval=100
    let model=TransferModel(directory:root,defaults:defaults,clock:{(Date(timeIntervalSince1970:seconds),seconds)})
    let repo=try XCTUnwrap(model.repository)
    _ = try await repo.create(password:"disposable selection password")
    await model.refresh();model.unlockDuration = .untilLocked
    seconds += 100000;model.expire()
    XCTAssertTrue(model.walletUnlocked)
    await repo.cancel()
    let stillUnlocked=try await repo.state()
    XCTAssertTrue(stillUnlocked.unlocked,"Closing Wallet forms cancels drafts, not unlock")
    model.lock()
    XCTAssertFalse(model.walletUnlocked)
    XCTAssertEqual(TransferUnlockDuration.load(defaults),.untilLocked)
  }
  @MainActor func testShorteningDeadlineDoesNotRestartIt() async throws {
    let root=FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at:root) }
    let name="TransferUnlockShortenTests."+UUID().uuidString,defaults=UserDefaults(suiteName:name)!
    defer { defaults.removePersistentDomain(forName:name) }
    var seconds:TimeInterval=100
    let model=TransferModel(directory:root,defaults:defaults,clock:{(Date(timeIntervalSince1970:seconds),seconds)})
    _ = try await XCTUnwrap(model.repository).create(password:"disposable shortening password")
    await model.refresh();seconds += 121
    model.unlockDuration = .twoMinutes
    XCTAssertFalse(model.walletUnlocked)
  }
}
#endif
