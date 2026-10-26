import Foundation
import XCTest
@testable import ZenithKit

final class WalletExperienceTests: XCTestCase {
  func testWalletNavigationSeparatesAccountsRecoveryCredentialsAndSecurity() {
    XCTAssertEqual(WalletDestination.allCases.map(\.rawValue),
      ["identities", "membership", "recovery", "access", "security", "about"])
    XCTAssertEqual(WalletDestination.access.title, "Saved grants")
    XCTAssertEqual(WalletDestination.security.title, "Unlock & security")
  }
  func testOnlyImplementedBackupCoveredDataIsShownInWallet() {
    XCTAssertEqual(WalletDestination.walletCases, [.identities, .membership, .recovery, .access])
    XCTAssertEqual(WalletDestination.identities.backupCoverage, .recoveryAndCastaway)
    XCTAssertEqual(WalletDestination.membership.backupCoverage, .castaway)
    XCTAssertEqual(WalletDestination.access.backupCoverage, .encryptedGrants)
    for applicationOnly in [WalletDestination.security, .about] {
      XCTAssertNil(applicationOnly.backupCoverage)
      XCTAssertFalse(WalletDestination.walletCases.contains(applicationOnly))
    }
  }
  func testImportCanReuseBackupPasswordWithoutChangingIdentityOrRequiringAnotherPassword() {
    XCTAssertEqual(WalletPasswordRules.importPassword(file: "my existing backup password", local: "", confirmation: "", reuse: true), "my existing backup password")
    XCTAssertNil(WalletPasswordRules.importPassword(file: "old", local: "", confirmation: "", reuse: true))
    XCTAssertEqual(WalletPasswordRules.importPassword(file: "old", local: "new local password", confirmation: "new local password", reuse: false), "new local password")
    XCTAssertNil(WalletPasswordRules.importPassword(file: "old", local: "new local password", confirmation: "different password", reuse: false))
  }
  func testPasswordRulesMatchCoreScalarsAndBoundBytesWithoutNormalization() {
    XCTAssertTrue(WalletPasswordRules.permitsLocal(String(repeating: "e\u{301}", count: 6)))
    XCTAssertFalse(WalletPasswordRules.permitsLocal(String(repeating: "a", count: 11)))
    XCTAssertFalse(WalletPasswordRules.permitsLocal(String(repeating: "é", count: 2049)))
  }
  func testSharedSessionDefaultPreservesSavedChoicesAndDoesNotExtendOnRead() {
    let name = "WalletExperienceTests." + UUID().uuidString
    let defaults = UserDefaults(suiteName: name)!
    defer { defaults.removePersistentDomain(forName: name) }
    XCTAssertEqual(WalletUnlockDuration.load(defaults, key: "test"), .oneHour)
    XCTAssertEqual(WalletUnlockDuration.selectableCases, [.fifteenMinutes, .oneHour, .fourHours, .untilLocked])
    defaults.set(WalletUnlockDuration.oneHour.rawValue, forKey: "test")
    XCTAssertEqual(WalletUnlockDuration.load(defaults, key: "test"), .oneHour)
    var timer = WalletUnlockTimer()
    timer.observe(unlocked: true, now: Date(timeIntervalSince1970: 1000), uptime: 100)
    timer.observe(unlocked: true, now: Date(timeIntervalSince1970: 4500), uptime: 3600)
    XCTAssertTrue(timer.expired(.oneHour, now: Date(timeIntervalSince1970: 1), uptime: 3700))
    XCTAssertFalse(timer.expired(.untilLocked, now: .distantFuture, uptime: 1_000_000))
    timer.observe(unlocked: false, now: Date(), uptime: 3700)
    XCTAssertNil(timer.deadline(.oneHour))
  }
  func testUserInputExtendsIdleButCannotReviveAnExpiredWallet() {
    var timer = WalletUnlockTimer()
    timer.observe(unlocked: true, now: Date(timeIntervalSince1970: 1000), uptime: 100)
    XCTAssertTrue(timer.activity(.oneHour, now: Date(timeIntervalSince1970: 4500), uptime: 3600))
    XCTAssertFalse(timer.expired(.oneHour, now: Date(timeIntervalSince1970: 4600), uptime: 3700))
    XCTAssertEqual(timer.deadline(.oneHour), Date(timeIntervalSince1970: 8100))
    XCTAssertFalse(timer.activity(.oneHour, now: Date(timeIntervalSince1970: 8100), uptime: 7200))
    XCTAssertTrue(timer.expired(.oneHour, now: Date(timeIntervalSince1970: 8100), uptime: 7200))
    timer.clear()
    XCTAssertFalse(timer.activity(.oneHour, now: Date(), uptime: 8000))
  }
}
