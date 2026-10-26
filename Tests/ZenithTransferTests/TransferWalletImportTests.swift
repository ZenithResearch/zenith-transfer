@testable import CastaliaCustody
#if os(macOS)
import Foundation
import XCTest
import ZenithKit
@testable import ZenithTransfer

final class TransferWalletImportTests: XCTestCase {
  func testRecoveryPasswordCanAlsoUnlockLocalCopyWithoutChangingBackup() async throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: directory) }
    let original = try WalletRepository(directory: directory.appendingPathComponent("original"))
    let originalState = try await original.create(password: "original local password")
    let secret = "disposable recovery password"
    let backup = try await original.exportRecovery(password: secret)
    let chosen = try XCTUnwrap(TransferPasswordRules.importPassword(file: secret, local: "", confirmation: "", reuse: true))
    let restored = try WalletRepository(directory: directory.appendingPathComponent("restored"))
    let preview = try await restored.prepareRestore(file: backup, filePassword: secret, password: chosen)
    XCTAssertEqual(preview.publicKey, originalState.publicKey)
    let before = try await restored.state()
    XCTAssertFalse(before.configured, "A preview must not save custody before public identity confirmation")
    let committed = try await restored.commit(preview)
    XCTAssertEqual(committed.publicKey, originalState.publicKey)
    await restored.lock()
    let unlocked = try await restored.unlock(password: secret)
    XCTAssertEqual(unlocked.publicKey, originalState.publicKey)
    // Re-open the same unchanged bytes with a separate local password.
    let second = try WalletRepository(directory: directory.appendingPathComponent("separate"))
    let other = try XCTUnwrap(TransferPasswordRules.importPassword(file: secret, local: "different local password", confirmation: "different local password", reuse: false))
    let secondPreview = try await second.prepareRestore(file: backup, filePassword: secret, password: other)
    _ = try await second.commit(secondPreview)
    await second.lock()
    do { _ = try await second.unlock(password: secret); XCTFail("Recovery password should not unlock a separately protected copy") }
    catch { XCTAssertEqual(error as? WalletFailure, .core("unlock_failed")) }
    let localUnlocked = try await second.unlock(password: other)
    XCTAssertEqual(localUnlocked.publicKey, originalState.publicKey)
  }

  func testValidationMatchesNativeScalarAndByteRulesWithoutNormalizingPasswords() {
    XCTAssertNil(TransferPasswordRules.importPassword(file: "short", local: "", confirmation: "", reuse: true))
    XCTAssertNotNil(TransferPasswordRules.importPassword(file: "short", local: "a separate local password", confirmation: "a separate local password", reuse: false))
    XCTAssertNil(TransferPasswordRules.importPassword(file: "file password", local: "long enough local password", confirmation: "different", reuse: false))
    XCTAssertNil(TransferPasswordRules.importPassword(file: "", local: "long enough local password", confirmation: "long enough local password", reuse: false))
    XCTAssertFalse(TransferPasswordRules.permitsLocal(String(repeating: "🔑", count: 11)))
    XCTAssertTrue(TransferPasswordRules.permitsLocal(String(repeating: "🔑", count: 12)))
    XCTAssertTrue(TransferPasswordRules.permitsLocal(String(repeating: "e\u{301}", count: 6)), "Rust counts Unicode scalars rather than graphemes")
    XCTAssertFalse(TransferPasswordRules.permitsLocal(String(repeating: "🔑", count: 1025)))
    XCTAssertEqual(TransferPasswordRules.importPassword(file: "  preserve these spaces  ", local: "", confirmation: "", reuse: true), "  preserve these spaces  ")
  }

  func testNativePreparationErrorsLeaveEmptyWalletRecoverableAndMessagesAreBounded() async throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: directory) }
    let original = try WalletRepository(directory: directory.appendingPathComponent("source"))
    _ = try await original.create(password: "disposable source password")
    let backup = try await original.exportRecovery(password: "disposable file password")
    let target = try WalletRepository(directory: directory.appendingPathComponent("target"))
    do {
      _ = try await target.prepareRestore(file: backup, filePassword: "disposable file password", password: "short")
      XCTFail("Native minimum must still be enforced")
    } catch { XCTAssertEqual(error as? WalletFailure, .core("password_minimum_12")) }
    do {
      _ = try await target.prepareRestore(file: backup, filePassword: "wrong file password", password: "disposable local password")
      XCTFail("Wrong file password accepted")
    } catch { XCTAssertEqual(error as? WalletFailure, .core("recovery_file_invalid")) }
    let state = try await target.state()
    XCTAssertFalse(state.configured)
    let preview = try await target.prepareRestore(file: backup, filePassword: "disposable file password", password: "disposable local password")
    XCTAssertFalse(preview.token.isEmpty, "Retry can recover without replacing the Wallet or backup")
    XCTAssertEqual(WalletFailure.core("password_minimum_12").errorDescription, "Use a password with at least 12 characters.")
    XCTAssertFalse(WalletFailure.core("unknown including sensitive input").errorDescription!.contains("sensitive input"))
  }
}
#endif
