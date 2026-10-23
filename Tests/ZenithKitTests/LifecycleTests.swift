import XCTest

@testable import ZenithKit

final class LifecycleTests: XCTestCase {
  func testInvalidationRejectsOldTicketButAdmitsNewWork() throws {
    let gate = LifecycleGate()
    let old = gate.ticket()
    gate.invalidate()
    XCTAssertThrowsError(try gate.withCurrent(old) { XCTFail("stale write") })
    XCTAssertEqual(try gate.withCurrent(gate.ticket()) { 42 }, 42)
  }
  func testCancelledRestoreCannotCommitAfterUnlockCycle() async throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: directory) }
    let source = try WalletRepository(directory: directory.appendingPathComponent("source"))
    _ = try await source.create(password: "local password 123")
    let backup = try await source.exportRecovery(password: "backup password 123")
    let target = try WalletRepository(directory: directory.appendingPathComponent("target"))
    let preview = try await target.prepareRestore(
      file: backup, filePassword: "backup password 123", password: "target password 123")
    target.invalidatePendingWork()
    do {
      _ = try await target.commit(preview)
      XCTFail("cancelled preview committed")
    } catch {}
    let state = try await target.state()
    XCTAssertFalse(state.configured)
  }
}
