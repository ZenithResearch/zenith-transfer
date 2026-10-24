#if os(macOS)
import AppKit
import SwiftUI
import XCTest
import ZenithKit
@testable import ZenithTransfer

final class TransferWalletSheetTests: XCTestCase {
  @MainActor func testFailedUnlockStaysLockedAndUsesInlineClosedMessage() async throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    let suite = "WalletSheetFailure." + UUID().uuidString
    let defaults = UserDefaults(suiteName: suite)!
    defer { try? FileManager.default.removeItem(at: root); defaults.removePersistentDomain(forName: suite) }
    let model = TransferModel(directory: root, defaults: defaults)
    let repository = try XCTUnwrap(model.repository)
    _ = try await repository.create(password: "synthetic correct unlock password")
    await repository.lock(); await model.refresh()
    var message: String?
    var succeeded = false
    let finished = expectation(description: "Inline unlock failure")
    model.perform(onFailure: { message = $0; finished.fulfill() }, {
      try await $0.unlock(password: "synthetic wrong unlock password")
    }, success: { _ in succeeded = true; finished.fulfill() })
    await fulfillment(of: [finished], timeout: 5)
    XCTAssertFalse(succeeded)
    XCTAssertFalse(model.walletUnlocked)
    XCTAssertNotNil(message)
    XCTAssertEqual(message, WalletFailure.core("unlock_failed").errorDescription)
    XCTAssertNil(model.error, "The parent alert must not consume or hide the sheet's error")
    XCTAssertFalse(message?.contains("synthetic") == true)
  }

  @MainActor func testSuccessfulUnlockReturnsAfterStateIsUpdated() async throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    let suite = "WalletSheetSuccess." + UUID().uuidString
    let defaults = UserDefaults(suiteName: suite)!
    defer { try? FileManager.default.removeItem(at: root); defaults.removePersistentDomain(forName: suite) }
    let model = TransferModel(directory: root, defaults: defaults)
    let repository = try XCTUnwrap(model.repository)
    let original = try await repository.create(password: "synthetic correct unlock password")
    await repository.lock(); await model.refresh()
    var message: String?
    var returned = false
    let finished = expectation(description: "Successful unlock return")
    model.perform(onFailure: { message = $0; finished.fulfill() }, {
      try await $0.unlock(password: "synthetic correct unlock password")
    }, success: { state in
      XCTAssertTrue(state.unlocked)
      XCTAssertTrue(model.walletUnlocked, "The caller must see the unlocked state before dismissal")
      XCTAssertEqual(model.wallet?.publicKey, original.publicKey)
      returned = true; finished.fulfill()
    })
    await fulfillment(of: [finished], timeout: 5)
    XCTAssertTrue(returned); XCTAssertNil(message); XCTAssertNil(model.error)
  }

  @MainActor func testWalletSheetHasVisibleEscapeDismissalWhileLocked() async throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    let suite = "WalletSheetEscape." + UUID().uuidString
    let defaults = UserDefaults(suiteName: suite)!
    defer { try? FileManager.default.removeItem(at: root); defaults.removePersistentDomain(forName: suite) }
    let model = TransferModel(directory: root, defaults: defaults)
    let repository = try XCTUnwrap(model.repository)
    _ = try await repository.create(password: "synthetic sheet escape password")
    await repository.lock(); await model.refresh()
    _ = NSApplication.shared
    let presentation = SheetPresentation()
    let host = NSHostingView(rootView: SheetHarness(model: model, presentation: presentation))
    let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 800, height: 760),
      styleMask: [.titled, .closable], backing: .buffered, defer: false)
    window.contentView = host
    window.makeKeyAndOrderFront(nil)
    defer { window.orderOut(nil); window.contentView = nil }
    let deadline = Date().addingTimeInterval(3)
    while window.attachedSheet == nil && Date() < deadline { try await Task.sleep(nanoseconds: 20_000_000) }
    let sheet = try XCTUnwrap(window.attachedSheet)
    XCTAssertTrue(presentation.presented)
    XCTAssertFalse(model.walletUnlocked)
    if let output = ProcessInfo.processInfo.environment["TRANSFER_WALLET_SHEET_SCREENSHOT_PATH"] {
      // Capture the real view with an explicit background; compositing an entire
      // native sheet through cacheDisplay omits some SwiftUI-rendered layers.
      let rendering = NSHostingView(rootView: TransferWalletSheet(model: model)
        .background(Color(nsColor: .windowBackgroundColor)).environment(\.colorScheme, .light))
      rendering.frame = NSRect(x: 0, y: 0, width: 640, height: 640)
      let preview = NSWindow(contentRect: rendering.frame, styleMask: .borderless, backing: .buffered, defer: false)
      preview.contentView = rendering; rendering.layoutSubtreeIfNeeded()
      try await Task.sleep(nanoseconds: 100_000_000)
      let bitmap = try XCTUnwrap(rendering.bitmapImageRepForCachingDisplay(in: rendering.bounds))
      rendering.cacheDisplay(in: rendering.bounds, to: bitmap)
      try bitmap.representation(using: .png, properties: [:])?.write(to: URL(fileURLWithPath: output))
      preview.contentView = nil
    }
    let escape = try XCTUnwrap(NSEvent.keyEvent(with: .keyDown, location: .zero, modifierFlags: [], timestamp: 0,
      windowNumber: sheet.windowNumber, context: nil, characters: "\u{1b}", charactersIgnoringModifiers: "\u{1b}", isARepeat: false, keyCode: 53))
    _ = sheet.performKeyEquivalent(with: escape)
    let closing = Date().addingTimeInterval(2)
    while presentation.presented && Date() < closing { try await Task.sleep(nanoseconds: 20_000_000) }
    XCTAssertFalse(presentation.presented, "Escape must return to the caller without a password")
    XCTAssertFalse(model.walletUnlocked)
    let state = try await repository.state()
    XCTAssertFalse(state.unlocked)
  }
  @MainActor func testEscapeWhileUnlockIsPendingCancelsItWithoutUnlocking() async throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    let suite = "WalletSheetPending." + UUID().uuidString
    let defaults = UserDefaults(suiteName: suite)!
    defer { try? FileManager.default.removeItem(at: root); defaults.removePersistentDomain(forName: suite) }
    let model = TransferModel(directory: root, defaults: defaults)
    let repository = try XCTUnwrap(model.repository)
    _ = try await repository.create(password: "synthetic pending unlock password")
    await repository.lock(); await model.refresh()
    _ = NSApplication.shared
    let presentation = SheetPresentation()
    let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 800, height: 760),
      styleMask: [.titled, .closable], backing: .buffered, defer: false)
    window.contentView = NSHostingView(rootView: SheetHarness(model: model, presentation: presentation))
    window.makeKeyAndOrderFront(nil)
    defer { window.orderOut(nil); window.contentView = nil }
    let opening = Date().addingTimeInterval(3)
    while window.attachedSheet == nil && Date() < opening { try await Task.sleep(nanoseconds: 20_000_000) }
    let sheet = try XCTUnwrap(window.attachedSheet)
    let ticket = repository.lifecycleTicket()
    let gate = UnlockGate()
    let finished = expectation(description: "Pending unlock rejected after dismissal")
    var succeeded = false
    var failure: String?
    model.perform(onFailure: { failure = $0; finished.fulfill() }, { repository in
      await gate.wait()
      return try await repository.unlock(password: "synthetic pending unlock password", expectedLifecycle: ticket)
    }, success: { _ in succeeded = true; finished.fulfill() })
    XCTAssertTrue(model.busy)
    try await Task.sleep(nanoseconds: 50_000_000)
    let escape = try XCTUnwrap(NSEvent.keyEvent(with: .keyDown, location: .zero, modifierFlags: [], timestamp: 0,
      windowNumber: sheet.windowNumber, context: nil, characters: "\u{1b}", charactersIgnoringModifiers: "\u{1b}", isARepeat: false, keyCode: 53))
    _ = sheet.performKeyEquivalent(with: escape)
    let closing = Date().addingTimeInterval(3)
    while (presentation.presented || window.attachedSheet != nil) && Date() < closing { try await Task.sleep(nanoseconds: 20_000_000) }
    XCTAssertFalse(presentation.presented, "The Close/Escape action must remain available while busy")
    XCTAssertThrowsError(try repository.checkLifecycle(ticket), "Leaving the sheet must invalidate the pending attempt")
    await gate.open()
    await fulfillment(of: [finished], timeout: 5)
    XCTAssertFalse(succeeded); XCTAssertNotNil(failure); XCTAssertNil(model.error)
    XCTAssertFalse(model.walletUnlocked)
    let state = try await repository.state(); XCTAssertFalse(state.unlocked)
  }

}
@MainActor private final class SheetPresentation: ObservableObject {
  @Published var presented = true
}
private struct SheetHarness: View {
  @ObservedObject var model: TransferModel
  @ObservedObject var presentation: SheetPresentation
  var body: some View {
    Text("Synthetic Wallet sheet test").frame(width: 800, height: 760)
      .sheet(isPresented: $presentation.presented) { TransferWalletSheet(model: model) }
  }
}
#endif

#if os(macOS)
private actor UnlockGate {
  private var opened = false
  private var waiting: CheckedContinuation<Void, Never>?
  func wait() async {
    if opened { return }
    await withCheckedContinuation { waiting = $0 }
  }
  func open() { opened = true; waiting?.resume(); waiting = nil }
}
#endif
