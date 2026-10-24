#if os(macOS)
import AppKit
import SwiftUI
import XCTest
import ZenithKit
@testable import ZenithTransfer

final class TransferNetworkSettingsTests: XCTestCase {
  @MainActor func testNewUserCanOpenNetworkSetupWhileWalletIsUnconfigured() async throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    let suite = "NetworkSetupPreview." + UUID().uuidString
    let defaults = UserDefaults(suiteName: suite)!
    defer { try? FileManager.default.removeItem(at: directory); defaults.removePersistentDomain(forName: suite) }
    let model = TransferModel(directory: directory, defaults: defaults)
    await model.refresh()
    XCTAssertFalse(model.walletUnlocked)
    XCTAssertEqual(model.wallet?.configured, false)
    _ = NSApplication.shared
    let content = NSHostingView(rootView: TransferNetworkSettingsView(model: model, openResources: {}, applicationDirectory: directory, automaticallyDiscover: false).preferredColorScheme(.light).background(Color.white))
    let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 920, height: 1100), styleMask: [.titled, .closable], backing: .buffered, defer: false)
    window.contentView = content; window.makeKeyAndOrderFront(nil)
    defer { window.orderOut(nil); window.contentView = nil }
    try await Task.sleep(nanoseconds: 100_000_000)
    content.layoutSubtreeIfNeeded()
    if let path = ProcessInfo.processInfo.environment["TRANSFER_NETWORK_SCREENSHOT"], let bitmap = content.bitmapImageRepForCachingDisplay(in: content.bounds) {
      content.cacheDisplay(in: content.bounds, to: bitmap)
      try bitmap.representation(using: .png, properties: [:])?.write(to: URL(fileURLWithPath: path))
    }
    XCTAssertTrue(model.resources.isEmpty)
    XCTAssertFalse(model.walletUnlocked)
    XCTAssertFalse(FileManager.default.fileExists(atPath: directory.appendingPathComponent("ConnectionFiles").path), "A preview does not save files or apply settings")
  }
}
#endif
