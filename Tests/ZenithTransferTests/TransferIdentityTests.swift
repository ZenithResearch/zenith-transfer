#if os(macOS)
import Foundation
import XCTest
import AppKit
import SwiftUI
import ZenithKit
@testable import ZenithTransfer

final class TransferIdentityTests: XCTestCase {
  @MainActor func testNativeIdentityWorkspaceRendersWithSavedAccount() async throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    let suite = "IdentityRenderTests." + UUID().uuidString
    let defaults = UserDefaults(suiteName: suite)!
    defer { try? FileManager.default.removeItem(at: root); defaults.removePersistentDomain(forName: suite) }
    let model = TransferModel(directory: root, defaults: defaults)
    _ = try await XCTUnwrap(model.repository).create(password: "disposable rendering password")
    await model.refresh()
    let account = try IdentityAccount(walletPublicKey: XCTUnwrap(model.wallet?.publicKey), provider: .tailscale,
      label: "Personal Tailnet", identifier: "owner@example.org", server: "tail-example.ts.net")
    try model.saveIdentityAccount(account, replacing: nil)
    let view = NSHostingView(rootView: TransferWalletWorkspace(model: model).frame(width: 800, height: 1000)
      .background(Color(nsColor: .windowBackgroundColor)).environment(\.colorScheme, .light))
    let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 800, height: 1000),
      styleMask: .borderless, backing: .buffered, defer: false)
    window.contentView = view
    view.layoutSubtreeIfNeeded()
    RunLoop.main.run(until: Date(timeIntervalSinceNow: 0.1))
    let bitmap = try XCTUnwrap(view.bitmapImageRepForCachingDisplay(in: view.bounds))
    view.cacheDisplay(in: view.bounds, to: bitmap)
    XCTAssertGreaterThan(bitmap.pixelsWide, 0)
    if let output = ProcessInfo.processInfo.environment["TRANSFER_SCREENSHOT_PATH"] {
      try bitmap.representation(using: .png, properties: [:])?.write(to: URL(fileURLWithPath: output))
    }
    window.contentView = nil
  }
  @MainActor func testIdentityEditsRequireMatchingUnlockedWalletAndSurviveLockAndRestart() async throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    let defaults = UserDefaults(suiteName: "IdentityTests." + UUID().uuidString)!
    defer { try? FileManager.default.removeItem(at: root) }
    let model = TransferModel(directory: root, defaults: defaults)
    let repo = try XCTUnwrap(model.repository)
    _ = try await repo.create(password: "disposable account test password")
    await model.refresh()
    let owner = try XCTUnwrap(model.wallet?.publicKey)
    let account = try IdentityAccount(walletPublicKey: owner, provider: .tailscale, label: "Network", identifier: "member", server: "example.ts.net")
    try model.saveIdentityAccount(account, replacing: nil)
    let other = try IdentityAccount(walletPublicKey: String(repeating: "b", count: 64), provider: .tailscale, label: "Other Wallet", identifier: "other", server: "example.ts.net")
    XCTAssertThrowsError(try model.saveIdentityAccount(other, replacing: nil))
    model.lock()
    XCTAssertThrowsError(try model.saveIdentityAccount(nil, replacing: account))
    XCTAssertEqual(model.identityAccounts, [account], "Public records remain readable while locked")
    for _ in 0..<100 { if !model.locking { break }; try await Task.sleep(nanoseconds: 1_000_000) }
    let restarted = TransferModel(directory: root, defaults: defaults)
    await restarted.refresh()
    XCTAssertFalse(restarted.walletUnlocked)
    XCTAssertEqual(restarted.identityAccounts, [account])
    let state = try await repo.state()
    XCTAssertFalse(state.unlocked)
  }
  @MainActor func testLegacyApplicationRecordsRemainReadOnlyThroughModel() async throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    let suite = "LegacyIdentityTests." + UUID().uuidString
    let defaults = UserDefaults(suiteName: suite)!
    defer { try? FileManager.default.removeItem(at: root); defaults.removePersistentDomain(forName: suite) }
    let model = TransferModel(directory: root, defaults: defaults)
    _ = try await XCTUnwrap(model.repository).create(password: "synthetic legacy test password")
    await model.refresh()
    let owner = try XCTUnwrap(model.wallet?.publicKey)
    let legacy = try IdentityAccount(walletPublicKey: owner, provider: .matrix, label: "Legacy chat",
      identifier: "@member:example.test", server: "https://matrix.example.test")
    XCTAssertThrowsError(try model.saveIdentityAccount(legacy, replacing: nil))
    let registry = try IdentityAccountRegistry(directory: root.appendingPathComponent("Identities"))
    try registry.save(legacy, replacing: nil)
    try model.reloadIdentityAccounts()
    XCTAssertEqual(model.identityAccounts, [legacy])
    XCTAssertThrowsError(try model.saveIdentityAccount(nil, replacing: legacy))
    XCTAssertThrowsError(try model.saveIdentityAccount(legacy, replacing: legacy))
    XCTAssertEqual(try registry.load(wallet: owner), [legacy])
    if let output = ProcessInfo.processInfo.environment["TRANSFER_LEGACY_SCREENSHOT_PATH"] {
      let view = NSHostingView(rootView: NavigationStack { TransferIdentityAccountsView(model: model, showWallet: {}) }
        .frame(width: 860, height: 1000).background(Color.white).environment(\.colorScheme, .light))
      let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 860, height: 1000),
        styleMask: .borderless, backing: .buffered, defer: false)
      window.contentView = view; view.layoutSubtreeIfNeeded()
      RunLoop.main.run(until: Date(timeIntervalSinceNow: 0.1))
      let bitmap = try XCTUnwrap(view.bitmapImageRepForCachingDisplay(in: view.bounds))
      view.cacheDisplay(in: view.bounds, to: bitmap)
      try bitmap.representation(using: .png, properties: [:])?.write(to: URL(fileURLWithPath: output))
      window.contentView = nil
    }
  }

}
#endif
