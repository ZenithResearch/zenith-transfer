#if os(macOS)
import AppKit
import Security
import SwiftUI
import XCTest
@testable import ZenithKit
@testable import ZenithTransfer

final class TransferTailscaleTokenViewsTests: XCTestCase {
  @MainActor func testSettingsAndGeneratorRenderMetadataWithoutReadingOrWritingSecrets() async throws {
    let profile = TailscaleAPITokenProfile(id: UUID(), name: "Personal network", tailnet: "-", updated: Date(timeIntervalSince1970: 1_800_000_000))
    let metadata = try JSONEncoder().encode(profile)
    var reads = 0, writes = 0
    let store = TailscaleAPITokenStore(operations: .init(copy: { query in
      reads += 1
      XCTAssertNil(query[kSecReturnData as String], "A rendered view must not read a token")
      return (errSecSuccess, [[kSecAttrAccount as String: profile.id.uuidString, kSecAttrGeneric as String: metadata]])
    }, add: { _ in writes += 1; return errSecAuthFailed }, update: { _, _ in writes += 1; return errSecAuthFailed }, delete: { _ in writes += 1; return errSecAuthFailed }))
    _ = NSApplication.shared
    for (name, root) in [("tokens", AnyView(TransferTailscaleAPITokensView(store: store))), ("generator", AnyView(TransferTailscaleKeyGeneratorView(tokenStore: store)))] {
      let view = NSHostingView(rootView: root.preferredColorScheme(.light).background(Color.white))
      let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 700, height: 800), styleMask: [.titled, .closable], backing: .buffered, defer: false)
      window.contentView = view; window.makeKeyAndOrderFront(nil)
      try await Task.sleep(nanoseconds: 100_000_000)
      view.layoutSubtreeIfNeeded()
      if let directory = ProcessInfo.processInfo.environment["TRANSFER_TOKEN_SCREENSHOTS"], let bitmap = view.bitmapImageRepForCachingDisplay(in: view.bounds) {
        view.cacheDisplay(in: view.bounds, to: bitmap)
        try bitmap.representation(using: .png, properties: [:])?.write(to: URL(fileURLWithPath: directory).appendingPathComponent(name + ".png"))
      }
      window.orderOut(nil); window.contentView = nil
    }
    XCTAssertGreaterThanOrEqual(reads, 2)
    XCTAssertEqual(writes, 0, "Opening settings or the generator creates no Keychain record or credential")
  }
}
#endif
