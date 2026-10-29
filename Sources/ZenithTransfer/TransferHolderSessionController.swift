#if os(macOS)
import AppKit
import Combine
import SwiftUI
import ZenithKit

@MainActor protocol HolderSessionReviewRouting: AnyObject {
  func services() async throws -> [SessionReviewService]
  func owns(client: String, method: String, params: [String: Any]) -> Bool
  func ownsOriginalRequest(client: String, params: [String: Any]) throws -> Bool
  func exchange(client: String, method: String, params: Data) async throws -> Data
  func close(client: String) async
  func stop() async
}

/// Native member signer routing. MCP may request/show/check/call/close, never
/// select provider files, approve, sign, change the native selection or renew.
@MainActor final class TransferHolderSessionController: ObservableObject, HolderSessionReviewRouting {
  private struct Request {
    let client: String, id: String, original: Data, model: HolderSessionReviewModel
  }
  private weak var wallet: TransferModel?
  private let directory: URL
  private let registration: HolderSessionRegistration
  private var requests: [String: Request] = [:]
  private var issuedHandles: [String: String] = [:]
  private var windows: [String: NSWindow] = [:]
  private var ended: Set<String> = []
  private var preparing: Set<String> = []
  private let openSettings: () -> Void
  init(wallet: TransferModel, directory: URL, registration: HolderSessionRegistration, openSettings: @escaping () -> Void) {
    self.wallet = wallet; self.directory = directory; self.registration = registration; self.openSettings = openSettings
  }
  var service: String { registration.provider.service }
  func services() async throws -> [SessionReviewService] { try await registration.services() }
  func owns(client: String, method: String, params: [String: Any]) -> Bool {
    if method == "request_review" { return params["service"] as? String == service }
    if method == "get_result", let h = params["request_handle"] as? String { return requests[h] != nil }
    if method == "execute", let h = params["credential_handle"] as? String { return issuedHandles[h] != nil || requests.values.contains { $0.client == client && $0.model.credentialHandle == h } }
    return false
  }
  func ownsOriginalRequest(client: String, params: [String: Any]) throws -> Bool {
    guard let id = params["request_id"] as? String,
      let original = requests.values.first(where: { $0.client == client && $0.id == id }) else { return false }
    guard try SessionReviewWire.encode(params) == original.original else { throw SessionAccessReviewError.changed }
    return true
  }
  func exchange(client: String, method: String, params: Data) async throws -> Data {
    guard !ended.contains(client) else { throw SessionReviewBridgeError.unauthorized }
    let value = try SessionReviewWire.object(params)
    switch method {
    case "request_review":
      let required: Set<String> = ["service", "permissions", "session_label", "purpose", "request_id"]
      guard required.isSubset(of: Set(value.keys)), Set(value.keys).isSubset(of: required.union(["lifetime_seconds"])),
        value["service"] as? String == service, let id = value["request_id"] as? String,
        id.range(of: "\\A[0-9a-f]{32}\\z", options: .regularExpression) != nil,
        let permissions = value["permissions"] as? [[String: Any]], (1...64).contains(permissions.count),
        let label = value["session_label"] as? String, let purpose = value["purpose"] as? String,
        let repository = wallet?.repository else { throw SessionReviewBridgeError.invalid }
      let original = try SessionReviewWire.encode(value)
      if let (handle, existing) = requests.first(where: { $0.value.client == client && $0.value.id == id }) {
        guard original == existing.original else { throw SessionAccessReviewError.changed }; show(handle); return try result(handle)
      }
      let correlation = client + ":" + id
      guard preparing.insert(correlation).inserted else { throw SessionReviewBridgeError.unavailable }
      defer { preparing.remove(correlation) }
      guard requests.count < 64 else { throw SessionReviewBridgeError.unavailable }
      let services = try await registration.services()
      guard !ended.contains(client), services.contains(where: { $0.service == service && $0.read_available }) else { throw SessionReviewBridgeError.unavailable }
      let reg = registration, dir = directory.appendingPathComponent("HolderSessions", isDirectory: true).appendingPathComponent(UUID().uuidString, isDirectory: true)
      let lifetime = value["lifetime_seconds"] as? UInt64 ?? 300
      guard lifetime > 0, lifetime <= 3600 else { throw SessionReviewBridgeError.invalid }
      let model = try HolderSessionReviewModel(service: service, label: label, purpose: purpose, maximumLifetime: reg.maximumLifetime(),
        proposedLifetime: lifetime, initialPermissions: SessionReviewWire.encode(permissions)) {
          try reg.flow(client: client, wallet: repository, directory: dir)
        }
      let handle = "holder-" + UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
      requests[handle] = Request(client: client, id: id, original: original, model: model); show(handle)
      return try result(handle)
    case "get_result":
      guard Set(value.keys) == ["request_handle"], let h = value["request_handle"] as? String, let r = requests[h], r.client == client else { throw SessionReviewBridgeError.unauthorized }
      if [.outcomeUnknown, .dispatched, .issued].contains(r.model.phase) { await r.model.checkOriginalResult() }
      return try result(h)
    case "execute":
      guard Set(value.keys) == ["credential_handle", "request_id", "operation", "resource", "parameters"],
        let handle = value["credential_handle"] as? String, let id = value["request_id"] as? String,
        id.range(of: "\\A[0-9a-f]{32}\\z", options: .regularExpression) != nil,
        let operation = value["operation"] as? String, let resource = value["resource"] as? String, let parameters = value["parameters"] as? [String: Any],
        let outer = issuedHandles[handle], let r = requests[outer], r.client == client else { throw SessionReviewBridgeError.unauthorized }
      let call = try SessionReviewWire.encode(["operation": operation, "resource": resource, "parameters": parameters])
      let business = try await r.model.execute(client: client, handle: handle, call: call)
      return try SessionReviewWire.encode(["schema": "zenith.session-call-result.v1", "request_id": id, "provider_service": service, "operation": operation,
        "result": SessionReviewWire.object(business)])
    default: throw SessionReviewBridgeError.invalid
    }
  }
  func close(client: String) async {
    ended.insert(client)
    for (h, request) in requests where request.client == client { await request.model.close(); windows[h]?.orderOut(nil) }
  }
  func stop() async { for c in Set(requests.values.map(\.client)) { await close(client: c) } }
  private func result(_ handle: String) throws -> Data {
    guard let r = requests[handle] else { throw SessionReviewBridgeError.invalid }
    let c = r.model.challenge, phase = r.model.phase
    if let credential = r.model.credentialHandle { issuedHandles[credential] = handle }
    let state: String
    switch phase { case .idle, .preparing, .awaitingHuman: state = "awaiting_human"; case .dispatched: state = "submitting"; case .outcomeUnknown: state = "outcome_unknown"; case .closed: state = "cancelled"; default: state = phase.rawValue }
    // v2 permits absent key/digest while the human is unlocking/preparing. No
    // fake key, challenge, token or model-driven root approval is synthesized.
    return try SessionReviewWire.encode(["schema": "zenith.session-access-result.v2", "request_handle": handle,
      "request_id": r.id, "review_digest_sha256": c?.digest as Any? ?? NSNull(), "provider_service": service,
      "holder_public_key": c?.intent.session.publicKey as Any? ?? NSNull(), "state": state,
      "credential_handle": phase == .issued ? (r.model.credentialHandle as Any? ?? NSNull()) : NSNull(),
      "expires_at": phase == .issued ? (c?.expiresAt as Any? ?? NSNull()) : NSNull(), "reconcile_required": phase == .outcomeUnknown])
  }
  private func show(_ handle: String) {
    guard let r = requests[handle], let wallet else { return }
    if windows[handle] == nil {
      let window = NSPanel(contentRect: NSRect(x: 0, y: 0, width: 760, height: 760), styleMask: [.titled, .closable, .resizable], backing: .buffered, defer: false)
      window.title = "Zenith Wallet · Session signer"; window.isReleasedWhenClosed = false
      window.contentView = NSHostingView(rootView: TransferHolderSessionView(model: r.model, wallet: wallet, openSettings: openSettings)); window.center(); windows[handle] = window
    }
    windows[handle]?.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps: true)
  }
}
private struct TransferHolderSessionView: View {
  @ObservedObject var model: HolderSessionReviewModel
  @ObservedObject var wallet: TransferModel
  let openSettings: () -> Void
  @State private var unlocking = false
  var body: some View {
    VStack {
      HolderSessionReviewView(model: model, unlocked: wallet.walletUnlocked) { unlocking = true }
      Button("Session request settings", action: openSettings).padding(.bottom)
    }
      .sheet(isPresented: $unlocking) { TransferWalletSheet(model: wallet) }
      .walletUserActivity { wallet.userActivity() }
  }
}
#endif
