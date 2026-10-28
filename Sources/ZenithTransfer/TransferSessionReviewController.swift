#if os(macOS)
import AppKit
import Combine
import SwiftUI
import ZenithKit

/// Narrow application port over the existing native consent API, not a new
/// signing protocol. There is no MCP argument for selecting its implementation.
protocol SessionReviewOwner: Sendable {
  func state() async throws -> WalletState
  func graphAccessIdentityV2() async throws -> Data
  func prepareOperatorAccess(_ challenge: Data, pin: ReadAuthorityPin, now: UInt64) async throws -> OperatorConsent
  func approveOperatorAccess(_ consent: OperatorConsent, now: UInt64) async throws -> Data
}
private struct NativeSessionReviewOwner: SessionReviewOwner {
  let session: any WalletSession
  func state() async throws -> WalletState { try await session.state() }
  func graphAccessIdentityV2() async throws -> Data { try await session.graphAccessIdentityV2() }
  func prepareOperatorAccess(_ challenge: Data, pin: ReadAuthorityPin, now: UInt64) async throws -> OperatorConsent {
    try await session.prepareOperatorAccess(challenge, pin: pin, now: now)
  }
  func approveOperatorAccess(_ consent: OperatorConsent, now: UInt64) async throws -> Data {
    try await session.approveOperatorAccess(consent, now: now)
  }
}

@MainActor final class TransferSessionReviewController: ObservableObject {
  static let enabledKey = "Transfer.sessionReview.localRequests.v1"
  @Published private(set) var enabled = false
  @Published private(set) var records: [String: SessionReviewRecord] = [:]
  @Published private(set) var active: String?
  @Published private(set) var consent: OperatorConsent?
  @Published private(set) var busy = false
  @Published private(set) var availableServices: [SessionReviewService] = []
  @Published private(set) var endedClients: Set<String> = []
  @Published var error: String?
  private weak var walletModel: TransferModel?
  private let provider: any SessionReviewProvider
  private let ownerOverride: (any SessionReviewOwner)?
  private let journal: SessionReviewJournal?
  private let defaults: UserDefaults
  private let socketDirectory: URL
  private let clock: () -> UInt64
  private let presentWindows: Bool
  private var socket: SessionReviewSocket?
  private var window: NSWindow?
  private var preparedOwner: String?
  private var preparing: Set<String> = []
  private var knownClients: Set<String> = []
  private var lifecycle: UInt64 = 0
  init(walletModel: TransferModel?, directory: URL?, defaults: UserDefaults = .standard,
    provider: (any SessionReviewProvider)? = nil,
    owner: (any SessionReviewOwner)? = nil,
    socketDirectory: URL = SessionReviewSocket.defaultDirectory,
    presentWindows: Bool = true,
    clock: @escaping () -> UInt64 = { UInt64(Date().timeIntervalSince1970) }) {
    self.walletModel = walletModel; self.defaults = defaults; ownerOverride = owner
    var registrationFailed = false
    if let provider { self.provider = provider }
    else {
      do {
        if let configured = try directory.flatMap({ try SessionProviderRegistration.loadIfPresent(directory: $0) }) {
          self.provider = configured
        } else { self.provider = UnavailableSessionReviewProvider() }
      } catch {
        self.provider = UnavailableSessionReviewProvider()
        registrationFailed = true
      }
    }
    self.socketDirectory = socketDirectory; self.clock = clock; self.presentWindows = presentWindows
    journal = try? directory.map(SessionReviewJournal.init(directory:))
    if registrationFailed { self.error = "The configured local session provider could not be verified. Its files have been preserved." }
    if let journal {
      do {
        for record in try journal.load() {
          let review = try record.preparation.checked(now: clock(), retained: true)
          guard records[review.requestHandle] == nil else { throw SessionReviewBridgeError.invalid }
          records[review.requestHandle] = record
        }
      } catch { records.removeAll(); self.error = "Saved session requests need attention. Their files have been preserved." }
    }
  }
  func resumeConfiguredBridge() {
    if defaults.bool(forKey: Self.enabledKey) { setEnabled(true) }
  }
  func refreshServices() async {
    do { availableServices = try await provider.services() }
    catch { availableServices = []; self.error = "Local session providers could not be verified. Existing requests are preserved." }
  }
  func setEnabled(_ value: Bool) {
    if !value {
      let closing = knownClients
      endedClients.formUnion(closing)
      lifecycle &+= 1; invalidatePreparedConsent()
      socket?.stop(); socket = nil; enabled = false; defaults.set(false, forKey: Self.enabledKey)
      Task {
        for client in closing {
          do { try await provider.closeClient(client); knownClients.remove(client) }
          catch { /* No key-destruction or revocation confirmation is claimed. */ }
        }
      }
      return
    }
    guard !enabled, journal != nil, error == nil else { return }
    do {
      let listener = SessionReviewSocket(directory: socketDirectory) { [weak self] client, method, params in
        guard let self else { throw SessionReviewBridgeError.unavailable }
        return try await self.exchange(client: client, method: method, params: params)
      }
      try listener.start(); lifecycle &+= 1; socket = listener; enabled = true; defaults.set(true, forKey: Self.enabledKey)
    } catch { self.error = "The local review channel could not start. Another Transfer instance may be using it." }
  }
  func stop() {
    lifecycle &+= 1
    socket?.stop(); socket = nil; enabled = false; consent = nil; preparedOwner = nil
    Task { await provider.shutdown() }
  }
  func invalidatePreparedConsent() { consent = nil; preparedOwner = nil }
  private var owner: (any SessionReviewOwner)? {
    if let ownerOverride { return ownerOverride }
    if let session = walletModel?.repository { return NativeSessionReviewOwner(session: session) }
    return nil
  }
  private func checkClient(_ client: String, epoch: UInt64) throws {
    guard enabled, lifecycle == epoch, !endedClients.contains(client) else { throw SessionAccessReviewError.changed }
  }
  private func checkReview(_ handle: String, record: SessionReviewRecord, epoch: UInt64, dispatched: Bool = false) throws {
    try checkClient(record.clientID, epoch: epoch)
    guard active == handle, records[handle]?.version == record.version,
      record.dispatched == dispatched, walletModel?.walletUnlocked == true else { throw SessionAccessReviewError.changed }
  }
  func review(_ handle: String) throws -> SessionAccessReview {
    guard let record = records[handle] else { throw SessionReviewBridgeError.invalid }
    return try record.preparation.checked(now: clock(), retained: true)
  }
  private func save(_ record: SessionReviewRecord, replacing previous: SessionReviewRecord?) throws {
    guard let journal else { throw SessionReviewBridgeError.unavailable }
    try journal.save(record, replacing: previous)
    let review = try record.preparation.checked(now: clock(), retained: true)
    records[review.requestHandle] = record
  }
  func exchange(client: String, method: String, params: Data) async throws -> Data {
    guard enabled, client.range(of: "\\A[0-9a-f]{32}\\z", options: .regularExpression) != nil else { throw SessionReviewBridgeError.unavailable }
    let raw = try SessionReviewWire.object(params)
    let epoch = lifecycle
    guard method == "close_client" || !endedClients.contains(client) else { throw SessionReviewBridgeError.unavailable }
    switch method {
    case "close_client":
      guard raw.isEmpty else { throw SessionReviewBridgeError.invalid }
      if records.values.contains(where: { $0.clientID == client }) || preparing.contains(where: { $0.hasPrefix(client + ":") }) {
        endedClients.insert(client)
      }
      if active.flatMap({ records[$0]?.clientID }) == client { invalidatePreparedConsent() }
      try await provider.closeClient(client)
      knownClients.remove(client)
      return try SessionReviewWire.encode(["schema":"zenith.session-client-closed.v1", "closed":true, "server_revocation_confirmed":false])
    case "list_services":
      guard raw.isEmpty else { throw SessionReviewBridgeError.invalid }
      let services = try await provider.services()
      try checkClient(client, epoch: epoch)
      guard services.count <= 64 else { throw SessionReviewBridgeError.invalid }
      return try SessionReviewWire.encode(["schema": "zenith.session-review-services.v1", "services":
        try services.map { try JSONSerialization.jsonObject(with: JSONEncoder().encode($0)) }])
    case "request_review":
      let required: Set<String> = ["service", "permissions", "session_label", "purpose", "request_id"]
      guard required.isSubset(of: Set(raw.keys)), Set(raw.keys).isSubset(of: required.union(["lifetime_seconds"])),
        let id = raw["request_id"] as? String, id.range(of: "\\A[0-9a-f]{32}\\z", options: .regularExpression) != nil,
        let requested = raw["permissions"] as? [[String: Any]], !requested.isEmpty, requested.count <= 64,
        ["service", "session_label", "purpose"].allSatisfy({ (raw[$0] as? String)?.isEmpty == false })
      else { throw SessionReviewBridgeError.invalid }
      let canonical = try SessionReviewWire.encode(raw)
      for (handle, existing) in records where existing.clientID == client {
        let old = try SessionReviewWire.object(existing.originalRequest)
        if old["request_id"] as? String == id {
          guard existing.originalRequest == canonical else { throw SessionAccessReviewError.changed }
          if existing.state == .awaitingHuman && !existing.dispatched { show(handle) }
          return try publicResult(handle)
        }
      }
      let correlation = client + ":" + id
      guard records.count < 64, knownClients.contains(client) || knownClients.count < 64,
        preparing.insert(correlation).inserted else { throw SessionReviewBridgeError.unavailable }
      knownClients.insert(client)
      defer { preparing.remove(correlation) }
      let value = try await provider.prepare(clientID: client, request: canonical)
      do { try checkClient(client, epoch: epoch) }
      catch { endedClients.insert(client); try? await provider.closeClient(client); throw error }
      let review = try value.checked(now: clock())
      guard review.requestID == id, review.service == raw["service"] as? String, records[review.requestHandle] == nil,
        let manifest = try SessionReviewWire.object(review.manifest)["permissions"],
        try SessionReviewWire.encode(manifest) == SessionReviewWire.encode(requested)
      else { throw SessionAccessReviewError.changed }
      try save(.init(clientID: client, originalRequest: canonical, preparation: value), replacing: nil)
      show(review.requestHandle)
      return try publicResult(review.requestHandle)
    case "get_result":
      guard Set(raw.keys) == ["request_handle"], let handle = raw["request_handle"] as? String,
        let record = records[handle], record.clientID == client else { throw SessionReviewBridgeError.unauthorized }
      if record.dispatched { try await reconcile(handle) }
      return try publicResult(handle)
    case "execute":
      guard Set(raw.keys) == ["credential_handle", "request_id", "operation", "resource", "parameters"],
        let handle = raw["credential_handle"] as? String, let id = raw["request_id"] as? String,
        id.range(of: "\\A[0-9a-f]{32}\\z", options: .regularExpression) != nil,
        let operation = raw["operation"] as? String, let resource = raw["resource"] as? String,
        let parameters = raw["parameters"] as? [String: Any] else { throw SessionReviewBridgeError.invalid }
      for record in records.values where record.clientID == client && record.state == .issued {
        let reviewed = try record.preparation.checked(now: clock(), retained: true)
        guard let retainedResult = record.result else { continue }
        let outcome = try SessionAccessOutcome.decode(retainedResult, review: reviewed, now: clock())
        guard outcome.credentialHandle == handle else { continue }
        let call = try SessionReviewWire.encode(["operation": operation, "resource": resource, "parameters": parameters])
        let result = try await provider.execute(record.preparation, credentialHandle: handle, requestID: id, call: call)
        try checkClient(client, epoch: epoch)
        let value = try SessionReviewWire.object(result)
        guard Set(value.keys) == ["schema", "request_id", "provider_service", "operation", "result"],
          value["schema"] as? String == "zenith.session-call-result.v1", value["request_id"] as? String == id,
          value["provider_service"] as? String == reviewed.service, value["operation"] as? String == operation else { throw SessionAccessReviewError.changed }
        return result
      }
      throw SessionReviewBridgeError.unauthorized
    default: throw SessionReviewBridgeError.invalid
    }
  }
  func publicResult(_ handle: String) throws -> Data {
    guard let record = records[handle] else { throw SessionReviewBridgeError.invalid }
    let review = try self.review(handle)
    if let result = record.result {
      if record.state == .issued && clock() >= review.expiresAt { return try SessionReviewWire.publicOutcome(review, state: .expired) }
      _ = try SessionAccessOutcome.decode(result, review: review, now: clock())
      return result
    }
    return try SessionReviewWire.publicOutcome(review, state: record.dispatched ? .outcomeUnknown : record.state)
  }
  func show(_ handle: String) {
    if active == nil || window?.isVisible != true { active = handle; consent = nil; preparedOwner = nil }
    guard presentWindows else { return }
    guard let walletModel else { return }
    if window == nil {
      let view = TransferSessionReviewView(controller: self, walletModel: walletModel)
      let panel = NSPanel(contentRect: NSRect(x: 0, y: 0, width: 760, height: 760),
        styleMask: [.titled, .closable, .resizable], backing: .buffered, defer: false)
      panel.title = "Zenith Wallet · Session access"; panel.isReleasedWhenClosed = false
      panel.contentView = NSHostingView(rootView: view); panel.minSize = NSSize(width: 640, height: 580)
      panel.center(); window = panel
    }
    window?.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps: true)
  }
  func dismiss() { window?.orderOut(nil); consent = nil; preparedOwner = nil; active = nil }
  func changeExpiry(_ expiry: UInt64) async {
    guard let handle = active, let before = records[handle], !before.dispatched, before.state == .awaitingHuman, !busy else { return }
    guard !endedClients.contains(before.clientID) else { return }
    busy = true; consent = nil; preparedOwner = nil; error = nil; defer { busy = false }
    let epoch = lifecycle
    do {
      let old = try review(handle), next = try await provider.updateExpiry(before.preparation, expiresAt: expiry)
      try checkClient(before.clientID, epoch: epoch)
      _ = try old.updatedExpiry(next.review, requestedExpiry: expiry, now: clock())
      guard records[handle]?.version == before.version, active == handle else { throw SessionAccessReviewError.changed }
      try save(before.replacing(next), replacing: before)
    } catch { self.error = "The updated review could not be verified. The original request is preserved." }
  }
  func prepareNativeReview() async {
    guard let handle = active, let before = records[handle], !before.dispatched, before.state == .awaitingHuman,
      !busy, let walletModel, walletModel.walletUnlocked, let repository = owner else { return }
    guard !endedClients.contains(before.clientID) else { return }
    busy = true; consent = nil; preparedOwner = nil; error = nil; defer { busy = false }
    let epoch = lifecycle
    do {
      let reviewed = try before.preparation.checked(now: clock())
      let state = try await repository.state()
      try checkReview(handle, record: before, epoch: epoch)
      guard state.unlocked, let owner = state.publicKey else { throw WalletFailure.locked }
      let identity = try await repository.graphAccessIdentityV2()
      try checkReview(handle, record: before, epoch: epoch)
      let challenge = try await provider.ownerChallenge(before.preparation, ownerIdentity: identity)
      try checkReview(handle, record: before, epoch: epoch)
      let native = try await repository.prepareOperatorAccess(challenge, pin: before.preparation.authority, now: clock())
      try checkReview(handle, record: before, epoch: epoch)
      let details = try SessionReviewWire.object(native.details)
      guard let binding = details["session_review"] as? [String: Any], Set(binding.keys) == ["manifest", "review_digest_sha256"],
        binding["review_digest_sha256"] as? String == reviewed.digest, let manifest = binding["manifest"],
        try SessionReviewWire.encode(manifest) == reviewed.manifest,
        native.operation == "access.decide", native.issuer == before.preparation.authority.issuer,
        native.receiver == before.preparation.authority.receiver,
        clock() < min(UInt64(native.expiresAt.timeIntervalSince1970), reviewed.reviewDeadline),
        records[handle]?.version == before.version, active == handle else { throw SessionAccessReviewError.changed }
      consent = native; preparedOwner = owner
    } catch { self.error = "Wallet could not verify this exact session approval. No credential was issued." }
  }
  /// Native UI only. Neither the Unix socket nor MCP exports this method.
  func approveNativeReview(reviewedDigest: String, reviewedExpiry: UInt64) async {
    guard let handle = active, var record = records[handle], let consent, !record.dispatched,
      record.state == .awaitingHuman, !busy, let walletModel, walletModel.walletUnlocked,
      let repository = owner, let expectedOwner = preparedOwner else { return }
    guard !endedClients.contains(record.clientID) else { return }
    busy = true; error = nil; defer { busy = false; self.consent = nil; preparedOwner = nil }
    let epoch = lifecycle
    do {
      let reviewed = try record.preparation.checked(now: clock())
      guard reviewed.digest == reviewedDigest, reviewed.expiresAt == reviewedExpiry,
        clock() < UInt64(consent.expiresAt.timeIntervalSince1970) else { throw SessionAccessReviewError.changed }
      let state = try await repository.state()
      try checkReview(handle, record: record, epoch: epoch)
      guard state.unlocked, state.publicKey == expectedOwner else { throw WalletFailure.conflict }
      let previous = record
      record.dispatched = true; record.state = .submitting; record.version += 1
      try save(record, replacing: previous) // durable before signing or dispatch
      let proof = try await repository.approveOperatorAccess(consent, now: clock())
      try checkReview(handle, record: record, epoch: epoch, dispatched: true)
      let result = try await provider.submit(record.preparation, ownerProof: proof)
      try checkReview(handle, record: record, epoch: epoch, dispatched: true)
      try acceptResult(result, handle: handle)
    } catch {
      if let saved = records[handle], saved.dispatched {
        var uncertain = saved; uncertain.version += 1; uncertain.state = .outcomeUnknown; uncertain.result = nil
        try? save(uncertain, replacing: saved)
        self.error = "The original result is not confirmed. Check its status; do not submit a second approval."
      } else { self.error = "The approval could not be saved safely. Nothing was submitted." }
    }
  }
  private func acceptResult(_ data: Data, handle: String) throws {
    guard let previous = records[handle], previous.dispatched else { throw SessionAccessReviewError.changed }
    let review = try self.review(handle), value = try SessionAccessOutcome.decode(data, review: review, now: clock())
    var flow = SessionAccessReviewFlow(review: review)
    // Reconstruct the dispatch fence without re-sending anything.
    try flow.markSubmitting(now: review.notBefore)
    if previous.state == .issued, let prior = previous.result { try flow.accept(prior, now: min(clock(), review.expiresAt - 1)) }
    else if [.denied, .cancelled, .expired, .revoked].contains(previous.state) {
      guard value.state == previous.state else { throw SessionAccessReviewError.changed }
    }
    try flow.accept(data, now: clock())
    var record = previous; record.version += 1; record.state = value.state; record.result = data
    try save(record, replacing: previous)
  }
  func reconcile(_ handle: String) async throws {
    guard let record = records[handle], record.dispatched else { throw SessionAccessReviewError.changed }
    let epoch = lifecycle
    try checkClient(record.clientID, epoch: epoch)
    let result = try await provider.reconcile(record.preparation)
    try checkClient(record.clientID, epoch: epoch)
    guard records[handle]?.version == record.version else { throw SessionAccessReviewError.changed }
    try acceptResult(result, handle: handle)
  }
  func checkActiveResult() async {
    guard let handle = active, !busy else { return }
    busy = true; error = nil; defer { busy = false }
    do { try await reconcile(handle) }
    catch { self.error = "The original result could not be confirmed. Its saved request is preserved." }
  }
  func declineNativeReview() {
    guard let handle = active, let previous = records[handle], !previous.dispatched, !busy else { return }
    do {
      var record = previous; record.version += 1; record.state = .denied
      record.result = try SessionReviewWire.publicOutcome(review(handle), state: .denied)
      try save(record, replacing: previous); consent = nil; preparedOwner = nil
    } catch { self.error = "The local decline could not be saved. The request is preserved." }
  }
}
#endif
