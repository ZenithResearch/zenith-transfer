import Foundation

// Source-level typed ports; these do not introduce another signed/wire format.
// The concrete broker adapter must decode its own frozen producer contract.
public enum HolderSessionExchangeResult: Sendable {
  case issued(Data), unknown, denied, revoked, expired
}
public protocol HolderSessionIssuer: Sendable {
  func shutdown() async
  func prepare(_ body: HolderSessionPrivatePayload) async throws -> Data
  func exchange(_ authorization: HolderSessionPrivatePayload, challenge: HolderSessionChallenge) async throws -> HolderSessionExchangeResult
  func status(_ proof: Data, challenge: HolderSessionChallenge) async throws -> HolderSessionExchangeResult
  func execute(_ presentation: Data) async throws -> Data
}
public extension HolderSessionIssuer { func shutdown() async {} }
public protocol HolderSessionCustody: Sendable {
  func create(expiresAt: UInt64, now: UInt64) async throws -> HolderSessionIdentity
  func possession(_ challenge: HolderSessionChallenge, now: UInt64) async throws -> String
  func install(_ credential: HolderSessionCredential, now: UInt64) async throws
  func present(_ credential: HolderSessionCredential, call: Data, now: UInt64) async throws -> Data
  func status(_ challenge: HolderSessionChallenge, now: UInt64) async throws -> Data
  func stop() async
}

public protocol HolderSessionWalletPort: Sendable {
  func parent(service: String, now: UInt64) async throws -> HolderSessionParentReference
  func prepare(_ intent: HolderSessionPrepareIntent, now: UInt64) async throws -> HolderSessionPrivatePayload
  func review(_ challenge: HolderSessionChallenge, now: UInt64) async throws -> HolderSessionAuthorizationReview
  func approve(_ review: HolderSessionAuthorizationReview, signature: String, now: UInt64) async throws -> HolderSessionPrivatePayload
}
public struct NativeHolderSessionWalletPort: HolderSessionWalletPort {
  let wallet: any WalletSession
  public init(wallet: any WalletSession) { self.wallet = wallet }
  public func parent(service: String, now: UInt64) async throws -> HolderSessionParentReference {
    try await wallet.holderSessionParentReference(service: service, now: now)
  }
  public func prepare(_ intent: HolderSessionPrepareIntent, now: UInt64) async throws -> HolderSessionPrivatePayload {
    try await wallet.buildHolderSessionPrepare(intent, now: now)
  }
  public func review(_ challenge: HolderSessionChallenge, now: UInt64) async throws -> HolderSessionAuthorizationReview {
    try await wallet.prepareHolderSessionAuthorization(challenge, now: now)
  }
  public func approve(_ review: HolderSessionAuthorizationReview, signature: String, now: UInt64) async throws -> HolderSessionPrivatePayload {
    try await wallet.approveHolderSessionAuthorization(review, sessionSignature: signature, now: now)
  }
}

public enum HolderSessionPhase: String, Codable, Sendable {
  case idle, preparing, awaitingHuman, dispatched, outcomeUnknown, issued, denied, revoked, expired, closed
}

/// Root-free application audit record. A journal cannot restore a lost key.
public struct HolderSessionFlowRecord: Codable, Sendable {
  let schema: String
  let clientID: String, requestID: String, requestHandle: String, service: String
  let challenge: Data
  var phase: HolderSessionPhase
  var version: UInt64
  var dispatched: Bool
  var credentialHandle: String?
}
public protocol HolderSessionRecordStore: Sendable {
  /// Must durably compare-and-swap before returning. No default memory store.
  func save(_ record: HolderSessionFlowRecord, replacing: HolderSessionFlowRecord?) throws
}

/// One request owned by one broker-authenticated local client. Only the native
/// UI calls review/approve. This object is never selected by model arguments.
public actor HolderSessionFlow {
  let clientID: String, requestID: String, requestHandle: String, service: String
  private let context: HolderSessionContext
  private let wallet: any HolderSessionWalletPort
  private let custody: any HolderSessionCustody
  private let issuer: any HolderSessionIssuer
  private let journal: any HolderSessionRecordStore
  private let clock: @Sendable () -> UInt64
  private var phase: HolderSessionPhase = .idle
  private var challenge: HolderSessionChallenge?
  private var consent: HolderSessionAuthorizationReview?
  private var credential: HolderSessionCredential?
  private var record: HolderSessionFlowRecord?
  private var epoch: UInt64 = 0
  private var busy = false

  public init(clientID: String, requestID: String, service: String, context: HolderSessionContext,
    wallet: any HolderSessionWalletPort, custody: any HolderSessionCustody, issuer: any HolderSessionIssuer,
    journal: any HolderSessionRecordStore, clock: @escaping @Sendable () -> UInt64 = { UInt64(Date().timeIntervalSince1970) }) throws {
    _ = try HS.hex(clientID, 32); _ = try HS.hex(requestID, 32); try HS.text(service)
    self.clientID = clientID; self.requestID = requestID; self.service = service; self.context = context
    self.wallet = wallet; self.custody = custody; self.issuer = issuer; self.journal = journal; self.clock = clock
    requestHandle = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
  }
  public func currentPhase() -> HolderSessionPhase { phase }
  public func reviewedChallenge() -> HolderSessionChallenge? { challenge }
  public func publicCredentialHandle() -> String? { phase == .issued ? record?.credentialHandle : nil }

  public func prepare(permissions: Data?, lifetime: UInt64, maximumSessionSeconds: UInt64) async throws -> HolderSessionChallenge {
    guard !busy, phase == .idle, lifetime > 0, lifetime <= 3600,
      maximumSessionSeconds > 0, maximumSessionSeconds <= 3600 else { throw HolderSessionError.changed }
    busy = true; phase = .preparing; let ticket = epoch
    defer { busy = false }
    do {
      let parent = try await wallet.parent(service: service, now: clock())
      try current(ticket)
      guard parent.pin.service == service else { throw HolderSessionError.changed }
      let now = clock(), duration = min(lifetime, maximumSessionSeconds, parent.maximumCredentialLifetime)
      guard now <= 9_007_199_254_740_991 - duration else { throw HolderSessionError.invalid }
      let end = min(now + duration, parent.notAfter ?? (now + duration))
      guard end > now else { throw HolderSessionError.expired }
      let session = try await custody.create(expiresAt: end, now: now)
      try current(ticket)
      let intent = try HolderSessionPrepareIntent(parent: parent, session: session, context: context,
        requestID: requestID, requestedTTL: duration, permissions: permissions)
      let body = try await wallet.prepare(intent, now: clock())
      try current(ticket)
      let raw = try await issuer.prepare(body)
      try current(ticket)
      let reviewed = try HolderSessionChallenge.decode(raw, intent: intent, now: clock())
      let next = HolderSessionFlowRecord(schema: "zenith.holder-session-record.v1", clientID: clientID,
        requestID: requestID, requestHandle: requestHandle, service: service, challenge: reviewed.data,
        phase: .awaitingHuman, version: 1, dispatched: false, credentialHandle: nil)
      try journal.save(next, replacing: nil)
      record = next; challenge = reviewed; phase = .awaitingHuman
      return reviewed
    } catch {
      phase = .closed; epoch &+= 1; await custody.stop(); await issuer.shutdown(); throw error
    }
  }
  public func prepareNativeReview() async throws -> HolderSessionAuthorizationReview {
    guard !busy, phase == .awaitingHuman, let challenge else { throw HolderSessionError.changed }
    busy = true; consent = nil; let ticket = epoch; defer { busy = false }
    try beforeConsent(challenge)
    let reviewed = try await wallet.review(challenge, now: clock())
    try current(ticket); try beforeConsent(challenge)
    consent = reviewed
    return reviewed
  }
  public func invalidateConsent() {
    // Locking the long-term Wallet cannot invalidate an already-issued session.
    guard phase == .awaitingHuman else { return }
    consent = nil; epoch &+= 1
  }

  public func approveNativeReview(digest: String, expiresAt: UInt64) async throws {
    guard !busy, phase == .awaitingHuman, let challenge, let consent,
      digest == challenge.digest, expiresAt == challenge.expiresAt else { throw HolderSessionError.changed }
    busy = true; self.consent = nil; let ticket = epoch
    defer { busy = false }
    try beforeConsent(challenge)
    let signature = try await custody.possession(challenge, now: clock())
    try current(ticket); try beforeConsent(challenge)
    let authorization = try await wallet.approve(consent, signature: signature, now: clock())
    try current(ticket); try beforeConsent(challenge)
    // The reusable parent/authorization exists only in memory. The journal
    // records dispatch first, and never receives either private payload.
    try transition(.dispatched, dispatched: true)
    do {
      let result = try await issuer.exchange(authorization, challenge: challenge)
      try current(ticket)
      try await accept(result, challenge: challenge, ticket: ticket)
    } catch {
      if epoch == ticket, [.dispatched, .outcomeUnknown].contains(phase) { try? transition(.outcomeUnknown, dispatched: true) }
      throw error
    }
  }
  public func checkOriginalResult() async throws {
    guard !busy, [.dispatched, .outcomeUnknown, .issued].contains(phase), let challenge else { throw HolderSessionError.changed }
    busy = true; let ticket = epoch; defer { busy = false }
    guard clock() < challenge.expiresAt else { try await finish(.expired); throw HolderSessionError.expired }
    let proof = try await custody.status(challenge, now: clock())
    try current(ticket)
    let result = try await issuer.status(proof, challenge: challenge)
    try current(ticket)
    try await accept(result, challenge: challenge, ticket: ticket)
  }
  public func execute(client: String, handle: String, call: Data) async throws -> Data {
    guard !busy, phase == .issued, client == clientID, record?.credentialHandle == handle,
      let credential else { throw HolderSessionError.changed }
    guard clock() < credential.challenge.expiresAt else { try await finish(.expired); throw HolderSessionError.expired }
    busy = true; let ticket = epoch; defer { busy = false }
    let presentation = try await custody.present(credential, call: call, now: clock())
    try current(ticket)
    // No Wallet access, renewal or new exchange on the call path.
    let businessResult = try await issuer.execute(presentation)
    try current(ticket)
    guard clock() < credential.challenge.expiresAt else { try await finish(.expired); throw HolderSessionError.expired }
    return businessResult
  }
  public func close() async throws {
    epoch &+= 1; consent = nil; credential = nil
    // Destroy local custody even if audit storage is unavailable.
    phase = .closed; await custody.stop(); await issuer.shutdown()
    if record != nil { try transition(.closed, dispatched: record!.dispatched) }
  }
  private func current(_ ticket: UInt64) throws {
    try Task.checkCancellation()
    guard epoch == ticket, phase != .closed else { throw HolderSessionError.changed }
  }
  private func beforeConsent(_ c: HolderSessionChallenge) throws {
    let now = clock()
    guard now >= c.issuedAt, now < c.reviewDeadline, now < c.expiresAt else { throw HolderSessionError.expired }
  }
  private func accept(_ result: HolderSessionExchangeResult, challenge: HolderSessionChallenge, ticket: UInt64) async throws {
    guard clock() < challenge.expiresAt else { try await finish(.expired); throw HolderSessionError.expired }
    switch result {
    case .issued(let data):
      let token = try HolderSessionCredential.decode(data, challenge: challenge, now: clock())
      if let original = credential, original.digest != token.digest { throw HolderSessionError.changed }
      try await custody.install(token, now: clock()); try current(ticket)
      guard clock() < challenge.expiresAt else { try await finish(.expired); throw HolderSessionError.expired }
      let handle = record?.credentialHandle ?? UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
      try transition(.issued, dispatched: true, credentialHandle: handle); credential = token
    case .unknown: try transition(.outcomeUnknown, dispatched: true)
    case .denied: try await finish(.denied)
    case .revoked: try await finish(.revoked)
    case .expired: try await finish(.expired)
    }
  }
  private func finish(_ next: HolderSessionPhase) async throws {
    credential = nil; phase = next
    await custody.stop(); await issuer.shutdown()
    try transition(next, dispatched: true)
  }
  private func transition(_ phase: HolderSessionPhase, dispatched: Bool, credentialHandle: String? = nil) throws {
    guard let previous = record, !previous.dispatched || dispatched else { throw HolderSessionError.changed }
    var next = previous; next.version += 1; next.phase = phase; next.dispatched = dispatched
    next.credentialHandle = credentialHandle ?? previous.credentialHandle
    try journal.save(next, replacing: previous)
    record = next; self.phase = phase
  }
}
