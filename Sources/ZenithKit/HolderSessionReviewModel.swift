import Combine
import Foundation

/// Application session state. Only a native human action invokes `approve`.
/// Revisions replace an unsubmitted request with a fresh key/request/challenge.
@MainActor
public final class HolderSessionReviewModel: ObservableObject {
  public typealias Factory = @Sendable () async throws -> HolderSessionFlow
  @Published public private(set) var challenge: HolderSessionChallenge?
  @Published public private(set) var phase: HolderSessionPhase = .idle
  @Published public private(set) var busy = false
  @Published public private(set) var error: String?
  @Published public private(set) var credentialHandle: String?
  public let service: String, label: String, purpose: String
  public let maximumLifetime: UInt64
  public let proposedLifetime: UInt64
  private let factory: Factory
  private var flow: HolderSessionFlow?
  private var epoch: UInt64 = 0
  private var selected: Data?
  private var submitted = false
  public init(service: String, label: String, purpose: String, maximumLifetime: UInt64, proposedLifetime: UInt64 = 300, initialPermissions: Data? = nil, factory: @escaping Factory) throws {
    try HS.text(service); try HS.text(label, maximum: 512); try HS.text(purpose, maximum: 512)
    guard maximumLifetime > 0, maximumLifetime <= 3600 else { throw HolderSessionError.invalid }
    self.service = service; self.label = label; self.purpose = purpose; self.maximumLifetime = maximumLifetime; self.proposedLifetime = min(max(1, proposedLifetime), maximumLifetime); self.selected = initialPermissions; self.factory = factory
  }
  public var permissions: [HolderGrantPermission] {
    challenge?.permissions ?? []
  }
  public var mayEdit: Bool { !submitted && !busy && ![.issued, .closed, .denied, .revoked].contains(phase) }
  public func prepare(lifetime: UInt64, permissions: Data? = nil) async {
    guard mayEdit, lifetime > 0, lifetime <= maximumLifetime else { return }
    busy = true; error = nil; epoch &+= 1; let ticket = epoch
    defer { busy = false }
    do {
      let requested = try permissions.map { data -> Data in
        try HS.permissions(HS.value(data)); return try HS.encode(HS.value(data))
      }
      // Native edits may narrow the offered set, never add another permission.
      if let challenge, let requested {
        let offered = try HS.value(challenge.permissionData) as! [[String: Any]]
        let chosen = try HS.value(requested) as! [[String: Any]]
        let allowed = try Set(offered.map { try HS.encode($0) })
        guard try chosen.allSatisfy({ try allowed.contains(HS.encode($0)) }) else { throw HolderSessionError.changed }
      }
      let next = try await factory()
      let prepared = try await next.prepare(permissions: requested ?? selected, lifetime: lifetime, maximumSessionSeconds: maximumLifetime)
      guard epoch == ticket else { try? await next.close(); throw HolderSessionError.changed }
      try await flow?.close(); flow = next; challenge = prepared; phase = .awaitingHuman; selected = try prepared.permissionData
    } catch { self.error = "Could not prepare this session. Unlock Wallet and check the saved service and reusable grant." }
  }
  public func approve(digest: String, expiresAt: UInt64) async {
    guard !busy, !submitted, phase == .awaitingHuman, let flow, let challenge,
      digest == challenge.digest, expiresAt == challenge.expiresAt else { return }
    busy = true; error = nil; let ticket = epoch; defer { busy = false }
    do {
      _ = try await flow.prepareNativeReview()
      guard epoch == ticket else { throw HolderSessionError.changed }
      // This point is reachable only through the native approval action.
      submitted = true
      try await flow.approveNativeReview(digest: digest, expiresAt: expiresAt)
      guard epoch == ticket else { throw HolderSessionError.changed }
      await synchronize()
    } catch {
      await synchronize()
      if phase == .awaitingHuman { submitted = false }
      self.error = submitted ? "The original result needs confirmation. Check it without approving again." : "Wallet could not verify this exact review. No new approval was submitted."
    }
  }
  public func checkOriginalResult() async {
    guard !busy, submitted, let flow else { return }
    busy = true; error = nil; defer { busy = false }
    do { try await flow.checkOriginalResult(); await synchronize() }
    catch { await synchronize(); self.error = "The original session could not be confirmed. No new approval was sent." }
  }
  public func invalidateConsent() async { await flow?.invalidateConsent() }
  public func execute(client: String, handle: String, call: Data) async throws -> Data {
    guard let flow, !busy else { throw HolderSessionError.changed }
    do { let result = try await flow.execute(client: client, handle: handle, call: call); await synchronize(); return result }
    catch { await synchronize(); throw error }
  }
  public func close() async {
    epoch &+= 1; credentialHandle = nil; phase = .closed
    try? await flow?.close(); flow = nil
  }
  private func synchronize() async {
    guard let flow else { return }
    phase = await flow.currentPhase(); credentialHandle = await flow.publicCredentialHandle()
  }
}
