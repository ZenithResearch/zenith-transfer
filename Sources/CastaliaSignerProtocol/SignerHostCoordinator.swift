import CryptoKit
import Foundation

public struct SignerWalletDescriptor: Codable, Equatable, Sendable {
  public let configured: Bool
  public let unlocked: Bool
  public let publicKey: String?
  public init(configured: Bool, unlocked: Bool, publicKey: String?) throws {
    guard publicKey.map({ SignerWire.hex($0, bytes: 32) }) ?? !configured,
      !unlocked || configured else { throw SignerFailure.invalidMessage }
    self.configured = configured; self.unlocked = unlocked; self.publicKey = publicKey
  }
}
public struct SignerVerifiedReview: Equatable, Sendable {
  public let requestDigest: String
  /// Produced by the native verifier, never copied from a client-supplied label.
  public let summary: Data
  public init(requestDigest: String, summary: Data) throws {
    guard SignerWire.hex(requestDigest, bytes: 32), !summary.isEmpty, summary.count <= 262_144 else {
      throw SignerFailure.invalidMessage
    }
    self.requestDigest = requestDigest; self.summary = summary
  }
}
/// Implemented only in signer custody. Native consent tokens stay behind this
/// boundary and are looked up using the exact signed request digest.
public protocol SignerRootEngine: Actor {
  func descriptor() async throws -> SignerWalletDescriptor
  func prepare(_ request: SignedSignerRequest, now: UInt64) async throws -> SignerVerifiedReview
  func approve(_ request: SignedSignerRequest, now: UInt64) async throws -> Data
  func cancelPrepared() async
  func lock() async
}
public enum SignerHostEvent: Sendable {
  case openWallet
  case review(requestID: String, client: String, digest: String, summary: Data)
}

/// The exported exchange method prepares/reads/cancels only. The separate
/// approve/decline methods are invoked by signer-owned UI and never exported
/// through XPC or URL dispatch. There is no automatic approval policy here.
public actor SignerHostCoordinator {
  private let journal: SignerConsentJournal
  private let engine: any SignerRootEngine
  private let identity: Curve25519.Signing.PrivateKey
  private let clock: @Sendable () -> UInt64
  private let event: @Sendable (SignerHostEvent) async -> Void
  private var epoch: UInt64 = 0
  public init(journal: SignerConsentJournal, engine: any SignerRootEngine,
    identity: Curve25519.Signing.PrivateKey,
    clock: @escaping @Sendable () -> UInt64 = { UInt64(Date().timeIntervalSince1970) },
    event: @escaping @Sendable (SignerHostEvent) async -> Void) {
    self.journal = journal; self.engine = engine; self.identity = identity; self.clock = clock; self.event = event
  }
  private func authorize(_ request: SignedSignerRequest) async throws -> SignerClientPolicy {
    let policy = try await journal.pairing(clientKey: request.body.clientKey).policy
    try policy.authorize(request, now: clock())
    let descriptor = try await engine.descriptor()
    guard descriptor.publicKey == policy.walletKey,
      request.body.expectedWallet == policy.walletKey else { throw SignerFailure.wrongWallet }
    return policy
  }
  public func exchange(_ wire: Data) async throws -> Data {
    let request = try SignedSignerRequest.decode(wire, now: clock())
    _ = try await authorize(request)
    let result: SignerResult, payload: Data
    switch request.body.operation {
    case .status, .readWalletDescriptors:
      result = .state; payload = try SignerWire.encode(await engine.descriptor())
    case .openWallet:
      await event(.openWallet); result = .interactionRequired; payload = Data()
    case .lock:
      await lock(); result = .state; payload = try SignerWire.encode(await engine.descriptor())
    case .prepareServiceProof:
      let generation = epoch
      let digest = try request.digest
      // Exact duplicate preparation recovers the saved result; it never calls
      // the root engine again, including after a crash or expired UI review.
      let existing = try? await journal.entry(requestID: request.body.requestID, clientKey: request.body.clientKey)
      let entry: SignerJournalEntry
      if let existing {
        guard existing.requestDigest == digest else { throw SignerFailure.changedRequest }; entry = existing
      } else {
        do {
          let review = try await engine.prepare(request, now: clock())
          guard generation == epoch, review.requestDigest == digest else { throw SignerFailure.changedRequest }
          let policy = try await authorize(request)
          entry = try await journal.register(request, policy: policy, verifiedSummary: review.summary, now: clock())
        } catch {
          await engine.cancelPrepared()
          try? await journal.invalidatePending()
          throw error
        }
      }
      (result, payload) = try await disclosure(entry)
    case .requestServiceApproval, .recoverOriginalResult, .cancel:
      guard let originalID = request.body.originalRequestID else { throw SignerFailure.invalidMessage }
      if request.body.operation == .cancel {
        try await journal.cancel(requestID: originalID, clientKey: request.body.clientKey)
        await engine.cancelPrepared()
        try await journal.invalidatePending()
      }
      let entry = try await journal.entry(requestID: originalID, clientKey: request.body.clientKey)
      guard entry.request.body.expectedWallet == request.body.expectedWallet else { throw SignerFailure.wrongWallet }
      let current = try await journal.pairing(clientKey: request.body.clientKey).policy
      try entry.request.verify(now: entry.request.body.issuedAt)
      guard current.operations.contains(entry.request.body.operation),
        entry.request.body.service.map({ current.services.contains($0) }) ?? true else { throw SignerFailure.unpairedClient }
      (result, payload) = try await disclosure(entry)
      if request.body.operation == .requestServiceApproval, entry.phase == .pending {
        _ = try await authorize(entry.request)
        await event(.review(requestID: originalID, client: request.body.clientKey, digest: entry.requestDigest, summary: entry.summary))
      }
    case .reviewWalletIdentities:
      // Custody maintenance belongs in the signer's Wallet UI. No arbitrary
      // JSON patch crosses this public proof endpoint.
      await event(.openWallet); result = .interactionRequired; payload = Data()
    }
    _ = try await authorize(request)
    let response = try SignerResponseBody(request: request, signerKey: SignerWire.hex(identity.publicKey.rawRepresentation),
      walletKey: request.body.expectedWallet, result: result, expiresAt: request.body.expiresAt, payload: payload)
    return try SignedSignerResponse(body: response, key: identity).encoded()
  }
  private func disclosure(_ entry: SignerJournalEntry) async throws -> (SignerResult, Data) {
    switch entry.phase {
    case .approved: return (.approved, entry.approvedProof ?? Data())
    case .denied: return (.denied, Data())
    case .cancelled: return (.cancelled, Data())
    case .signing, .uncertain: return (.interactionRequired, Data())
    case .pending:
      if entry.request.body.expiresAt <= clock() { return (.expired, Data()) }
      return (.pending, entry.summary)
    }
  }
  /// Trusted UI supplies the digest it actually displayed; the client cannot
  /// invoke this through the closed exchange contract.
  public func approve(requestID: String, clientKey: String, reviewedDigest: String) async throws {
    let generation = epoch
    let entry = try await journal.entry(requestID: requestID, clientKey: clientKey)
    let policy = try await authorize(entry.request)
    let ticket = try await journal.beginApproval(requestID: requestID, clientKey: clientKey,
      reviewedDigest: reviewedDigest, policy: policy, now: clock())
    guard generation == epoch else { throw SignerFailure.cancelled }
    let proof = try await engine.approve(entry.request, now: clock())
    guard generation == epoch else { throw SignerFailure.cancelled }
    let currentPolicy = try await authorize(entry.request)
    try await journal.complete(ticket, approvedProof: proof, policy: currentPolicy, now: clock())
  }
  public func decline(requestID: String, clientKey: String, reviewedDigest: String) async throws {
    try await journal.decline(requestID: requestID, clientKey: clientKey, reviewedDigest: reviewedDigest)
    try await journal.invalidatePending()
    await engine.cancelPrepared()
  }
  public func lock() async {
    epoch &+= 1
    // If persistence fails, the engine still locks and no saved approval token
    // survives the core lock. The next startup converts signing to uncertain.
    try? await journal.invalidatePending()
    await engine.lock()
  }
}
