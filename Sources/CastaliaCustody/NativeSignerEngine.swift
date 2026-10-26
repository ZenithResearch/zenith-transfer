import CastaliaSignerProtocol
import Foundation
import ZenithKit

/// The native verifier and actual one-use consent remain in the signer. This
/// object is not exported and cannot be constructed by an isolated app client.
public actor NativeSignerEngine: SignerRootEngine {
  private let repository: WalletRepository
  private enum Consent {
    case operatorAccess(SignedSignerRequest, OperatorConsent)
    case graphAccess(SignedSignerRequest, NativeAccessRequestPreview, UInt64)
  }
  private var prepared: [String: Consent] = [:]
  private var preparing = false
  private var epoch: UInt64 = 0
  public init(repository: WalletRepository) { self.repository = repository }
  public func descriptor() async throws -> SignerWalletDescriptor {
    let state = try await repository.state()
    return try SignerWalletDescriptor(configured: state.configured, unlocked: state.unlocked, publicKey: state.publicKey)
  }
  public func prepare(_ request: SignedSignerRequest, now: UInt64) async throws -> SignerVerifiedReview {
    try request.verify(now: now)
    guard request.body.operation == .prepareServiceProof, !preparing, prepared.isEmpty,
      let service = request.body.service, let kind = request.body.proofKind else { throw SignerFailure.interactionRequired }
    preparing = true; defer { preparing = false }
    let state = try await repository.state()
    guard state.unlocked, state.publicKey == request.body.expectedWallet else { throw SignerFailure.interactionRequired }
    let input = try SignerServiceChallenge.decode(request.body.payload)
    // Decode the closed native pin schema; the client cannot replace the paired
    // service identity/key through fields inside the challenge payload.
    let pinData = try JSONSerialization.data(withJSONObject: ["issuer": service.issuer, "audience": service.audience,
      "key_id": service.keyID, "public_key": service.publicKey, "receiver": input.receiver])
    let pin = try JSONDecoder().decode(ReadAuthorityPin.self, from: pinData)
    let generation = epoch, digest = try request.digest, ticket = repository.lifecycleTicket()
    let consent: Consent, disclosure: SignerProofDisclosure
    switch kind {
    case .operatorAccessV1:
      let value = try await repository.prepareOperatorAccess(input.challenge, pin: pin, now: now)
      guard value.issuer == service.issuer, value.receiver == input.receiver else { throw SignerFailure.changedRequest }
      consent = .operatorAccess(request, value)
      disclosure = try SignerProofDisclosure(request: request, receiver: value.receiver, operation: value.operation,
        expiresAt: UInt64(value.expiresAt.timeIntervalSince1970), verifiedDetails: value.details)
    case .graphAccessRequestV2:
      let value = try await repository.prepareGraphAccessRequestV2(input.challenge, pin: pin, now: now)
      guard value.summary.issuer == service.issuer, value.summary.receiver == input.receiver else { throw SignerFailure.changedRequest }
      consent = .graphAccess(request, value, ticket)
      disclosure = try SignerProofDisclosure(request: request, receiver: value.summary.receiver, operation: value.summary.operation,
        expiresAt: value.summary.expires_at, verifiedDetails: input.challenge)
    default:
      // No fallback to a raw signature or a less constrained older protocol.
      throw SignerFailure.unsupportedVersion
    }
    guard generation == epoch else { throw SignerFailure.cancelled }
    try repository.checkLifecycle(ticket)
    prepared[digest] = consent
    return try SignerVerifiedReview(requestDigest: digest, summary: SignerWire.encode(disclosure))
  }
  public func approve(_ request: SignedSignerRequest, now: UInt64) async throws -> Data {
    try request.verify(now: now)
    let digest = try request.digest
    guard let consent = prepared.removeValue(forKey: digest) else { throw SignerFailure.alreadyDecided }
    switch consent {
    case .operatorAccess(let original, let value):
      guard original == request else { throw SignerFailure.changedRequest }
      return try await repository.approveOperatorAccess(value, now: now)
    case .graphAccess(let original, let value, let ticket):
      guard original == request else { throw SignerFailure.changedRequest }
      return try await repository.approveGraphAccessRequestV2(value, now: now, ticket: ticket)
    }
  }
  public func cancelPrepared() async {
    epoch &+= 1; prepared.removeAll(); repository.invalidatePendingWork(); await repository.cancel()
  }
  public func lock() async {
    epoch &+= 1; prepared.removeAll(); repository.invalidatePendingWork(); await repository.lock()
  }
}
