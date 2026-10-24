import CryptoKit
import Foundation

public protocol SignerTransport: Sendable {
  /// One attempt only. A timeout is uncertain, never permission to sign again.
  func exchange(_ message: Data) async throws -> Data
}

/// Application-side state contains only its own holder key, paired signer pin,
/// public request bytes and approved application results. It has no Wallet core.
public actor SignerClientSession {
  private let holder: Curve25519.Signing.PrivateKey
  private let pinnedSigner: String
  private let wallet: String
  private let transport: any SignerTransport
  private var pending: [String: SignedSignerRequest] = [:]
  private var inFlight: Set<String> = []
  public init(holder: Curve25519.Signing.PrivateKey, pinnedSigner: String, wallet: String,
    transport: any SignerTransport) throws {
    guard SignerWire.hex(pinnedSigner, bytes: 32), SignerWire.hex(wallet, bytes: 32) else { throw SignerFailure.invalidMessage }
    self.holder = holder; self.pinnedSigner = pinnedSigner; self.wallet = wallet; self.transport = transport
  }
  public func prepare(operation: SignerOperation, service: SignerService? = nil, proofKind: SignerProofKind? = nil,
    originalRequestID: String? = nil, payload: Data = Data(), now: UInt64) throws -> SignedSignerRequest {
    guard pending.count < 16, now <= 9_007_199_254_740_871 else { throw SignerFailure.unavailable }
    let nonce = SymmetricKey(size: .bits256).withUnsafeBytes { SignerWire.hex(Data($0)) }
    let body = try SignerRequestBody(clientKey: SignerWire.hex(holder.publicKey.rawRepresentation), expectedWallet: wallet,
      issuedAt: now, expiresAt: now + 120, nonce: nonce, operation: operation, service: service,
      proofKind: proofKind, originalRequestID: originalRequestID, payload: payload)
    let request = try SignedSignerRequest(body: body, key: holder); pending[body.requestID] = request; return request
  }
  public func send(requestID: String, now: @Sendable () -> UInt64) async throws -> SignedSignerResponse {
    guard let request = pending[requestID], inFlight.insert(requestID).inserted else { throw SignerFailure.changedRequest }
    defer { inFlight.remove(requestID) }
    try request.verify(now: now())
    let data = try await transport.exchange(request.encoded())
    try Task.checkCancellation()
    return try SignedSignerResponse.decode(data, request: request, pinnedSigner: pinnedSigner, now: now())
  }
  public func retainedRequest(_ requestID: String) -> SignedSignerRequest? { pending[requestID] }
  /// Removing local correlation does not remotely cancel an uncertain operation.
  public func forget(_ requestID: String) throws {
    guard !inFlight.contains(requestID) else { throw SignerFailure.interactionRequired }
    pending.removeValue(forKey: requestID)
  }
}
