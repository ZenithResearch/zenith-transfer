import CryptoKit
import Foundation

/// Public keys are accepted only from a pairing reviewed inside the signer.
/// A URL scheme or app name is not an authenticated application identity.
public struct SignerPeer: Codable, Equatable, Sendable {
  public let signingKey: String
  public let agreementKey: String
  public init(signingKey: String, agreementKey: String) throws {
    guard SignerWire.hex(signingKey, bytes: 32), SignerWire.hex(agreementKey, bytes: 32) else {
      throw SignerFailure.invalidMessage
    }
    self.signingKey = signingKey; self.agreementKey = agreementKey
  }
}

public enum SignerHandoffDirection: String, Codable, Sendable { case request, response }

/// An encrypted, bounded foreground handoff for the iOS 18 baseline. Only this
/// ciphertext may enter a URL or shared transport. Root custody never enters it.
public struct SignerSealedHandoff: Codable, Sendable {
  public let schema: String
  public let requestID: String
  public let direction: SignerHandoffDirection
  public let sender: SignerPeer
  public let recipient: SignerPeer
  public let ciphertext: Data

  private struct Context: Codable {
    let schema: String
    let requestID: String
    let direction: SignerHandoffDirection
    let sender: SignerPeer
    let recipient: SignerPeer
  }
  private var context: Context {
    Context(schema: schema, requestID: requestID, direction: direction, sender: sender, recipient: recipient)
  }
  private static func key(privateKey: Curve25519.KeyAgreement.PrivateKey,
    peer: SignerPeer, context: Data) throws -> SymmetricKey {
    guard let bytes = SignerWire.bytes(peer.agreementKey, count: 32) else { throw SignerFailure.unpairedClient }
    let publicKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: bytes)
    return try privateKey.sharedSecretFromKeyAgreement(with: publicKey).hkdfDerivedSymmetricKey(
      using: SHA256.self, salt: Data("castalia/sealed-handoff/v1".utf8), sharedInfo: context, outputByteCount: 32)
  }
  public init(requestID: String, direction: SignerHandoffDirection, sender: SignerPeer,
    recipient: SignerPeer, privateKey: Curve25519.KeyAgreement.PrivateKey, plaintext: Data) throws {
    guard SignerWire.uuid(requestID), !plaintext.isEmpty, plaintext.count <= 786_432,
      SignerWire.hex(privateKey.publicKey.rawRepresentation) == sender.agreementKey else {
      throw SignerFailure.invalidMessage
    }
    self.schema = "castalia.signer-sealed.v1"; self.requestID = requestID; self.direction = direction
    self.sender = sender; self.recipient = recipient
    let context = Context(schema: schema, requestID: requestID, direction: direction, sender: sender, recipient: recipient)
    let aad = try SignerWire.encode(context)
    guard let combined = try AES.GCM.seal(plaintext,
      using: Self.key(privateKey: privateKey, peer: recipient, context: aad), authenticating: aad).combined else {
      throw SignerFailure.unavailable
    }
    ciphertext = combined
  }
  public func open(expectedRequestID: String, direction expectedDirection: SignerHandoffDirection,
    sender expectedSender: SignerPeer, recipient expectedRecipient: SignerPeer,
    privateKey: Curve25519.KeyAgreement.PrivateKey) throws -> Data {
    guard schema == "castalia.signer-sealed.v1", requestID == expectedRequestID,
      SignerWire.uuid(requestID), direction == expectedDirection, sender == expectedSender,
      recipient == expectedRecipient, SignerWire.hex(privateKey.publicKey.rawRepresentation) == recipient.agreementKey,
      (29...786_460).contains(ciphertext.count) else { throw SignerFailure.changedRequest }
    let aad = try SignerWire.encode(context)
    do {
      return try AES.GCM.open(AES.GCM.SealedBox(combined: ciphertext),
        using: Self.key(privateKey: privateKey, peer: sender, context: aad), authenticating: aad)
    } catch { throw SignerFailure.changedRequest }
  }
  public func encoded() throws -> Data { try SignerWire.encode(self) }
  public func openRequest(signer: SignerPeer, pairedClient: SignerPeer,
    privateKey: Curve25519.KeyAgreement.PrivateKey, now: UInt64) throws -> SignedSignerRequest {
    let plaintext = try open(expectedRequestID: requestID, direction: .request, sender: pairedClient,
      recipient: signer, privateKey: privateKey)
    let request = try SignedSignerRequest.decode(plaintext, now: now)
    guard request.body.requestID == requestID, request.body.clientKey == pairedClient.signingKey else {
      throw SignerFailure.changedRequest
    }
    return request
  }
  public func openResponse(request: SignedSignerRequest, signer: SignerPeer, client: SignerPeer,
    privateKey: Curve25519.KeyAgreement.PrivateKey, now: UInt64) throws -> SignedSignerResponse {
    let plaintext = try open(expectedRequestID: request.body.requestID, direction: .response, sender: signer,
      recipient: client, privateKey: privateKey)
    guard request.body.clientKey == client.signingKey else { throw SignerFailure.unpairedClient }
    return try SignedSignerResponse.decode(plaintext, request: request, pinnedSigner: signer.signingKey, now: now)
  }
  public static func decode(_ data: Data) throws -> Self {
    // Base64 expands the maximum cipher size above the regular message bound.
    guard data.count <= 1_049_600 else { throw SignerFailure.invalidMessage }
    var validator = StrictSignerJSON(data, maximumBytes: 1_049_600); try validator.validate()
    let root = try SignerWire.object(JSONSerialization.jsonObject(with: data),
      allowed: ["schema", "requestID", "direction", "sender", "recipient", "ciphertext"],
      required: ["schema", "requestID", "direction", "sender", "recipient", "ciphertext"])
    for name in ["sender", "recipient"] {
      _ = try SignerWire.object(root[name], allowed: ["signingKey", "agreementKey"], required: ["signingKey", "agreementKey"])
    }
    return try JSONDecoder().decode(Self.self, from: data)
  }
}
