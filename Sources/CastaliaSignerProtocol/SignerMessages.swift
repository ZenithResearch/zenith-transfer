import Foundation
import CryptoKit

public enum SignerFailure: String, Error, Codable, Sendable {
  case invalidMessage, unsupportedVersion, unpairedClient, wrongWallet, expired
  case changedRequest, cancelled, alreadyDecided, interactionRequired, unavailable
}

/// Transport-neutral identity. An HTTPS route is deliberately not a field in
/// this authority binding; TLS/origin checks remain the network client's job.
public struct SignerService: Codable, Equatable, Hashable, Sendable {
  public let issuer: String
  public let audience: String
  public let keyID: String
  public let publicKey: String
  public init(issuer: String, audience: String, keyID: String, publicKey: String) throws {
    self.issuer = issuer; self.audience = audience; self.keyID = keyID; self.publicKey = publicKey
    try validate()
  }
  public func validate() throws {
    guard SignerWire.identifier(issuer), SignerWire.identifier(audience),
      SignerWire.identifier(keyID), SignerWire.hex(publicKey, bytes: 32) else { throw SignerFailure.invalidMessage }
  }
}

/// This list is closed. It contains neither a raw core invoke nor sign(bytes).
/// Custody maintenance opens signer-owned UI; no password/seed travels over IPC.
public enum SignerOperation: String, Codable, CaseIterable, Sendable {
  case status, openWallet, lock, cancel
  case prepareServiceProof, requestServiceApproval, recoverOriginalResult
  case readWalletDescriptors, reviewWalletIdentities
}
public enum SignerProofKind: String, Codable, Sendable {
  case graphAccessRequestV2, graphReadEnrollmentV2, graphReadPresentationV2
  case operatorAccessV1, resourceOwnerV1, membershipRequestV1
}

public struct SignerRequestBody: Codable, Equatable, Sendable {
  public let schema: String
  public let requestID: String
  public let clientKey: String
  public let expectedWallet: String?
  public let issuedAt: UInt64
  public let expiresAt: UInt64
  public let nonce: String
  public let operation: SignerOperation
  public let service: SignerService?
  public let proofKind: SignerProofKind?
  public let originalRequestID: String?
  /// Exact original public protocol bytes, never a decrypted custody snapshot.
  public let payload: Data
  public init(requestID: String = UUID().uuidString.lowercased(), clientKey: String,
    expectedWallet: String?, issuedAt: UInt64, expiresAt: UInt64, nonce: String,
    operation: SignerOperation, service: SignerService? = nil, proofKind: SignerProofKind? = nil,
    originalRequestID: String? = nil, payload: Data = Data()) throws {
    schema = "castalia.signer-request.v1"; self.requestID = requestID; self.clientKey = clientKey
    self.expectedWallet = expectedWallet; self.issuedAt = issuedAt; self.expiresAt = expiresAt
    self.nonce = nonce; self.operation = operation; self.service = service; self.proofKind = proofKind
    self.originalRequestID = originalRequestID; self.payload = payload
    try validate(now: issuedAt)
  }
  public func validate(now: UInt64) throws {
    guard schema == "castalia.signer-request.v1" else { throw SignerFailure.unsupportedVersion }
    guard SignerWire.uuid(requestID), SignerWire.hex(clientKey, bytes: 32),
      expectedWallet.map({ SignerWire.hex($0, bytes: 32) }) ?? true,
      SignerWire.hex(nonce, bytes: 32), issuedAt <= 9_007_199_254_740_991,
      expiresAt <= 9_007_199_254_740_991, expiresAt > issuedAt,
      expiresAt - issuedAt <= 120, payload.count <= 262_144 else { throw SignerFailure.invalidMessage }
    guard issuedAt <= now, now < expiresAt else { throw SignerFailure.expired }
    switch operation {
    case .status, .openWallet, .lock, .readWalletDescriptors:
      guard payload.isEmpty, service == nil, proofKind == nil, originalRequestID == nil else { throw SignerFailure.invalidMessage }
    case .prepareServiceProof:
      guard expectedWallet != nil, let service, proofKind != nil,
        originalRequestID == nil, !payload.isEmpty else { throw SignerFailure.invalidMessage }
      try service.validate()
    case .requestServiceApproval, .recoverOriginalResult, .cancel:
      guard originalRequestID.map(SignerWire.uuid) == true, payload.isEmpty,
        service == nil, proofKind == nil else { throw SignerFailure.invalidMessage }
    case .reviewWalletIdentities:
      guard expectedWallet != nil, !payload.isEmpty, service == nil,
        proofKind == nil, originalRequestID == nil else { throw SignerFailure.invalidMessage }
    }
  }
  public func canonicalBytes() throws -> Data { try SignerWire.encode(self) }
}

public struct SignedSignerRequest: Codable, Equatable, Sendable {
  public let body: SignerRequestBody
  public let signature: String
  public init(body: SignerRequestBody, key: Curve25519.Signing.PrivateKey) throws {
    guard SignerWire.hex(key.publicKey.rawRepresentation) == body.clientKey else { throw SignerFailure.unpairedClient }
    self.body = body
    signature = SignerWire.hex(try key.signature(for: Self.transcript(body)))
  }
  public func verify(now: UInt64) throws {
    try body.validate(now: now)
    guard let bytes = SignerWire.bytes(signature, count: 64),
      let publicBytes = SignerWire.bytes(body.clientKey, count: 32),
      let key = try? Curve25519.Signing.PublicKey(rawRepresentation: publicBytes),
      key.isValidSignature(bytes, for: try Self.transcript(body)) else { throw SignerFailure.unpairedClient }
  }
  public var digest: String { get throws { SignerWire.hex(Data(SHA256.hash(data: try SignerWire.encode(self)))) } }
  private static func transcript(_ body: SignerRequestBody) throws -> Data {
    var value = Data("castalia/signer-request/v1\0".utf8); value.append(try body.canonicalBytes()); return value
  }
  public func encoded() throws -> Data { try SignerWire.encode(self) }
  public static func decode(_ data: Data, now: UInt64) throws -> Self {
    try SignerWire.closedRequest(data)
    let value = try JSONDecoder().decode(Self.self, from: data); try value.verify(now: now); return value
  }
}

public enum SignerResult: String, Codable, Sendable {
  case state, pending, approved, denied, cancelled, expired, interactionRequired
}
public struct SignerResponseBody: Codable, Equatable, Sendable {
  public let schema: String
  public let requestID: String
  public let requestDigest: String
  public let clientKey: String
  public let signerKey: String
  public let walletKey: String?
  public let result: SignerResult
  public let expiresAt: UInt64
  /// Public state, verified summary or approved proof; never root custody.
  public let payload: Data
  public init(request: SignedSignerRequest, signerKey: String, walletKey: String?, result: SignerResult,
    expiresAt: UInt64, payload: Data = Data()) throws {
    schema = "castalia.signer-response.v1"; requestID = request.body.requestID
    requestDigest = try request.digest; clientKey = request.body.clientKey; self.signerKey = signerKey
    self.walletKey = walletKey; self.result = result; self.expiresAt = expiresAt; self.payload = payload
  }
}
public struct SignedSignerResponse: Codable, Equatable, Sendable {
  public let body: SignerResponseBody
  public let signature: String
  public init(body: SignerResponseBody, key: Curve25519.Signing.PrivateKey) throws {
    guard body.signerKey == SignerWire.hex(key.publicKey.rawRepresentation) else { throw SignerFailure.invalidMessage }
    self.body = body; signature = SignerWire.hex(try key.signature(for: Self.transcript(body)))
  }
  public func verify(request: SignedSignerRequest, pinnedSigner: String, now: UInt64) throws {
    try request.verify(now: now)
    guard body.schema == "castalia.signer-response.v1" else { throw SignerFailure.unsupportedVersion }
    guard body.requestID == request.body.requestID, body.requestDigest == (try request.digest),
      body.clientKey == request.body.clientKey, body.signerKey == pinnedSigner,
      body.walletKey.map({ SignerWire.hex($0, bytes: 32) }) ?? true,
      body.expiresAt <= request.body.expiresAt, now < body.expiresAt,
      body.payload.count <= 524_288 else { throw SignerFailure.changedRequest }
    if let expected = request.body.expectedWallet, body.walletKey != expected { throw SignerFailure.wrongWallet }
    guard let keyBytes = SignerWire.bytes(pinnedSigner, count: 32), let bytes = SignerWire.bytes(signature, count: 64),
      let key = try? Curve25519.Signing.PublicKey(rawRepresentation: keyBytes),
      key.isValidSignature(bytes, for: try Self.transcript(body)) else { throw SignerFailure.changedRequest }
  }
  public func encoded() throws -> Data { try SignerWire.encode(self) }
  public static func decode(_ data: Data, request: SignedSignerRequest, pinnedSigner: String, now: UInt64) throws -> Self {
    try SignerWire.closedResponse(data)
    let value = try JSONDecoder().decode(Self.self, from: data)
    try value.verify(request: request, pinnedSigner: pinnedSigner, now: now); return value
  }
  private static func transcript(_ body: SignerResponseBody) throws -> Data {
    var value = Data("castalia/signer-response/v1\0".utf8); value.append(try SignerWire.encode(body)); return value
  }
}

public enum SignerWire {
  public static func encode<T: Encodable>(_ value: T) throws -> Data {
    let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    return try encoder.encode(value)
  }
  public static func hex(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }
  public static func hex(_ text: String, bytes: Int) -> Bool {
    text.utf8.count == bytes * 2 && text.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
  }
  public static func bytes(_ text: String, count: Int) -> Data? {
    guard hex(text, bytes: count) else { return nil }
    let chars = Array(text.utf8); var out = Data(); out.reserveCapacity(count)
    for i in stride(from: 0, to: chars.count, by: 2) {
      func nibble(_ b: UInt8) -> UInt8 { b <= 57 ? b - 48 : b - 87 }
      out.append(nibble(chars[i]) * 16 + nibble(chars[i+1]))
    }
    return out
  }
  public static func uuid(_ text: String) -> Bool {
    UUID(uuidString: text)?.uuidString.lowercased() == text && text != "00000000-0000-0000-0000-000000000000"
  }
  public static func identifier(_ text: String) -> Bool {
    !text.isEmpty && text.utf8.count <= 256 && text.unicodeScalars.allSatisfy { $0.isASCII && $0.value > 32 && $0.value < 127 }
  }
  static func object(_ value: Any?, allowed: Set<String>, required: Set<String>) throws -> [String: Any] {
    guard let object = value as? [String: Any], Set(object.keys).isSubset(of: allowed),
      required.isSubset(of: Set(object.keys)) else { throw SignerFailure.invalidMessage }; return object
  }
  static func closedRequest(_ data: Data) throws {
    var checker = StrictSignerJSON(data); try checker.validate()
    let root = try object(JSONSerialization.jsonObject(with: data), allowed: ["body","signature"], required: ["body","signature"])
    let required: Set<String> = ["schema","requestID","clientKey","issuedAt","expiresAt","nonce","operation","payload"]
    let body = try object(root["body"], allowed: required.union(["expectedWallet","service","proofKind","originalRequestID"]), required: required)
    if let service = body["service"] { _ = try object(service, allowed: ["issuer","audience","keyID","publicKey"], required: ["issuer","audience","keyID","publicKey"]) }
  }
  static func closedResponse(_ data: Data) throws {
    var checker = StrictSignerJSON(data); try checker.validate()
    let root = try object(JSONSerialization.jsonObject(with: data), allowed: ["body","signature"], required: ["body","signature"])
    let required: Set<String> = ["schema","requestID","requestDigest","clientKey","signerKey","result","expiresAt","payload"]
    _ = try object(root["body"], allowed: required.union(["walletKey"]), required: required)
  }
}
