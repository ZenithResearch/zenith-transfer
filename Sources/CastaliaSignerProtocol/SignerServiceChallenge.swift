import Foundation

/// The endpoint is a presentation route, separate from canonical service
/// authority. The native engine verifies the original signed challenge using
/// the paired canonical issuer key and this exact route.
public struct SignerServiceChallenge: Codable, Sendable {
  public let schema: String
  public let receiver: String
  public let challenge: Data
  public init(receiver: String, challenge: Data) throws {
    schema = "castalia.signer-service-challenge.v1"; self.receiver = receiver; self.challenge = challenge
    try validate()
  }
  public func validate() throws {
    guard schema == "castalia.signer-service-challenge.v1", !challenge.isEmpty, challenge.count <= 131_072,
      receiver.utf8.count <= 2048, let url = URLComponents(string: receiver),
      url.scheme == "https", url.host?.isEmpty == false, url.user == nil, url.password == nil,
      url.query == nil, url.fragment == nil, url.path.isEmpty,
      url.url?.absoluteString == receiver else { throw SignerFailure.invalidMessage }
  }
  public func encoded() throws -> Data { try SignerWire.encode(self) }
  public static func decode(_ data: Data) throws -> Self {
    var validator = StrictSignerJSON(data); try validator.validate()
    _ = try SignerWire.object(JSONSerialization.jsonObject(with: data), allowed: ["schema", "receiver", "challenge"], required: ["schema", "receiver", "challenge"])
    let value = try JSONDecoder().decode(Self.self, from: data); try value.validate(); return value
  }
}

/// Every value comes from native verification or the signed request. It does
/// not carry native consent tokens. Signer-owned UI renders all detail fields.
public struct SignerProofDisclosure: Codable, Sendable {
  public let schema: String
  public let wallet: String
  public let client: String
  public let service: SignerService
  public let receiver: String
  public let proofKind: SignerProofKind
  public let operation: String
  public let expiresAt: UInt64
  public let details: Data
  public init(request: SignedSignerRequest, receiver: String, operation: String, expiresAt: UInt64, verifiedDetails: Data) throws {
    guard let wallet = request.body.expectedWallet, let service = request.body.service,
      let kind = request.body.proofKind, !operation.isEmpty, operation.utf8.count <= 128,
      !verifiedDetails.isEmpty, verifiedDetails.count <= 131_072,
      expiresAt <= 9_007_199_254_740_991 else { throw SignerFailure.invalidMessage }
    schema = "castalia.signer-proof-disclosure.v1"; self.wallet = wallet; client = request.body.clientKey
    self.service = service; self.receiver = receiver; proofKind = kind; self.operation = operation
    self.expiresAt = expiresAt; details = verifiedDetails
  }
}
