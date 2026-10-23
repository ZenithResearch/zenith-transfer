#if os(macOS)
import CryptoKit
import Darwin
import Foundation

/// An independently inspected selection, not a server-supplied replacement URL.
public struct ResourceOwnerBinding: Codable, Equatable, Sendable {
  public let resourceID: String
  public let endpoint: String
  public let configurationSHA256: String
  public let registrationSHA256: String
  enum CodingKeys: String, CodingKey {
    case resourceID = "resource_id", endpoint
    case configurationSHA256 = "configuration_sha256", registrationSHA256 = "registration_sha256"
  }
  public func validate() throws {
    guard UUID(uuidString: resourceID)?.uuidString.lowercased() == resourceID,
      ownerHex(configurationSHA256, 64), ownerHex(registrationSHA256, 64),
      endpoint.utf8.count <= 2048, endpoint.unicodeScalars.allSatisfy({ $0.isASCII && $0.value > 32 && $0.value != 127 }),
      !endpoint.contains("\\"), !endpoint.contains("%"),
      let url = URLComponents(string: endpoint), ["http", "https"].contains(url.scheme),
      let host = url.host, host == host.lowercased(), url.user == nil, url.password == nil,
      url.path.isEmpty, url.query == nil, url.fragment == nil,
      url.port != 0, url.port != (url.scheme == "https" ? 443 : 80),
      url.string == endpoint else { throw OwnerSetupError.invalid }
    if url.scheme == "http" {
      var address = in_addr(), address6 = in6_addr()
      let plain = host.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
      let ipv4 = inet_pton(AF_INET, plain, &address) == 1 && (UInt32(bigEndian: address.s_addr) >> 24) == 127
      let ipv6 = inet_pton(AF_INET6, plain, &address6) == 1 && plain == "::1"
      guard ipv4 || ipv6 else { throw OwnerSetupError.invalid }
    }
  }
}

public struct ResourceAdminGrant: Codable, Equatable, Sendable {
  public let schema: String
  public let grantID: String
  public let holderPublicKey: String
  public let resourceID: String
  public let operations: [String]
  public let validity: Validity
  public let onwardDelegation: Bool
  public struct Validity: Codable, Equatable, Sendable { public let mode: String }
  enum CodingKeys: String, CodingKey {
    case schema, operations, validity
    case grantID = "grant_id", holderPublicKey = "holder_public_key", resourceID = "resource_id", onwardDelegation = "onward_delegation"
  }
}

public struct ResourceOwnerChallenge: Codable, Equatable, Sendable {
  public let schema: String
  public let binding: ResourceOwnerBinding
  public let claimID: String
  public let nonce: String
  public let issuedAt: UInt64
  public let expiresAt: UInt64
  public let adminGrant: ResourceAdminGrant
  enum CodingKeys: String, CodingKey {
    case schema, binding, nonce
    case claimID = "claim_id", issuedAt = "issued_at", expiresAt = "expires_at", adminGrant = "admin_grant"
  }
  public static func decode(_ data: Data, binding: ResourceOwnerBinding, now: UInt64) throws -> Self {
    let raw = try ownerObject(data)
    try ownerKeys(raw, ["schema", "binding", "claim_id", "nonce", "issued_at", "expires_at", "admin_grant"])
    try ownerKeys(raw["binding"], ["resource_id", "endpoint", "configuration_sha256", "registration_sha256"])
    try ownerKeys(raw["admin_grant"], ["schema", "grant_id", "holder_public_key", "resource_id", "operations", "validity", "onward_delegation"])
    try ownerKeys((raw["admin_grant"] as? [String: Any])?["validity"], ["mode"])
    let value = try JSONDecoder().decode(Self.self, from: data)
    try binding.validate()
    guard value.binding == binding, value.schema == "zenith.resource-owner-challenge.v1",
      ownerHex(value.claimID, 32), ownerHex(value.nonce, 64), now <= 9_007_199_254_740_991,
      value.issuedAt <= now, now < value.expiresAt, value.expiresAt <= 9_007_199_254_740_991,
      value.expiresAt - value.issuedAt <= 120,
      value.adminGrant.schema == "zenith.resource-admin-grant.v1", ownerHex(value.adminGrant.grantID, 64),
      ownerHex(value.adminGrant.holderPublicKey, 64), value.adminGrant.resourceID == binding.resourceID,
      value.adminGrant.operations == ["access.inbox", "access.review", "access.decide", "access.status"],
      value.adminGrant.validity.mode == "until_revoked", !value.adminGrant.onwardDelegation
    else { throw OwnerSetupError.changed }
    return value
  }
  public func encoded() throws -> Data {
    let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    return try encoder.encode(self)
  }
  public func validateProof(_ data: Data) throws {
    let raw = try ownerObject(data)
    try ownerKeys(raw, ["schema", "challenge", "signature"])
    guard raw["schema"] as? String == "zenith.resource-owner-proof.v1",
      let signature = raw["signature"] as? String, ownerHex(signature, 128),
      let challenge = raw["challenge"], try ownerCanonical(challenge) == encoded(),
      let publicKey = ownerBytes(adminGrant.holderPublicKey), let bytes = ownerBytes(signature)
    else { throw OwnerSetupError.changed }
    let key = try Curve25519.Signing.PublicKey(rawRepresentation: publicKey)
    var message = Data("zenith/resource-owner-approval/v1\0".utf8); message.append(try encoded())
    guard key.isValidSignature(bytes, for: message) else { throw OwnerSetupError.invalid }
  }
}

/// Exact native review plus a lifecycle ticket. No generic signing fallback.
public struct ResourceOwnerConsent: Identifiable, Sendable {
  let token: String
  public let challenge: ResourceOwnerChallenge
  let lifecycle: UInt64
  public var id: String { token }
  static func decode(_ data: Data, challenge: ResourceOwnerChallenge, lifecycle: UInt64) throws -> Self {
    let value = try ownerObject(data)
    try ownerKeys(value, ["token", "summary"])
    guard let token = value["token"] as? String, ownerHex(token, 32),
      let summary = value["summary"] as? [String: Any],
      let c = try JSONSerialization.jsonObject(with: challenge.encoded()) as? [String: Any]
    else { throw OwnerSetupError.invalid }
    let expected: [String: Any] = ["kind":"first_resource_administrator", "native_protocol":"zenith.resource-owner.v1",
      "binding":c["binding"]!, "admin_grant":c["admin_grant"]!, "claim_id":challenge.claimID,
      "expires_at":challenge.expiresAt, "setup_authorization_consumed_on_activation":true]
    guard try ownerCanonical(summary) == ownerCanonical(expected) else { throw OwnerSetupError.changed }
    return Self(token: token, challenge: challenge, lifecycle: lifecycle)
  }
}

private func ownerObject(_ data: Data) throws -> [String: Any] {
  var checked = OwnerPlanJSON(data, maximumBytes: 16384, maximumKeys: 100, maximumArray: 16, maximumDepth: 8)
  try checked.validate()
  guard let value = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw OwnerSetupError.invalid }
  return value
}
private func ownerCanonical(_ value: Any) throws -> Data {
  try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys, .withoutEscapingSlashes])
}
private func ownerKeys(_ value: Any?, _ keys: Set<String>) throws {
  guard let object = value as? [String: Any], Set(object.keys) == keys else { throw OwnerSetupError.invalid }
}
private func ownerHex(_ value: String, _ length: Int) -> Bool {
  value.utf8.count == length && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
}
private func ownerBytes(_ text: String) -> Data? {
  var result = Data(); var index = text.startIndex
  while index < text.endIndex {
    let next = text.index(index, offsetBy: 2, limitedBy: text.endIndex) ?? text.endIndex
    guard let byte = UInt8(text[index..<next], radix: 16) else { return nil }
    result.append(byte); index = next
  }
  return result
}
#endif
