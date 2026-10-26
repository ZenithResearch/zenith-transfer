import CryptoKit
import Foundation

/// A public provider signature authenticates a route, never member authority.
public struct ServiceAccessPoint: Codable, Hashable, Sendable {
  public struct Claims: Codable, Hashable, Sendable {
    public let schema: String
    public let issuer: String
    public let key_id: String
    public let service: String
    public let origin: String
    public let authority_receiver: String
    public let prefix: String
    public let not_before: UInt64
    public let not_after: UInt64
  }
  public let claims: Claims
  public let signature: String
  public func verify(configuration: WorkAccessConfiguration, now: UInt64? = nil) throws {
    let c = claims
    guard c.schema == "secs.service-access-point.v1", c.issuer == configuration.issuer,
      c.key_id == configuration.authority.key_id, c.origin == configuration.origin,
      c.prefix == "/service/v1", !c.service.isEmpty, c.service.utf8.count <= 256,
      c.not_before < c.not_after, c.not_after <= 9_007_199_254_740_991,
      c.not_after - c.not_before <= 604800,
      try WorkServerSettings.address(c.authority_receiver).absoluteString == c.authority_receiver,
      signature.range(of: "^[0-9a-f]{128}$", options: .regularExpression) != nil
    else { throw WalletFailure.core("invalid_service_binding") }
    if let now, now < c.not_before || now >= c.not_after { throw WalletFailure.core("service_binding_expired") }
    let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    var transcript = Data("secs.service-access-point.v1\0".utf8); transcript.append(try encoder.encode(c))
    func bytes(_ value: String) throws -> Data {
      guard value.count % 2 == 0 else { throw WalletFailure.invalidFile }
      var result = Data(); var index = value.startIndex
      while index != value.endIndex {
        let next = value.index(index, offsetBy: 2)
        guard let byte = UInt8(value[index..<next], radix: 16) else { throw WalletFailure.invalidFile }
        result.append(byte); index = next
      }
      return result
    }
    let key = try Curve25519.Signing.PublicKey(rawRepresentation: bytes(configuration.authority.public_key))
    guard key.isValidSignature(try bytes(signature), for: transcript) else { throw WalletFailure.core("invalid_service_binding") }
  }
  public static func decode(_ data: Data, configuration: WorkAccessConfiguration) throws -> Self {
    var strict = AccountRecordJSON(data, maximumBytes: 16384, maximumDepth: 8); try strict.validate()
    guard data.count <= 16384,
      let raw = try JSONSerialization.jsonObject(with: data) as? [String:Any],
      Set(raw.keys) == ["schema", "binding"], raw["schema"] as? String == "devgraph.service-access-point.v1",
      let binding = raw["binding"] as? [String:Any], Set(binding.keys) == ["claims", "signature"],
      let claims = binding["claims"] as? [String:Any],
      Set(claims.keys) == ["schema","issuer","key_id","service","origin","authority_receiver","prefix","not_before","not_after"]
    else { throw WalletFailure.core("invalid_service_binding") }
    let value = try JSONDecoder().decode(Self.self, from: JSONSerialization.data(withJSONObject: binding))
    try value.verify(configuration: configuration, now: UInt64(Date().timeIntervalSince1970)); return value
  }
}

public extension WorkAccessConfiguration {
  var authorityOrigin: String { service_access_point?.claims.authority_receiver ?? origin }
  var serviceID: String? { service_access_point?.claims.service }
  // Retain the canonical authority's existing journal namespace. Transport
  // aliases never create a second request or relabel an original signed action.
  var authorityJournalKey: String { authorityOrigin }
  var credentialAuthority: ReadAuthorityPin {
    ReadAuthorityPin(issuer: authority.issuer, key_id: authority.key_id, public_key: authority.public_key, receiver: authorityOrigin, audience: authority.audience)
  }
  func apiURL(_ path: String) throws -> URL {
    if let binding = service_access_point { try binding.verify(configuration: self, now: UInt64(Date().timeIntervalSince1970)) }
    guard path.hasPrefix("/"), !path.hasPrefix("//"), let url = URL(string: origin + (service_access_point?.claims.prefix ?? "") + path) else { throw WalletFailure.core("invalid_service_path") }
    return url
  }
  func withServiceAccessPoint(_ value: ServiceAccessPoint?) throws -> Self {
    try Self(name: name, receiver: receiver, issuer: issuer, keyID: authority.key_id, publicKey: authority.public_key, network: network, tlsCertificateSHA256: tls_certificate_sha256, serviceAccessPoint: value)
  }
  /// Only a missing protocol (404) permits legacy negotiation. A bad signature
  /// or unavailable canonical service must never silently select another inbox.
  func resolveService(transport: PrivateTransport) async throws -> Self {
#if os(macOS)
    if LocalAdminRPC.hasRegisteredService(configuration: self) {
      let rpc = try LocalAdminRPC.discover(configuration: self)
      let inspected = try await rpc.call(operation: "inspect", body: Data("{}".utf8))
      guard inspected.status == 200,
        let value = try JSONSerialization.jsonObject(with: inspected.data) as? [String:Any] else { throw LocalAdminRPCError.changed }
      guard let binding = value["service_access_point"] else { return try withServiceAccessPoint(nil) }
      let wrapper: [String:Any] = ["schema":"devgraph.service-access-point.v1", "binding":binding]
      return try withServiceAccessPoint(ServiceAccessPoint.decode(JSONSerialization.data(withJSONObject: wrapper), configuration: self))
    }
#endif
    let response = try await transport.exchange(URLRequest(url: receiver.appendingPathComponent(".well-known/devgraph-service.json")), maximum: 16384)
    if response.status == 404 { return try withServiceAccessPoint(nil) }
    guard response.status == 200 else { throw WalletFailure.core("service_binding_unavailable") }
    return try withServiceAccessPoint(ServiceAccessPoint.decode(response.data, configuration: self))
  }
}
