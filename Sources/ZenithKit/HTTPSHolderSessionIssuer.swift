import Foundation

/// Public metadata is compared with the saved service pin before any Wallet
/// identity or parent is sent. Access-point URLs never become issuer authority.
public struct HolderSessionCapabilities: Sendable {
  public let provider: HolderIssuerPin, maximumLifetime: UInt64
  public let context: HolderSessionContext
  let challengePath: String, exchangePath: String, statusPath: String
  public static func decode(_ data: Data, configuration: WorkAccessConfiguration, origin: String) throws -> Self? {
    let v = try HS.object(data)
    try HS.keys(v, "schema supported profile issuer_pin audience grant_schemas credential_schema presentation_schema read_only max_ttl_seconds review_ttl_seconds proof_max_ttl_seconds challenge_path exchange_path status_path")
    let pin = try HS.pin(v["issuer_pin"]), maximum = try HS.integer(v["max_ttl_seconds"])
    guard v["schema"] as? String == "secs.holder-session-capabilities.v1", v["profile"] as? String == "secs.holder-session.v1",
      v["audience"] as? String == "devgraph", v["grant_schemas"] as? [String] == ["secs.holder-grant.v2"],
      v["credential_schema"] as? String == "secs.holder-session-credential.v1", v["presentation_schema"] as? String == "secs.holder-session-presentation.v1",
      try HS.boolean(v["read_only"]), maximum > 0, maximum <= 3600,
      try HS.integer(v["review_ttl_seconds"]) == 120, try HS.integer(v["proof_max_ttl_seconds"]) == 60,
      pin.issuer == configuration.issuer, pin.key_id == configuration.authority.key_id, pin.public_key == configuration.authority.public_key,
      configuration.serviceID.map({ $0 == pin.service }) ?? true else { throw HolderSessionError.changed }
    let prefix = (configuration.service_access_point?.claims.prefix ?? "") + "/holder-sessions/v1"
    guard v["challenge_path"] as? String == prefix + "/challenges", v["exchange_path"] as? String == prefix + "/exchange",
      v["status_path"] as? String == prefix + "/status" else { throw HolderSessionError.changed }
    guard try HS.boolean(v["supported"]) else { return nil }
    return try Self(provider: pin, maximumLifetime: maximum, context: .init(origin: origin, audience: "devgraph"),
      challengePath: prefix + "/challenges", exchangePath: prefix + "/exchange", statusPath: prefix + "/status")
  }
  public var custodyProfile: Data { get throws {
    try HS.encode(["schema": "castalia.holder-session-agent-profile.v1", "provider": JSONSerialization.jsonObject(with: JSONEncoder().encode(provider)),
      "context": JSONSerialization.jsonObject(with: JSONEncoder().encode(context)), "maximum_session_seconds": maximumLifetime])
  } }
}
public actor HTTPSHolderSessionIssuer: HolderSessionIssuer {
  private let transport: PrivateTransport
  private let configuration: WorkAccessConfiguration
  private let capabilities: HolderSessionCapabilities
  public init(transport: PrivateTransport, configuration: WorkAccessConfiguration, capabilities: HolderSessionCapabilities) {
    self.transport = transport; self.configuration = configuration; self.capabilities = capabilities
  }
  public static func discover(transport: PrivateTransport, configuration: WorkAccessConfiguration, origin: String = "app://zenith-ios") async throws -> HolderSessionCapabilities? {
    let reply = try await transport.exchange(URLRequest(url: configuration.apiURL("/holder-sessions/v1/capabilities")), maximum: 16384)
    if reply.status == 404 { return nil }
    guard reply.status == 200 else { throw HolderSessionError.unsupported }
    return try .decode(reply.data, configuration: configuration, origin: origin)
  }
  private func post(_ path: String, body: Data) async throws -> Data {
    // Discovered paths include the access prefix already. Do not prefix twice.
    guard path.hasPrefix("/"), !path.hasPrefix("//"), let url = URL(string: configuration.origin + path) else { throw HolderSessionError.invalid }
    var request = URLRequest(url: url); request.httpMethod = "POST"; request.httpBody = body
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    request.setValue(capabilities.context.origin, forHTTPHeaderField: "Origin")
    return try await transport.request(request, maximum: 131072, viewChangedOnConflict: true)
  }
  public func prepare(_ body: HolderSessionPrivatePayload) async throws -> Data {
    let v = try HS.object(body.bytes)
    guard v["origin"] as? String == capabilities.context.origin, v["audience"] as? String == capabilities.context.audience else { throw HolderSessionError.changed }
    return try HolderSessionBrokerWire.challengeData(await post(capabilities.challengePath, body: body.bytes))
  }
  public func exchange(_ authorization: HolderSessionPrivatePayload, challenge: HolderSessionChallenge) async throws -> HolderSessionExchangeResult {
    try check(challenge)
    return try HolderSessionBrokerWire.outcome(await post(capabilities.exchangePath, body: authorization.bytes), challenge: challenge, now: UInt64(Date().timeIntervalSince1970))
  }
  public func status(_ proof: Data, challenge: HolderSessionChallenge) async throws -> HolderSessionExchangeResult {
    try check(challenge)
    return try HolderSessionBrokerWire.outcome(await post(capabilities.statusPath, body: proof), challenge: challenge, now: UInt64(Date().timeIntervalSince1970))
  }
  public func execute(_ presentation: Data) async throws -> Data {
    let v = try HS.object(presentation)
    guard let token = v["credential"] as? [String: Any], let claims = token["claims"] as? [String: Any],
      let c = claims["challenge"] as? [String: Any], c["service"] as? String == capabilities.provider.service,
      c["origin"] as? String == capabilities.context.origin else { throw HolderSessionError.changed }
    let data = try await post((configuration.service_access_point?.claims.prefix ?? "") + "/monitor/wallet-access/v1/requests", body: presentation)
    // Existing native-read envelope is validated by DevgraphReadClient.
    return data
  }
  private func check(_ c: HolderSessionChallenge) throws {
    guard c.intent.parent.pin == capabilities.provider, c.intent.context == capabilities.context else { throw HolderSessionError.changed }
  }
}
