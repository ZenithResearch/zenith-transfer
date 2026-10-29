#if os(macOS)
import Foundation

/// Trusted local DevGraph broker. No HTTP endpoint, profile, runtime or pin is
/// accepted from the model. This adapter owns no session key and never invokes
/// the owner-bootstrap provider if member exchange fails.
actor LocalHolderSessionIssuer: HolderSessionIssuer {
  private let process: SessionProviderProcess
  private let clientID: String
  private let pin: HolderIssuerPin
  private let context: HolderSessionContext
  private let clock: @Sendable () -> UInt64
  init(process: SessionProviderProcess, clientID: String, pin: HolderIssuerPin,
    context: HolderSessionContext, clock: @escaping @Sendable () -> UInt64 = { UInt64(Date().timeIntervalSince1970) }) throws {
    _ = try HS.hex(clientID, 32)
    self.process = process; self.clientID = clientID; self.pin = pin; self.context = context; self.clock = clock
  }
  func services() async throws -> [HolderSessionBrokerWire.Service] {
    try HolderSessionBrokerWire.services(await process.exchangeHolder(clientID: clientID, command: .services), pin: pin, context: context)
  }
  func prepare(_ body: HolderSessionPrivatePayload) async throws -> Data {
    let input = try HS.object(body.bytes)
    guard input["origin"] as? String == context.origin, input["audience"] as? String == context.audience,
      let root = input["parent_grant"] as? [String: Any], let claims = root["claims"] as? [String: Any],
      claims["service"] as? String == pin.service, claims["issuer"] as? String == pin.issuer,
      claims["key_id"] as? String == pin.key_id else { throw HolderSessionError.changed }
    let value = try await process.exchangeHolder(clientID: clientID, command: .prepare(body))
    let challenge = try HolderSessionBrokerWire.challengeData(value), c = try HS.object(challenge)
    try bound(c)
    return challenge // Flow compares the full key, installation, scope and expiry intent.
  }
  func exchange(_ authorization: HolderSessionPrivatePayload, challenge: HolderSessionChallenge) async throws -> HolderSessionExchangeResult {
    try bound(challenge)
    let value = try await process.exchangeHolder(clientID: clientID, command: .exchange(authorization))
    return try HolderSessionBrokerWire.outcome(value, challenge: challenge, now: clock())
  }
  func status(_ proof: Data, challenge: HolderSessionChallenge) async throws -> HolderSessionExchangeResult {
    try bound(challenge)
    let p = try HS.object(proof)
    guard p["request_id"] as? String == challenge.intent.requestID, p["challenge_id"] as? String == challenge.challengeID else { throw HolderSessionError.changed }
    let value = try await process.exchangeHolder(clientID: clientID, command: .status(proof))
    return try HolderSessionBrokerWire.outcome(value, challenge: challenge, now: clock())
  }
  func execute(_ presentation: Data) async throws -> Data {
    let p = try HS.object(presentation)
    guard let credential = p["credential"] as? [String: Any], let claims = credential["claims"] as? [String: Any],
      let challenge = claims["challenge"] as? [String: Any], let call = p["call"] as? [String: Any],
      let operation = call["operation"] as? String else { throw HolderSessionError.invalid }
    try bound(challenge)
    let value = try await process.exchangeHolder(clientID: clientID, command: .execute(presentation))
    return try HolderSessionBrokerWire.businessResult(value, service: pin.service, operation: operation)
  }
  private func bound(_ challenge: HolderSessionChallenge) throws {
    guard challenge.intent.parent.pin == pin, challenge.intent.context == context else { throw HolderSessionError.changed }
  }
  private func bound(_ c: [String: Any]) throws {
    guard c["issuer"] as? String == pin.issuer, c["key_id"] as? String == pin.key_id,
      c["service"] as? String == pin.service, c["origin"] as? String == context.origin,
      c["audience"] as? String == context.audience else { throw HolderSessionError.changed }
  }
}
#endif
