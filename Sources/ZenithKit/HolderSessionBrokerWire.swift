#if os(macOS)
import Foundation

/// The broker owns routing/exchange, never temporary key custody. The closed
/// command set intentionally has no owner, renewal, expiry-edit or close tool.
enum HolderSessionBrokerCommand: Sendable {
  case services
  case prepare(HolderSessionPrivatePayload)
  case exchange(HolderSessionPrivatePayload)
  case status(Data)
  case execute(Data)

  var operation: String {
    switch self {
    case .services: return "services"
    case .prepare: return "prepare"
    case .exchange: return "exchange"
    case .status: return "status"
    case .execute: return "execute"
    }
  }
  func arguments() throws -> Data {
    let value: [String: Any]
    switch self {
    case .services: value = [:]
    case .prepare(let body):
      let object = try HS.object(body.bytes)
      guard object["schema"] as? String == "secs.holder-session-prepare.v1" else { throw HolderSessionError.invalid }
      value = ["body": object]
    case .exchange(let authorization):
      let object = try HS.object(authorization.bytes)
      guard object["schema"] as? String == "secs.holder-session-authorization.v1" else { throw HolderSessionError.invalid }
      value = ["authorization": object]
    case .status(let proof):
      let object = try HS.object(proof)
      try HS.keys(object, "schema request_id challenge_id nonce issued_at expires_at signature")
      guard object["schema"] as? String == "secs.holder-session-status.v1" else { throw HolderSessionError.invalid }
      value = ["proof": object]
    case .execute(let presentation):
      let object = try HS.object(presentation); try HS.keys(object, "credential call proof")
      value = ["presentation": object]
    }
    return try HS.encode(value)
  }
}

enum HolderSessionBrokerWire {
  struct Service: Sendable {
    let service: String, name: String
    let maximumTTL: UInt64
  }
  static func services(_ data: Data, pin: HolderIssuerPin, context: HolderSessionContext) throws -> [Service] {
    let result = try HS.object(data); try HS.keys(result, "schema services")
    guard result["schema"] as? String == "devgraph.holder-session-services.v1",
      let services = result["services"] as? [[String: Any]], services.count <= 1 else { throw HolderSessionError.invalid }
    return try services.map { value in
      try HS.keys(value, "service name issuer_pin context grant_schemas read_only max_ttl_seconds")
      guard value["service"] as? String == pin.service, try HS.pin(value["issuer_pin"]) == pin,
        let c = value["context"] as? [String: Any], c["origin"] as? String == context.origin,
        c["audience"] as? String == context.audience, value["grant_schemas"] as? [String] == ["secs.holder-grant.v2"],
        try HS.boolean(value["read_only"]), let name = value["name"] as? String else { throw HolderSessionError.changed }
      try HS.keys(c, "origin audience"); try HS.text(name, maximum: 80)
      let limit = try HS.integer(value["max_ttl_seconds"])
      guard limit > 0, limit <= 3600 else { throw HolderSessionError.invalid }
      // This profile declares read-only, but the issuer/receiver still owns the
      // trusted operation catalogue. Do not infer operations from this Boolean.
      return Service(service: pin.service, name: name, maximumTTL: limit)
    }
  }
  static func challengeData(_ data: Data) throws -> Data {
    let result = try HS.object(data); try HS.keys(result, "schema challenge")
    guard result["schema"] as? String == "secs.holder-session-challenge-result.v1" else { throw HolderSessionError.invalid }
    return try HS.encode(result["challenge"]!)
  }
  static func challenge(_ data: Data, intent: HolderSessionPrepareIntent, now: UInt64) throws -> HolderSessionChallenge {
    try .decode(challengeData(data), intent: intent, now: now)
  }
  static func outcome(_ data: Data, challenge: HolderSessionChallenge, now: UInt64) throws -> HolderSessionExchangeResult {
    let result = try HS.object(data); try HS.keys(result, "schema request_id challenge_id state credential expires_at")
    guard result["schema"] as? String == "secs.holder-session-result.v1",
      result["request_id"] as? String == challenge.intent.requestID,
      result["challenge_id"] as? String == challenge.challengeID,
      try HS.integer(result["expires_at"]) == challenge.expiresAt else { throw HolderSessionError.changed }
    if result["state"] as? String == "issued" {
      let token = try HolderSessionCredential.decode(HS.encode(result["credential"]!), challenge: challenge, now: now)
      return .issued(token.data)
    }
    guard result["credential"] is NSNull else { throw HolderSessionError.invalid }
    switch result["state"] as? String {
    case "pending": return .unknown // No automatic resubmission of possible dispatch.
    case "revoked": return .revoked
    case "expired": return .expired
    default: throw HolderSessionError.invalid
    }
  }
  static func businessResult(_ data: Data, service: String, operation: String) throws -> Data {
    let result = try HS.object(data); try HS.keys(result, "schema service operation result")
    guard result["schema"] as? String == "devgraph.holder-session-call-result.v1",
      result["service"] as? String == service, result["operation"] as? String == operation else { throw HolderSessionError.changed }
    return try HS.encode(result["result"]!)
  }
}
#endif
