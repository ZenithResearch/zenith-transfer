import CryptoKit
import Foundation

public struct HolderSessionAgentProfile: Sendable {
  public let provider: HolderIssuerPin, context: HolderSessionContext
  public let maximumSessionSeconds: UInt64
  public static func decode(_ data: Data) throws -> Self {
    let v = try HS.object(data); try HS.keys(v, "schema provider context maximum_session_seconds")
    guard v["schema"] as? String == "castalia.holder-session-agent-profile.v1",
      let context = v["context"] as? [String: Any], let origin = context["origin"] as? String,
      let audience = context["audience"] as? String else { throw HolderSessionError.invalid }
    try HS.keys(context, "origin audience")
    let maximum = try HS.integer(v["maximum_session_seconds"])
    guard maximum > 0, maximum <= 3600 else { throw HolderSessionError.invalid }
    return try Self(provider: HS.pin(v["provider"]), context: .init(origin: origin, audience: audience), maximumSessionSeconds: maximum)
  }
}

/// Private helper protocol only. There is no model-selected command, signing
/// seed, parent-grant import or owner operation in this closed enum.
public enum HolderSessionAgentCommand: Sendable {
  case create(expiresAt: UInt64)
  case possession(session: String, challenge: HolderSessionChallenge)
  case install(session: String, credential: HolderSessionCredential)
  case present(session: String, credential: HolderSessionCredential, call: Data)
  case status(session: String, challenge: HolderSessionChallenge)
  case close(session: String)

  func body() throws -> [String: Any] {
    if case .create(let end) = self {
      _ = try HS.integer(NSNumber(value: end))
      return ["operation": "create_session", "expires_at": end]
    }
    let handle: String
    switch self {
    case .possession(let value, _), .install(let value, _), .present(let value, _, _), .status(let value, _), .close(let value): handle = value
    case .create: throw HolderSessionError.invalid
    }
    _ = try HS.hex(handle, 32)
    var body: [String: Any] = ["session_handle": handle]
    switch self {
    case .possession(_, let c): body["operation"] = "prove_possession"; body["challenge"] = try HS.object(c.data)
    case .install(_, let token):
      body["operation"] = "install_credential"; body["credential"] = try HS.object(token.data)
      body["reviewed_challenge"] = try HS.object(token.challenge.data)
    case .present(_, _, let data):
      let call = try HS.object(data); try HS.keys(call, "operation resource parameters")
      guard let op = call["operation"] as? String, let resource = call["resource"] as? String, call["parameters"] is [String: Any] else { throw HolderSessionError.invalid }
      try HS.text(op); try HS.text(resource, maximum: 2048)
      body["operation"] = "present_call"; body["call"] = call
    case .status(_, let c): body["operation"] = "status_proof"; body["challenge"] = try HS.object(c.data)
    case .close: body["operation"] = "close_session"
    case .create: throw HolderSessionError.invalid
    }
    return body
  }
}

public enum HolderSessionAgentWire {
  public static func request(_ command: HolderSessionAgentCommand, requestID: String) throws -> Data {
    _ = try HS.hex(requestID, 32)
    let data = try HS.encode(["schema": "castalia.holder-session-agent-command.v1", "request_id": requestID, "body": command.body()])
    // Reserve the terminating newline inside the producer's frame budget.
    guard data.count < 131072 else { throw HolderSessionError.invalid }
    return data
  }
  /// Returns private verified helper data, never a model-facing result.
  public static func response(_ data: Data, requestID: String, command: HolderSessionAgentCommand,
    profile: HolderSessionAgentProfile, now: UInt64) throws -> Data {
    let reply = try HS.object(data)
    guard reply["schema"] as? String == "castalia.holder-session-agent-result.v1",
      reply["request_id"] as? String == requestID else { throw HolderSessionError.changed }
    let ok = try HS.boolean(reply["ok"])
    try HS.keys(reply, ok ? "schema request_id ok value" : "schema request_id ok error")
    guard ok else { throw HolderSessionError.invalid }
    guard let value = reply["value"] as? [String: Any] else { throw HolderSessionError.invalid }
    switch command {
    case .create(let end):
      guard end > now, end - now <= profile.maximumSessionSeconds else { throw HolderSessionError.expired }
      _ = try HolderSessionIdentity.decode(HS.encode(value), service: profile.provider.service, expiresAt: end)
    case .possession(_, let c):
      try bound(c, profile)
      try HS.keys(value, "session_signature challenge_digest")
      guard value["challenge_digest"] as? String == c.digest, now < c.reviewDeadline else { throw HolderSessionError.changed }
      try verifySignature(value["session_signature"], key: c.intent.session.publicKey,
        domain: "secs.holder-session-possession.v1/signature", value: HS.object(c.data))
    case .install(_, let token):
      try bound(token.challenge, profile); try HS.keys(value, "installed expires_at")
      guard try HS.boolean(value["installed"]), try HS.integer(value["expires_at"]) == token.challenge.expiresAt,
        now < token.challenge.expiresAt else { throw HolderSessionError.changed }
    case .present(_, let token, let call):
      let c = token.challenge; try bound(c, profile)
      try HS.keys(value, "credential call proof")
      guard try HS.encode(value["credential"]!) == token.data,
        try HS.encode(value["call"]!) == HS.encode(HS.object(call)), let proof = value["proof"] as? [String: Any]
      else { throw HolderSessionError.changed }
      try HS.keys(proof, "schema credential_digest call_digest nonce issued_at expires_at signature")
      guard proof["schema"] as? String == "secs.holder-session-presentation.v1",
        proof["credential_digest"] as? String == token.digest,
        try proof["call_digest"] as? String == HS.digest(HS.encode(HS.object(call))) else { throw HolderSessionError.changed }
      try proofBounds(proof, c, now)
      var unsigned = proof; unsigned.removeValue(forKey: "signature")
      try verifySignature(proof["signature"], key: c.intent.session.publicKey,
        domain: "secs.holder-session-presentation.v1/signature", value: unsigned)
    case .status(_, let c):
      try bound(c, profile)
      try HS.keys(value, "schema request_id challenge_id nonce issued_at expires_at signature")
      guard value["schema"] as? String == "secs.holder-session-status.v1",
        value["request_id"] as? String == c.intent.requestID, value["challenge_id"] as? String == c.challengeID else { throw HolderSessionError.changed }
      try proofBounds(value, c, now)
      var unsigned = value; unsigned.removeValue(forKey: "signature")
      try verifySignature(value["signature"], key: c.intent.session.publicKey,
        domain: "secs.holder-session-status.v1/signature", value: unsigned)
    case .close:
      try HS.keys(value, "closed server_revocation_confirmed")
      guard try HS.boolean(value["closed"]), try !HS.boolean(value["server_revocation_confirmed"]) else { throw HolderSessionError.changed }
    }
    return try HS.encode(value)
  }
  private static func bound(_ c: HolderSessionChallenge, _ p: HolderSessionAgentProfile) throws {
    guard c.intent.parent.pin == p.provider, c.intent.context == p.context else { throw HolderSessionError.changed }
  }
  private static func proofBounds(_ value: [String: Any], _ c: HolderSessionChallenge, _ now: UInt64) throws {
    _ = try HS.hex(value["nonce"], 32)
    let start = try HS.integer(value["issued_at"]), end = try HS.integer(value["expires_at"])
    guard start >= c.issuedAt, start <= now, now < end, end <= min(start + 60, c.expiresAt) else { throw HolderSessionError.expired }
  }
  private static func verifySignature(_ signature: Any?, key: String, domain: String, value: [String: Any]) throws {
    let signature = try HS.hex(signature, 128)
    var transcript = Data((domain + "\0").utf8); transcript.append(try HS.encode(value))
    let publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: HS.unhex(key))
    guard publicKey.isValidSignature(try HS.unhex(signature), for: transcript) else { throw HolderSessionError.invalid }
  }
}
