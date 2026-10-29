import CoreFoundation
import CryptoKit
import Foundation

/// Qualified native consumer integration for the exact compiled Core revision.
public enum HolderSessionIntegration {
  public static let qualified = true
  public static let coreRevision = "72ed5cd36ef0d8a96a64d80d51eb12db1f4e411d"
}
public enum HolderSessionError: Error { case unsupported, invalid, changed, expired, unsafeHelperProfile, custodyLost }

/// Trusted caller context, separate from the service's network receiver origin.
public struct HolderSessionContext: Codable, Sendable, Equatable {
  public let origin: String
  public let audience: String
  public init(origin: String, audience: String) throws {
    try HS.text(origin, maximum: 2048); try HS.text(audience)
    self.origin = origin; self.audience = audience
  }
}

public struct HolderSessionIdentity: Sendable, Equatable {
  public let handle: String, publicKey: String, installationID: String, service: String
  public let maximumExpiresAt: UInt64
  public static func decode(_ data: Data, service: String, expiresAt: UInt64) throws -> Self {
    let v = try HS.object(data)
    try HS.keys(v, "session_handle session_public_key session_installation_id maximum_expires_at service")
    let end = try HS.integer(v["maximum_expires_at"])
    guard end == expiresAt, v["service"] as? String == service else { throw HolderSessionError.changed }
    return try Self(handle: HS.hex(v["session_handle"], 32), publicKey: HS.hex(v["session_public_key"], 64),
      installationID: HS.hex(v["session_installation_id"], 32), service: service, maximumExpiresAt: end)
  }
}

/// Public references only; the reusable grant never belongs in this value.
public struct HolderSessionParentReference: Sendable {
  public let pin: HolderIssuerPin
  public let grantID: String, digest: String, revision: String, holderPublicKey: String, installationID: String
  public let notBefore: UInt64, notAfter: UInt64?, maximumCredentialLifetime: UInt64
  public static func decode(_ data: Data, service: String, now: UInt64) throws -> Self {
    let v = try HS.object(data)
    try HS.keys(v, "schema issuer_pin service parent_grant_id parent_grant_digest parent_revision holder_public_key installation_id validity max_credential_lifetime_seconds")
    guard v["schema"] as? String == "castalia.holder-session-parent-reference.v1",
      v["service"] as? String == service, let validity = v["validity"] as? [String: Any]
    else { throw HolderSessionError.invalid }
    let pin = try HS.pin(v["issuer_pin"])
    guard pin.service == service else { throw HolderSessionError.changed }
    guard validity["schema"] as? String == "castalia.grant-validity.v1" else { throw HolderSessionError.invalid }
    let start = try HS.integer(validity["not_before"]), end: UInt64?
    switch validity["mode"] as? String {
    case "dated": try HS.keys(validity, "schema mode not_before not_after"); end = try HS.integer(validity["not_after"])
    case "until_revoked": try HS.keys(validity, "schema mode not_before"); end = nil
    default: throw HolderSessionError.invalid
    }
    let maximum = try HS.integer(v["max_credential_lifetime_seconds"])
    guard now >= start, end.map({ now < $0 }) ?? true, maximum > 0, maximum <= 3600 else { throw HolderSessionError.expired }
    return try Self(pin: pin, grantID: HS.hex(v["parent_grant_id"], 32), digest: HS.hex(v["parent_grant_digest"], 64),
      revision: HS.hex(v["parent_revision"], 64), holderPublicKey: HS.hex(v["holder_public_key"], 64),
      installationID: HS.hex(v["installation_id"], 32), notBefore: start, notAfter: end, maximumCredentialLifetime: maximum)
  }
}

public struct HolderSessionPrepareIntent: Sendable {
  public let parent: HolderSessionParentReference, session: HolderSessionIdentity, context: HolderSessionContext
  public let requestID: String, requestedTTL: UInt64
  public let permissions: Data?
  public init(parent: HolderSessionParentReference, session: HolderSessionIdentity, context: HolderSessionContext,
    requestID: String, requestedTTL: UInt64, permissions: Data? = nil) throws {
    _ = try HS.hex(requestID, 32)
    guard session.service == parent.pin.service, session.publicKey != parent.holderPublicKey,
      requestedTTL > 0, requestedTTL <= 3600 else { throw HolderSessionError.invalid }
    if let permissions { try HS.permissions(HS.value(permissions)) }
    self.parent = parent; self.session = session; self.context = context; self.requestID = requestID
    self.requestedTTL = requestedTTL; self.permissions = try permissions.map { try HS.encode(HS.value($0)) }
  }
}

/// An unsigned, exactly bound review snapshot. Only typed Core approval can
/// authorize it; this parser does not replace signature or parent verification.
public struct HolderSessionChallenge: Sendable {
  public let data: Data, digest: String
  public let intent: HolderSessionPrepareIntent
  public let challengeID: String, issuedAt: UInt64, reviewDeadline: UInt64, expiresAt: UInt64
  public let permissions: [HolderGrantPermission]
  public var permissionData: Data { get throws { try HS.encode(HS.object(data)["permissions"]!) } }
  public static func decode(_ data: Data, intent: HolderSessionPrepareIntent, now: UInt64, retained: Bool = false) throws -> Self {
    let v = try HS.object(data), parent = intent.parent, session = intent.session
    try HS.keys(v, "schema challenge_id request_id nonce issuer key_id service audience origin parent_grant_id parent_grant_digest parent_revision holder_public_key installation_id session_installation_id session_public_key permissions issued_at review_deadline expires_at")
    guard v["schema"] as? String == "secs.holder-session-challenge.v1",
      v["request_id"] as? String == intent.requestID,
      v["issuer"] as? String == parent.pin.issuer, v["key_id"] as? String == parent.pin.key_id,
      v["service"] as? String == parent.pin.service, v["origin"] as? String == intent.context.origin,
      v["audience"] as? String == intent.context.audience, v["parent_grant_id"] as? String == parent.grantID,
      v["parent_grant_digest"] as? String == parent.digest, v["parent_revision"] as? String == parent.revision,
      v["holder_public_key"] as? String == parent.holderPublicKey,
      v["installation_id"] as? String == parent.installationID,
      v["session_public_key"] as? String == session.publicKey,
      v["session_installation_id"] as? String == session.installationID
    else { throw HolderSessionError.changed }
    _ = try HS.hex(v["nonce"], 64)
    let id = try HS.hex(v["challenge_id"], 32), issued = try HS.integer(v["issued_at"])
    let deadline = try HS.integer(v["review_deadline"]), end = try HS.integer(v["expires_at"])
    guard issued <= now, issued >= parent.notBefore, retained || now < deadline, now < end,
      deadline == min(issued + 120, end),
      end <= min(session.maximumExpiresAt, issued + min(intent.requestedTTL, parent.maximumCredentialLifetime)),
      parent.notAfter.map({ end <= $0 }) ?? true else { throw HolderSessionError.expired }
    try HS.permissions(v["permissions"])
    let permissionsData = try HS.encode(v["permissions"]!)
    if let requested = intent.permissions, requested != permissionsData { throw HolderSessionError.changed }
    let canonical = try HS.encode(v)
    return Self(data: canonical, digest: HS.digest(canonical), intent: intent, challengeID: id,
      issuedAt: issued, reviewDeadline: deadline, expiresAt: end,
      permissions: try JSONDecoder().decode([HolderGrantPermission].self, from: permissionsData))
  }
}

/// Finite issuer token only. Verification does not establish current parent
/// policy/revocation, which remains a receiver obligation on every request.
public struct HolderSessionCredential: Sendable {
  public let data: Data, credentialID: String, digest: String
  public let challenge: HolderSessionChallenge
  public static func decode(_ data: Data, challenge: HolderSessionChallenge, now: UInt64) throws -> Self {
    guard now >= challenge.issuedAt, now < challenge.expiresAt else { throw HolderSessionError.expired }
    let value = try HS.object(data); try HS.keys(value, "claims signature")
    guard let claims = value["claims"] as? [String: Any] else { throw HolderSessionError.invalid }
    try HS.keys(claims, "schema credential_id challenge_digest challenge")
    guard claims["schema"] as? String == "secs.holder-session-credential.v1",
      claims["challenge_digest"] as? String == challenge.digest,
      try HS.encode(claims["challenge"]!) == challenge.data else { throw HolderSessionError.changed }
    let id = try HS.hex(claims["credential_id"], 32), signature = try HS.hex(value["signature"], 128)
    let publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: HS.unhex(challenge.intent.parent.pin.public_key))
    var transcript = Data("secs.holder-session-credential.v1/signature\0".utf8)
    transcript.append(try HS.encode(claims))
    guard publicKey.isValidSignature(try HS.unhex(signature), for: transcript) else { throw HolderSessionError.invalid }
    let bytes = try HS.encode(value)
    return Self(data: bytes, credentialID: id, digest: HS.digest(bytes), challenge: challenge)
  }
}

/// One-use Core consent handle, deliberately not Codable or a journal entry.
public struct HolderSessionAuthorizationReview: Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
  public let challenge: HolderSessionChallenge, lifecycle: UInt64
  public let token: String
  public var description: String { "HolderSessionAuthorizationReview(<private consent handle>)" }
  public var debugDescription: String { description }
  public var customMirror: Mirror { Mirror(self, children: [:]) }
  public static func decode(_ data: Data, challenge: HolderSessionChallenge, lifecycle: UInt64, now: UInt64) throws -> Self {
    guard now < challenge.reviewDeadline else { throw HolderSessionError.expired }
    let v = try HS.object(data)
    try HS.keys(v, "token summary")
    guard let s = v["summary"] as? [String: Any] else { throw HolderSessionError.invalid }
    try HS.keys(s, "schema issuer_pin parent_grant_id parent_grant_digest parent_revision holder_public_key installation_id session_public_key session_installation_id origin audience permissions not_before expires_at review_deadline review_digest_sha256 hard_expiry onward_delegation")
    guard s["schema"] as? String == "castalia.holder-session-review.v1",
      try HS.pin(s["issuer_pin"]) == challenge.intent.parent.pin,
      s["review_digest_sha256"] as? String == challenge.digest,
      try HS.boolean(s["hard_expiry"]), try !HS.boolean(s["onward_delegation"]),
      try HS.integer(s["not_before"]) == challenge.issuedAt
    else { throw HolderSessionError.changed }
    let c = try HS.object(challenge.data)
    for key in ["parent_grant_id", "parent_grant_digest", "parent_revision", "holder_public_key", "installation_id", "session_public_key", "session_installation_id", "origin", "audience", "permissions", "expires_at", "review_deadline"] {
      guard try HS.encode(s[key]!) == HS.encode(c[key]!) else { throw HolderSessionError.changed }
    }
    return try Self(challenge: challenge, lifecycle: lifecycle, token: HS.hex(v["token"], 32))
  }
}

/// Root-containing Core output may be consumed only by a trusted private issuer
/// adapter in this module. No public bytes accessor, Codable or debug export.
public struct HolderSessionPrivatePayload: Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
  let bytes: Data
  public var description: String { "HolderSessionPrivatePayload(<redacted>)" }
  public var debugDescription: String { description }
  public var customMirror: Mirror { Mirror(self, children: [:]) }
  private init(_ bytes: Data) { self.bytes = bytes }
  public static func prepare(_ data: Data, intent: HolderSessionPrepareIntent) throws -> Self {
    let v = try HS.object(data); try HS.keys(v, "schema body")
    guard v["schema"] as? String == "castalia.holder-session-private-prepare.v1",
      let body = v["body"] as? [String: Any] else { throw HolderSessionError.invalid }
    try HS.keys(body, "schema request_id parent_grant installation_id session_public_key session_installation_id origin audience permissions requested_ttl_seconds")
    guard body["schema"] as? String == "secs.holder-session-prepare.v1",
      body["request_id"] as? String == intent.requestID,
      body["installation_id"] as? String == intent.parent.installationID,
      body["session_public_key"] as? String == intent.session.publicKey,
      body["session_installation_id"] as? String == intent.session.installationID,
      body["origin"] as? String == intent.context.origin, body["audience"] as? String == intent.context.audience,
      try HS.integer(body["requested_ttl_seconds"]) == min(intent.requestedTTL, intent.parent.maximumCredentialLifetime),
      try HS.digest(HS.encode(body["parent_grant"]!)) == intent.parent.digest,
      try HS.encode(body["permissions"]!) == (intent.permissions ?? Data("null".utf8))
    else { throw HolderSessionError.changed }
    return try Self(HS.encode(body))
  }
  public static func authorization(_ data: Data, review: HolderSessionAuthorizationReview, sessionSignature: String) throws -> Self {
    _ = try HS.hex(sessionSignature, 128)
    let v = try HS.object(data); try HS.keys(v, "schema challenge parent_grant holder_signature session_signature")
    guard v["schema"] as? String == "secs.holder-session-authorization.v1",
      try HS.encode(v["challenge"]!) == review.challenge.data,
      try HS.digest(HS.encode(v["parent_grant"]!)) == review.challenge.intent.parent.digest,
      v["session_signature"] as? String == sessionSignature else { throw HolderSessionError.changed }
    _ = try HS.hex(v["holder_signature"], 128)
    return try Self(HS.encode(v))
  }
}

/// This new signed contract uses RFC8785 key ordering (UTF-16), unlike the
/// legacy owner's Python code-point ordering. Never change the old encoder.
enum HS {
  static func value(_ data: Data) throws -> Any {
    var strict = HolderSessionJSON(data, maximumBytes: 131072, maximumKeys: 256, maximumArray: 256, maximumDepth: 24, allowNegativeIntegers: true)
    try strict.validate()
    return try JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed])
  }
  static func object(_ data: Data) throws -> [String: Any] {
    guard let v = try value(data) as? [String: Any] else { throw HolderSessionError.invalid }; return v
  }
  static func keys(_ v: [String: Any], _ expected: String) throws {
    guard Set(v.keys) == Set(expected.split(separator: " ").map(String.init)) else { throw HolderSessionError.invalid }
  }
  static func integer(_ value: Any?) throws -> UInt64 {
    guard let n = value as? NSNumber, CFGetTypeID(n) != CFBooleanGetTypeID(), !["f", "d"].contains(String(cString: n.objCType)),
      n.doubleValue >= 0, n.doubleValue <= 9_007_199_254_740_991 else { throw HolderSessionError.invalid }; return n.uint64Value
  }
  static func boolean(_ value: Any?) throws -> Bool {
    guard let n = value as? NSNumber, CFGetTypeID(n) == CFBooleanGetTypeID() else { throw HolderSessionError.invalid }; return n.boolValue
  }
  static func hex(_ value: Any?, _ length: Int) throws -> String {
    guard let s = value as? String, s.utf8.count == length, s.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else { throw HolderSessionError.invalid }; return s
  }
  static func unhex(_ value: String) throws -> Data {
    guard value.utf8.count.isMultiple(of: 2) else { throw HolderSessionError.invalid }
    var data = Data(); var index = value.startIndex
    while index < value.endIndex {
      let end = value.index(index, offsetBy: 2)
      guard let byte = UInt8(value[index..<end], radix: 16) else { throw HolderSessionError.invalid }
      data.append(byte); index = end
    }
    return data
  }
  static func text(_ value: String, maximum: Int = 256) throws {
    guard !value.isEmpty, value.utf8.count <= maximum, !value.unicodeScalars.contains(where: { $0.value < 32 || (127...159).contains($0.value) || (0x202a...0x202e).contains($0.value) || (0x2066...0x2069).contains($0.value) }) else { throw HolderSessionError.invalid }
  }
  static func pin(_ value: Any?) throws -> HolderIssuerPin {
    guard let p = value as? [String: Any] else { throw HolderSessionError.invalid }; try keys(p, "issuer key_id public_key service")
    guard let issuer = p["issuer"] as? String, let key = p["key_id"] as? String, let service = p["service"] as? String else { throw HolderSessionError.invalid }
    try text(issuer); try text(key); try text(service)
    return try HolderIssuerPin(issuer: issuer, keyID: key, publicKey: hex(p["public_key"], 64), service: service)
  }
  static func permissions(_ value: Any?) throws {
    guard let a = value as? [[String: Any]], !a.isEmpty, a.count <= 64 else { throw HolderSessionError.invalid }
    for p in a { try keys(p, "operation resource roles constraints"); guard let op = p["operation"] as? String, let resource = p["resource"] as? String,
      p["roles"] is [[String: Any]], p["constraints"] is [String: Any] else { throw HolderSessionError.invalid }; try text(op); try text(resource, maximum: 2048) }
  }
  static func digest(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
  static func encode(_ value: Any) throws -> Data {
    func quote(_ s: String) -> String {
      var out = "\""
      for c in s.unicodeScalars {
        switch c.value {
        case 34: out += "\\\""
        case 92: out += "\\\\"
        case 8: out += "\\b"
        case 9: out += "\\t"
        case 10: out += "\\n"
        case 12: out += "\\f"
        case 13: out += "\\r"
        case 0...31: out += String(format: "\\u%04x", c.value)
        default: out.unicodeScalars.append(c)
        }
      }
      return out + "\""
    }
    func string(_ v: Any, _ depth: Int) throws -> String {
      guard depth <= 24 else { throw HolderSessionError.invalid }
      if let object = v as? [String: Any] {
        let keys = object.keys.sorted { $0.utf16.lexicographicallyPrecedes($1.utf16) }
        return "{" + (try keys.map { try quote($0) + ":" + string(object[$0]!, depth + 1) }).joined(separator: ",") + "}"
      }
      if let array = v as? [Any] { return "[" + (try array.map { try string($0, depth + 1) }).joined(separator: ",") + "]" }
      if let text = v as? String { return quote(text) }
      if v is NSNull { return "null" }
      if let n = v as? NSNumber {
        if CFGetTypeID(n) == CFBooleanGetTypeID() { return n.boolValue ? "true" : "false" }
        guard !["f", "d"].contains(String(cString: n.objCType)), abs(n.doubleValue) <= 9_007_199_254_740_991 else { throw HolderSessionError.invalid }
        return n.stringValue
      }
      throw HolderSessionError.invalid
    }
    let data = Data(try string(value, 0).utf8)
    guard data.count <= 131072 else { throw HolderSessionError.invalid }; return data
  }
}
