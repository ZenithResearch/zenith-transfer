#if os(macOS)
import CoreFoundation
import Foundation

/// Candidate application interface only. These unsigned snapshots are not
/// credentials or signer consent. No production path calls this adapter yet.
public enum SessionAccessReviewError: Error { case invalid, changed, unavailable }

public struct SessionAccessExpiryLimits: Sendable, Equatable {
  public let minimum: UInt64
  public let proposedDefault: UInt64
  public let maximum: UInt64
  fileprivate init(_ object: [String: Any]) throws {
    try sessionKeys(object, "minimum_seconds default_seconds maximum_seconds")
    minimum = try sessionInteger(object["minimum_seconds"])
    proposedDefault = try sessionInteger(object["default_seconds"])
    maximum = try sessionInteger(object["maximum_seconds"])
    guard minimum > 0, minimum <= proposedDefault, proposedDefault <= maximum else { throw SessionAccessReviewError.invalid }
  }
}

public struct SessionAccessCapabilities: Sendable {
  public let expiryLimits: SessionAccessExpiryLimits
  public let enrollment: Bool, readIssuance: Bool, writeIssuance: Bool, execution: Bool
  public var readAvailable: Bool { enrollment && readIssuance && execution }
  public var writeAvailable: Bool { enrollment && writeIssuance && execution }
  public static func decode(_ data: Data, trustedProvider: Data) throws -> Self {
    let raw = try sessionObject(data)
    let known = Set("schema provider profile session_key_enrollment session_read_issuance session_write_issuance session_request_execution expiry_limits reason".split(separator: " ").map(String.init))
    guard Set(raw.keys).isSubset(of: known), raw["schema"] as? String == "zenith.session-access-capabilities.v1",
      raw["profile"] as? String == "secs.holder-grant.v2",
      let provider = raw["provider"] as? [String: Any], let limits = raw["expiry_limits"] as? [String: Any],
      try sessionCanonical(provider) == sessionCanonical(sessionObject(trustedProvider)) else { throw SessionAccessReviewError.unavailable }
    return try Self(expiryLimits: .init(limits), enrollment: sessionFeature(raw["session_key_enrollment"]),
      readIssuance: sessionFeature(raw["session_read_issuance"]), writeIssuance: sessionFeature(raw["session_write_issuance"]),
      execution: sessionFeature(raw["session_request_execution"]))
  }
}

/// Trust inputs must come from reviewed local configuration and authenticated
/// custody IPC, never from the model or a page nominating its own issuer.
public struct SessionAccessReview: Sendable {
  public let requestHandle: String, requestID: String, digest: String
  public let service: String, holderPublicKey: String, sessionLabel: String, purpose: String
  public let revision: UInt64, notBefore: UInt64, expiresAt: UInt64, reviewDeadline: UInt64
  public let manifest: Data
  public let permissions: [HolderGrantPermission]
  private let provider: Data, holder: Data
  private let limits: SessionAccessExpiryLimits

  public static func decode(_ data: Data, trustedProvider: Data, expectedHolder: Data,
                            limits: SessionAccessExpiryLimits, now: UInt64) throws -> Self {
    guard now <= sessionSafeInteger else { throw SessionAccessReviewError.invalid }
    let raw = try sessionObject(data)
    try sessionKeys(raw, "manifest review_digest_sha256 state request_handle")
    guard raw["state"] as? String == "awaiting_human", let m = raw["manifest"] as? [String: Any] else { throw SessionAccessReviewError.invalid }
    try sessionKeys(m, "schema request_id review_revision provider holder permissions not_before expires_at review_deadline challenge_id display")
    guard m["schema"] as? String == "zenith.session-access-review.v1",
      let p = m["provider"] as? [String: Any], let h = m["holder"] as? [String: Any],
      let display = m["display"] as? [String: Any], let permissions = m["permissions"] as? [[String: Any]],
      (1...64).contains(permissions.count) else { throw SessionAccessReviewError.invalid }
    try sessionKeys(p, "service issuer key_id public_key profile_digest_sha256 policy_binding")
    guard let policy = p["policy_binding"] as? [String: Any] else { throw SessionAccessReviewError.invalid }
    try sessionKeys(policy, "policy_id policy_version policy_digest_sha256")
    guard try sessionInteger(policy["policy_version"]) > 0 else { throw SessionAccessReviewError.invalid }
    for v in [p["public_key"], p["profile_digest_sha256"], policy["policy_digest_sha256"]] { _ = try sessionText(v, "[0-9a-f]{64}") }
    for v in [p["service"], p["issuer"], p["key_id"], policy["policy_id"]] { _ = try sessionDisplay(v) }
    try sessionKeys(h, "session_handle public_key installation_id")
    _ = try sessionText(h["session_handle"], "[A-Za-z0-9._:-]{1,128}")
    _ = try sessionText(h["installation_id"], "[0-9a-f]{32}")
    let publicKey = try sessionText(h["public_key"], "[0-9a-f]{64}")
    guard try sessionCanonical(p) == sessionCanonical(sessionObject(trustedProvider)),
      try sessionCanonical(h) == sessionCanonical(sessionObject(expectedHolder)) else { throw SessionAccessReviewError.changed }
    try sessionKeys(display, "session_label purpose")
    let label = try sessionDisplay(display["session_label"]), purpose = try sessionDisplay(display["purpose"])
    let start = try sessionInteger(m["not_before"]), end = try sessionInteger(m["expires_at"])
    let deadline = try sessionInteger(m["review_deadline"]), revision = try sessionInteger(m["review_revision"])
    guard revision > 0, start <= now, now < deadline, deadline <= end, deadline - now <= 120,
      end > start, end - start >= limits.minimum, end - start <= limits.maximum else { throw SessionAccessReviewError.invalid }
    _ = try sessionText(m["challenge_id"], "[0-9a-f]{32}")
    let canonical = try sessionCanonical(m), digest = try sessionText(raw["review_digest_sha256"], "[0-9a-f]{64}")
    guard OwnerSetupPlan.sha256(canonical) == digest else { throw SessionAccessReviewError.changed }
    // Decode the existing shared display shape, not a new selector evaluator.
    // Native secS/Core must validate the complete permissions before signing.
    for permission in permissions { try sessionKeys(permission, "operation resource roles constraints") }
    let decoded = try JSONDecoder().decode([HolderGrantPermission].self, from: sessionCanonical(permissions))
    return Self(requestHandle: try sessionText(raw["request_handle"], "[A-Za-z0-9._:-]{1,128}"),
      requestID: try sessionText(m["request_id"], "[0-9a-f]{32}"), digest: digest,
      service: p["service"] as! String, holderPublicKey: publicKey, sessionLabel: label, purpose: purpose,
      revision: revision, notBefore: start, expiresAt: end, reviewDeadline: deadline, manifest: canonical,
      permissions: decoded, provider: try sessionCanonical(p), holder: try sessionCanonical(h), limits: limits)
  }

  /// Use only before dispatch. The caller cannot locally edit a review and
  /// preserve its old challenge; the provider must return a new bound snapshot.
  public func updatedExpiry(_ data: Data, requestedExpiry: UInt64, now: UInt64) throws -> Self {
    let updated = try Self.decode(data, trustedProvider: provider, expectedHolder: holder, limits: limits, now: now)
    let before = try sessionObject(manifest), after = try sessionObject(updated.manifest)
    let mutable: Set<String> = ["review_revision", "expires_at", "challenge_id", "review_deadline"]
    guard requestHandle == updated.requestHandle, updated.expiresAt == requestedExpiry,
      updated.revision > revision, before["challenge_id"] as? String != after["challenge_id"] as? String,
      updated.digest != digest,
      try sessionCanonical(before.filter { !mutable.contains($0.key) }) == sessionCanonical(after.filter { !mutable.contains($0.key) })
    else { throw SessionAccessReviewError.changed }
    return updated
  }
}

public enum SessionAccessState: String, Codable, Sendable {
  case prepared, awaitingHuman = "awaiting_human", submitting, issued, denied, cancelled, expired, revoked
  case outcomeUnknown = "outcome_unknown"
}

public struct SessionAccessOutcome: Sendable {
  public let state: SessionAccessState
  public let credentialHandle: String?
  public let expiresAt: UInt64?
  public let reconcileRequired: Bool
  public static func decode(_ data: Data, review: SessionAccessReview, now: UInt64) throws -> Self {
    guard now <= sessionSafeInteger else { throw SessionAccessReviewError.invalid }
    let raw = try sessionObject(data)
    try sessionKeys(raw, "schema request_handle request_id review_digest_sha256 provider_service holder_public_key state credential_handle expires_at reconcile_required")
    guard raw["schema"] as? String == "zenith.session-access-result.v1",
      raw["request_handle"] as? String == review.requestHandle, raw["request_id"] as? String == review.requestID,
      raw["review_digest_sha256"] as? String == review.digest, raw["provider_service"] as? String == review.service,
      raw["holder_public_key"] as? String == review.holderPublicKey,
      let state = (raw["state"] as? String).flatMap(SessionAccessState.init(rawValue:)),
      try sessionFeature(raw["reconcile_required"]) == (state == .outcomeUnknown)
    else { throw SessionAccessReviewError.changed }
    if state == .issued {
      let expiry = try sessionInteger(raw["expires_at"])
      guard expiry == review.expiresAt, now >= review.notBefore, now < expiry else { throw SessionAccessReviewError.changed }
      return Self(state: state, credentialHandle: try sessionText(raw["credential_handle"], "[A-Za-z0-9._:-]{1,128}"), expiresAt: expiry, reconcileRequired: false)
    }
    guard raw["credential_handle"] is NSNull, raw["expires_at"] is NSNull else { throw SessionAccessReviewError.invalid }
    return Self(state: state, credentialHandle: nil, expiresAt: nil, reconcileRequired: state == .outcomeUnknown)
  }
}

/// In-memory preview lifecycle only; no signing, IPC or durable request journal.
/// A production broker must persist its dispatch binding before sending.
public struct SessionAccessReviewFlow: Sendable {
  public private(set) var review: SessionAccessReview
  public private(set) var state: SessionAccessState = .awaitingHuman
  public private(set) var outcome: SessionAccessOutcome?
  public init(review: SessionAccessReview) { self.review = review }
  public mutating func updateExpiry(_ data: Data, requestedExpiry: UInt64, now: UInt64) throws {
    guard state == .awaitingHuman else { throw SessionAccessReviewError.changed }
    review = try review.updatedExpiry(data, requestedExpiry: requestedExpiry, now: now)
  }
  public mutating func markSubmitting(now: UInt64) throws {
    guard state == .awaitingHuman, now >= review.notBefore, now < review.reviewDeadline else { throw SessionAccessReviewError.changed }
    state = .submitting
  }
  public mutating func accept(_ data: Data, now: UInt64) throws {
    let result = try SessionAccessOutcome.decode(data, review: review, now: now)
    let allowed: Set<SessionAccessState>
    switch state {
    case .awaitingHuman: allowed = [.awaitingHuman, .denied, .cancelled, .expired]
    case .submitting, .outcomeUnknown: allowed = [.issued, .denied, .cancelled, .expired, .revoked, .outcomeUnknown]
    case .issued: allowed = [.issued, .expired, .revoked]
    default: allowed = [state]
    }
    guard allowed.contains(result.state) else { throw SessionAccessReviewError.changed }
    if state == .issued, result.state == .issued {
      guard outcome?.credentialHandle == result.credentialHandle else { throw SessionAccessReviewError.changed }
    }
    state = result.state
    outcome = result
  }
}

private let sessionSafeInteger: UInt64 = 9_007_199_254_740_991
private func sessionObject(_ data: Data) throws -> [String: Any] {
  var reader = OwnerPlanJSON(data, maximumBytes: 65536, maximumKeys: 256, maximumArray: 256, maximumDepth: 24, allowNegativeIntegers: true)
  try reader.validate()
  guard let raw = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw SessionAccessReviewError.invalid }
  return raw
}
private func sessionCanonical(_ value: Any) throws -> Data { try OwnerReviewCanonicalJSON.encode(value) }
private func sessionKeys(_ object: [String: Any], _ keys: String) throws {
  guard Set(object.keys) == Set(keys.split(separator: " ").map(String.init)) else { throw SessionAccessReviewError.invalid }
}
private func sessionFeature(_ value: Any?) throws -> Bool {
  guard let value else { return false }
  guard let n = value as? NSNumber, CFGetTypeID(n) == CFBooleanGetTypeID() else { throw SessionAccessReviewError.invalid }
  return n.boolValue
}
private func sessionInteger(_ value: Any?) throws -> UInt64 {
  guard let n = value as? NSNumber, CFGetTypeID(n) != CFBooleanGetTypeID(),
    !["f", "d"].contains(String(cString: n.objCType)), n.int64Value >= 0, n.uint64Value <= sessionSafeInteger else { throw SessionAccessReviewError.invalid }
  return n.uint64Value
}
private func sessionText(_ value: Any?, _ pattern: String) throws -> String {
  guard let text = value as? String, text.range(of: "\\A(?:" + pattern + ")\\z", options: .regularExpression) != nil else { throw SessionAccessReviewError.invalid }
  return text
}
private func sessionDisplay(_ value: Any?) throws -> String {
  guard let text = value as? String, !text.isEmpty, text.unicodeScalars.count <= 512,
    text.unicodeScalars.allSatisfy({ s in
      let c = s.value
      return c >= 32 && !(127...159).contains(c) && ![0x061c,0x200e,0x200f].contains(c)
        && !(0x202a...0x202e).contains(c) && !(0x2066...0x2069).contains(c)
    }) else { throw SessionAccessReviewError.invalid }
  return text
}
#endif
