#if os(macOS)
import Foundation
import XCTest
@testable import ZenithKit

final class SessionAccessReviewTests: XCTestCase {
  let now: UInt64 = 2_000_000_000
  // Canonical DevGraph producer 9b2e76914d75e5848bdf9a303c756960daee3973.
  func testFrozenProducerFixtureBytes() throws {
    let url = try XCTUnwrap(Bundle.module.url(forResource: "session-access-review-v1", withExtension: "json"))
    XCTAssertEqual(OwnerSetupPlan.sha256(try Data(contentsOf: url)),
      "87aea530001e28d7d1bb69b1937c86f800fb996ecccd7e707318355ed10f8262")
  }
  func bundle() throws -> [String: Any] {
    try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: XCTUnwrap(
      Bundle.module.url(forResource: "session-access-review-v1", withExtension: "json")))) as? [String: Any])
  }
  func bytes(_ value: Any) throws -> Data { try OwnerReviewCanonicalJSON.encode(value) }
  func inputs() throws -> (Data, Data, SessionAccessExpiryLimits) {
    let b = try bundle(), caps = b["unsupported"] as! [String: Any]
    let m = (b["initial_review"] as! [String: Any])["manifest"] as! [String: Any]
    let provider = try bytes(caps["provider"]!), holder = try bytes(m["holder"]!)
    let parsed = try SessionAccessCapabilities.decode(bytes(caps), trustedProvider: provider)
    return (provider, holder, parsed.expiryLimits)
  }
  func review(_ name: String = "expiry_adjusted_review") throws -> SessionAccessReview {
    let (provider, holder, limits) = try inputs()
    return try .decode(bytes(bundle()[name]!), trustedProvider: provider, expectedHolder: holder, limits: limits, now: now)
  }
  func result(_ state: String) throws -> Data {
    try bytes(XCTUnwrap((bundle()["results"] as! [[String: Any]]).first { $0["state"] as? String == state }))
  }
  func testProducerReviewsAndEveryOutcomeDecodeWithoutNewPermissionSemantics() throws {
    for name in ["initial_review", "expiry_adjusted_review", "minimum_expiry_review"] {
      let value = try review(name)
      XCTAssertEqual(value.permissions.count, 1)
      XCTAssertNotNil(value.permissions[0].roles)
      XCTAssertEqual(value.permissions[0].operation, "devgraph.work.get")
    }
    let value = try review()
    for row in try bundle()["results"] as! [[String: Any]] {
      let parsed = try SessionAccessOutcome.decode(bytes(row), review: value, now: now)
      XCTAssertEqual(parsed.credentialHandle != nil, parsed.state == .issued)
    }
    for row in try bundle()["invalid_results"] as! [[String: Any]] {
      XCTAssertThrowsError(try SessionAccessOutcome.decode(bytes(row["result"]!), review: value, now: now))
    }
  }
  func testCapabilitiesMissingFeatureDefaultsOffAndNoImplicitWriteQualification() throws {
    let b = try bundle(), (p, _, _) = try inputs()
    let unsupported = try SessionAccessCapabilities.decode(bytes(b["unsupported"]!), trustedProvider: p)
    XCTAssertFalse(unsupported.readAvailable); XCTAssertFalse(unsupported.writeIssuance)
    var simulated = b["simulated_read_qualified"] as! [String: Any]
    XCTAssertTrue(try SessionAccessCapabilities.decode(bytes(simulated), trustedProvider: p).readAvailable)
    XCTAssertFalse(try SessionAccessCapabilities.decode(bytes(simulated), trustedProvider: p).writeIssuance)
    simulated["session_write_issuance"] = true
    simulated["session_request_execution"] = false
    XCTAssertFalse(try SessionAccessCapabilities.decode(bytes(simulated), trustedProvider: p).writeAvailable)
    simulated["session_request_execution"] = true
    simulated["session_key_enrollment"] = false
    XCTAssertFalse(try SessionAccessCapabilities.decode(bytes(simulated), trustedProvider: p).writeAvailable)
    simulated["session_key_enrollment"] = true
    simulated.removeValue(forKey: "session_read_issuance")
    XCTAssertFalse(try SessionAccessCapabilities.decode(bytes(simulated), trustedProvider: p).readAvailable)
    simulated["session_read_issuance"] = 1
    XCTAssertThrowsError(try SessionAccessCapabilities.decode(bytes(simulated), trustedProvider: p))
    simulated["schema"] = "zenith.session-access-capabilities.v2"
    XCTAssertThrowsError(try SessionAccessCapabilities.decode(bytes(simulated), trustedProvider: p))
  }
  func testExpiryUpdateMustUseFreshProviderSnapshotAndKeepExactScopeAndIdentity() throws {
    let first = try review("initial_review"), b = try bundle()
    let updated = try first.updatedExpiry(bytes(b["expiry_adjusted_review"]!), requestedExpiry: now + 1800, now: now)
    XCTAssertEqual(updated.expiresAt, now + 1800)
    XCTAssertEqual(updated.requestID, first.requestID)
    XCTAssertNotEqual(updated.digest, first.digest)
    XCTAssertThrowsError(try first.updatedExpiry(bytes(b["expiry_adjusted_review"]!), requestedExpiry: now + 3600, now: now))
    XCTAssertThrowsError(try first.updatedExpiry(bytes(b["initial_review"]!), requestedExpiry: now + 3600, now: now))
    for key in ["provider", "holder", "permissions", "request_id", "display"] {
      var changed = b["expiry_adjusted_review"] as! [String: Any]
      var m = changed["manifest"] as! [String: Any]
      if key == "permissions" { m[key] = [] as [Any] }
      else if key == "request_id" { m[key] = String(repeating: "ff", count: 16) }
      else { m[key] = [:] as [String: Any] }
      changed["manifest"] = m; changed["review_digest_sha256"] = OwnerSetupPlan.sha256(try bytes(m))
      XCTAssertThrowsError(try first.updatedExpiry(bytes(changed), requestedExpiry: now + 1800, now: now))
    }
  }
  func testShortExpiryAndExactDeadlines() throws {
    let b = try bundle(), (p, h, limits) = try inputs(), raw = try bytes(b["minimum_expiry_review"]!)
    let short = try SessionAccessReview.decode(raw, trustedProvider: p, expectedHolder: h, limits: limits, now: now)
    XCTAssertEqual(short.reviewDeadline, short.expiresAt)
    XCTAssertThrowsError(try SessionAccessReview.decode(raw, trustedProvider: p, expectedHolder: h, limits: limits, now: short.reviewDeadline))
    let r = try review()
    XCTAssertThrowsError(try SessionAccessOutcome.decode(result("issued"), review: r, now: r.expiresAt))
    XCTAssertThrowsError(try SessionAccessOutcome.decode(result("issued"), review: r, now: r.notBefore - 1))
  }
  func testRawDuplicateEscapedKeysFloatAndBooleanIntegerRejected() throws {
    let (p, h, limits) = try inputs(), raw = String(decoding: try bytes(bundle()["initial_review"]!), as: UTF8.self)
    let invalid = [
      raw.replacingOccurrences(of: "\"review_revision\":1", with: "\"review_revision\":1,\"review_revisi\\u006fn\":2"),
      raw.replacingOccurrences(of: "\"review_revision\":1", with: "\"review_revision\":1.0"),
      raw.replacingOccurrences(of: "\"review_revision\":1", with: "\"review_revision\":true")
    ]
    for value in invalid {
      XCTAssertNotEqual(value, raw)
      XCTAssertThrowsError(try SessionAccessReview.decode(Data(value.utf8), trustedProvider: p, expectedHolder: h, limits: limits, now: now))
    }
  }
  func testUnknownFieldAndPresentationLeakRejected() throws {
    var row = try XCTUnwrap((bundle()["results"] as! [[String: Any]]).first { $0["state"] as? String == "issued" })
    row["presentation"] = "must-not-be-model-output"
    XCTAssertThrowsError(try SessionAccessOutcome.decode(bytes(row), review: review(), now: now))
    var raw = try bundle()["initial_review"] as! [String: Any]
    var manifest = raw["manifest"] as! [String: Any]
    manifest["endpoint"] = "https://example.invalid"
    raw["manifest"] = manifest; raw["review_digest_sha256"] = OwnerSetupPlan.sha256(try bytes(manifest))
    let (p,h,limits) = try inputs()
    XCTAssertThrowsError(try SessionAccessReview.decode(bytes(raw), trustedProvider: p, expectedHolder: h, limits: limits, now: now))
  }
  func testUnknownSubmissionRetainsOriginalAndOnlyReconcilesBoundResult() throws {
    var flow = SessionAccessReviewFlow(review: try review())
    try flow.markSubmitting(now: now)
    try flow.accept(result("outcome_unknown"), now: now)
    XCTAssertEqual(flow.state, .outcomeUnknown)
    XCTAssertThrowsError(try flow.updateExpiry(bytes(bundle()["initial_review"]!), requestedExpiry: now + 3600, now: now))
    XCTAssertThrowsError(try flow.markSubmitting(now: now))
    XCTAssertThrowsError(try flow.accept(result("awaiting_human"), now: now))
    try flow.accept(result("issued"), now: now)
    XCTAssertEqual(flow.state, .issued)
    try flow.accept(result("revoked"), now: now)
    XCTAssertThrowsError(try flow.accept(result("issued"), now: now))
  }
  func testUndispatchedCannotBecomeIssuedAndExpiredReviewCannotSubmit() throws {
    var flow = SessionAccessReviewFlow(review: try review())
    XCTAssertThrowsError(try flow.accept(result("issued"), now: now))
    XCTAssertThrowsError(try flow.markSubmitting(now: flow.review.reviewDeadline))
    XCTAssertEqual(flow.state, .awaitingHuman)
    try flow.accept(result("cancelled"), now: now)
    XCTAssertThrowsError(try flow.markSubmitting(now: now))
  }
  func testAnIssuedRequestCannotReturnADifferentCredentialHandle() throws {
    var flow = SessionAccessReviewFlow(review: try review())
    try flow.markSubmitting(now: now)
    try flow.accept(result("issued"), now: now)
    try flow.accept(result("issued"), now: now)
    var changed = try XCTUnwrap((bundle()["results"] as! [[String: Any]]).first { $0["state"] as? String == "issued" })
    changed["credential_handle"] = "another_credential"
    XCTAssertThrowsError(try flow.accept(bytes(changed), now: now))
    XCTAssertEqual(flow.outcome?.credentialHandle, "credential_example")
  }
  func testMatchingDigestDoesNotAuthorizeAnExpiredOrBroadenedSnapshot() throws {
    let b = try bundle(), (p,h,limits) = try inputs()
    for lifetime: UInt64 in [59, 3601] {
      var raw = b["initial_review"] as! [String: Any], m = raw["manifest"] as! [String: Any]
      m["expires_at"] = now + lifetime; m["review_deadline"] = now + min(120, lifetime)
      raw["manifest"] = m; raw["review_digest_sha256"] = OwnerSetupPlan.sha256(try bytes(m))
      XCTAssertThrowsError(try SessionAccessReview.decode(bytes(raw), trustedProvider: p, expectedHolder: h, limits: limits, now: now))
    }
    var raw = b["expiry_adjusted_review"] as! [String: Any], m = raw["manifest"] as! [String: Any]
    var provider = m["provider"] as! [String: Any], policy = provider["policy_binding"] as! [String: Any]
    policy["policy_version"] = 99; provider["policy_binding"] = policy; m["provider"] = provider
    raw["manifest"] = m; raw["review_digest_sha256"] = OwnerSetupPlan.sha256(try bytes(m))
    XCTAssertThrowsError(try SessionAccessReview.decode(bytes(raw), trustedProvider: p, expectedHolder: h, limits: limits, now: now))
    raw = b["expiry_adjusted_review"] as! [String: Any]; m = raw["manifest"] as! [String: Any]
    var permissions = m["permissions"] as! [[String: Any]]
    permissions[0]["operation"] = "devgraph.work.list"
    m["permissions"] = permissions; raw["manifest"] = m
    raw["review_digest_sha256"] = OwnerSetupPlan.sha256(try bytes(m))
    XCTAssertThrowsError(try review("initial_review").updatedExpiry(bytes(raw), requestedExpiry: now + 1800, now: now))
  }
  func testSharedPermissionConstraintsKeepSignedIntegersButTimeDoesNot() throws {
    var raw = try bundle()["initial_review"] as! [String: Any], m = raw["manifest"] as! [String: Any]
    var permissions = m["permissions"] as! [[String: Any]], constraints = permissions[0]["constraints"] as! [String: Any]
    constraints["example_threshold"] = -10
    permissions[0]["constraints"] = constraints; m["permissions"] = permissions; raw["manifest"] = m
    raw["review_digest_sha256"] = OwnerSetupPlan.sha256(try bytes(m))
    let (p,h,limits) = try inputs()
    let decoded = try SessionAccessReview.decode(bytes(raw), trustedProvider: p, expectedHolder: h, limits: limits, now: now)
    XCTAssertTrue(decoded.permissions[0].conditions.contains("-10"))
    m["not_before"] = -1; raw["manifest"] = m; raw["review_digest_sha256"] = OwnerSetupPlan.sha256(try bytes(m))
    XCTAssertThrowsError(try SessionAccessReview.decode(bytes(raw), trustedProvider: p, expectedHolder: h, limits: limits, now: now))
    var oldReader = OwnerPlanJSON(Data("{\"value\":-10}".utf8))
    XCTAssertThrowsError(try oldReader.validate(), "Existing owner readers keep their original nonnegative contract")
    m["not_before"] = now; m["review_revision"] = -1
    raw["manifest"] = m; raw["review_digest_sha256"] = OwnerSetupPlan.sha256(try bytes(m))
    XCTAssertThrowsError(try SessionAccessReview.decode(bytes(raw), trustedProvider: p, expectedHolder: h, limits: limits, now: now))
  }
  func testUnicodeReviewDigestMatchesIndependentPythonProducerEncoding() throws {
    var raw = try bundle()["initial_review"] as! [String: Any], m = raw["manifest"] as! [String: Any]
    m["display"] = ["session_label": "작업 세션 👩🏽‍💻", "purpose": "Read café / e\u{0301}"]
    raw["manifest"] = m
    raw["review_digest_sha256"] = "8b3e8f8bc7573d848c64d006ed47873d28e8af450d24ec2763535eeaa4650d31"
    let (p,h,limits) = try inputs()
    let value = try SessionAccessReview.decode(bytes(raw), trustedProvider: p, expectedHolder: h, limits: limits, now: now)
    XCTAssertEqual(value.sessionLabel, "작업 세션 👩🏽‍💻")
  }
}
#endif
