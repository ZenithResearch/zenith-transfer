#if os(macOS)
import Foundation
import XCTest
@testable import ZenithKit

final class OwnerInstallationTests: XCTestCase {
  private func fixture() throws -> ([String: Any], OwnerSetupPlan) {
    let url = try XCTUnwrap(Bundle.module.url(forResource: "owner-install-review", withExtension: "json"))
    var raw = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
    let plan = try OwnerSetupPlan.decode(JSONSerialization.data(withJSONObject: raw.removeValue(forKey: "plan")!))
    return (raw, plan)
  }
  func testPythonPreparationReviewMatchesNativeDecoderAndPlanDigest() throws {
    let (raw, plan) = try fixture()
    let result = try OwnerInstallationReview.decode(JSONSerialization.data(withJSONObject: raw), plan: plan)
    XCTAssertEqual(result.ownerPublicKey, plan.ownerPublicKey)
    XCTAssertEqual(result.endpoint, plan.walletEndpoint)
    XCTAssertEqual(result.nativeVersion, 32); XCTAssertEqual(result.previousNativeVersion, 31)
    XCTAssertEqual(result.preservedRules, 2); XCTAssertEqual(result.operations,["devgraph.work.patch.v2"])
    XCTAssertEqual(result.connection.network, .lan)
    XCTAssertEqual(result.connection.tls_certificate_sha256,result.certificateSHA256)
  }
  func testChangedOwnerOriginCertificateOrAuthorityCannotReuseReview() throws {
    let (original, plan) = try fixture()
    for mutation in ["owner_public_key", "endpoint", "native_key_unchanged", "members_preassigned", "onward_delegation"] {
      var raw = original, review = raw["review"] as! [String: Any]
      switch mutation {
      case "owner_public_key": review[mutation] = String(repeating: "f", count: 64)
      case "endpoint": review[mutation] = "https://192.168.10.21:18443"
      case "members_preassigned": review[mutation] = 1
      default: review[mutation] = mutation == "onward_delegation"
      }
      raw["review"] = review
      XCTAssertThrowsError(try OwnerInstallationReview.decode(JSONSerialization.data(withJSONObject: raw), plan: plan))
    }
    var changed = original
    changed["review_digest"] = String(repeating: "0", count: 64)
    XCTAssertThrowsError(try OwnerInstallationReview.decode(JSONSerialization.data(withJSONObject: changed), plan: plan))
  }
  func testDuplicateFieldsAndFractionalVersionsFailBeforeDictionaryCollapse() throws {
    let (raw, plan) = try fixture()
    let valid = String(decoding: try JSONSerialization.data(withJSONObject: raw, options: [.sortedKeys]), as: UTF8.self)
    let duplicate = String(valid.dropLast()) + ",\"review_digest\":\"" + String(repeating: "0", count: 64) + "\"}"
    XCTAssertThrowsError(try OwnerInstallationReview.decode(Data(duplicate.utf8), plan: plan))
    let fractional = valid.replacingOccurrences(of: "\"native_policy_version\":32", with: "\"native_policy_version\":32.0")
    XCTAssertNotEqual(fractional, valid)
    XCTAssertThrowsError(try OwnerInstallationReview.decode(Data(fractional.utf8), plan: plan))
  }
  func testBootstrapCannotPreadmitRecipientsOrDisableExactDecisionAdmission() throws {
    let (original, plan) = try fixture()
    for field in ["native_holders", "native_admission_on_grant"] {
      var raw = original, review = raw["review"] as! [String: Any]
      review[field] = field == "native_holders" ? [String(repeating: "a", count: 64)] : false
      raw["review"] = review
      XCTAssertThrowsError(try OwnerInstallationReview.decode(JSONSerialization.data(withJSONObject: raw), plan: plan))
    }
  }
}
#endif
