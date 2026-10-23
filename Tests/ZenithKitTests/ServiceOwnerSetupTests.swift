#if os(macOS)
import Foundation
import XCTest
@testable import ZenithKit

final class ServiceOwnerSetupTests: XCTestCase {
  func testInstalledPreparedStatusWhenProvided() throws {
    guard let path = ProcessInfo.processInfo.environment["SERVICE_OWNER_STATUS_FILE"],
      let servicePath = ProcessInfo.processInfo.environment["SERVICE_OWNER_RECORD_FILE"] else {
      throw XCTSkip("Installed public status fixture not provided")
    }
    let bytes = try Data(contentsOf: URL(fileURLWithPath: path))
    let service = try LocalService.decode(Data(contentsOf: URL(fileURLWithPath: servicePath)))
    let raw = try JSONSerialization.jsonObject(with: bytes) as! [String: Any]
    let plan = try OwnerSetupPlan.decode(data(raw["plan"]!))
    let envelope = raw["preparation"] as! [String: Any]
    XCTAssertEqual(OwnerSetupPlan.sha256(try OwnerReviewCanonicalJSON.encode(envelope["review"]!)), envelope["review_digest"] as? String, "Installed review canonical bytes")
    XCTAssertNoThrow(try OwnerInstallationReview.decode(data(raw["preparation"]!), plan: plan), "Installed review")
    XCTAssertNoThrow(try ServiceOwnerPreparation.decode(data(["schema": "devgraph.service-owner-preparation.v1", "plan": raw["plan"]!, "preparation": raw["preparation"]!]), service: service), "Installed preparation")
    XCTAssertNoThrow(try ServiceOwnerStatus.decode(bytes, service: service), "Installed status")
  }
  private func fixture() throws -> ([String: Any], LocalService) {
    let url = try XCTUnwrap(Bundle.module.url(forResource: "service-owner-preparation", withExtension: "json"))
    var value = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
    let service = try LocalService.decode(JSONSerialization.data(withJSONObject: value.removeValue(forKey: "service")!))
    return (value, service)
  }
  private func data(_ raw: Any) throws -> Data { try JSONSerialization.data(withJSONObject: raw, options: [.sortedKeys, .withoutEscapingSlashes]) }
  func testPythonPreparationUsesSelectedInstanceAndExistingPin() throws {
    let (raw, service) = try fixture()
    let preparation = try ServiceOwnerPreparation.decode(data(raw), service: service)
    XCTAssertEqual(preparation.binding.endpoint, service.endpoint)
    XCTAssertNotEqual(preparation.binding.endpoint, preparation.plan.localEndpoint)
    XCTAssertEqual(preparation.review.connection, service.connection)
    XCTAssertEqual(preparation.review.certificateSHA256, service.connection?.tls_certificate_sha256)
    XCTAssertEqual(preparation.plan.ownerPublicKey, preparation.review.ownerPublicKey)
    XCTAssertEqual(preparation.plan.scopeMode, "global")
    XCTAssertNil(preparation.plan.notAfter)
    _ = try ServiceOwnerCoordinator(service: service)
  }
  func testValidlyRehashedReviewCannotChangeSelectedServiceOrIssuer() throws {
    let (original, service) = try fixture()
    for field in ["instance_id", "endpoint", "label", "connection"] {
      var raw = original
      var envelope = raw["preparation"] as! [String: Any]
      var review = envelope["review"] as! [String: Any]
      var existing = review["existing_service"] as! [String: Any]
      if field == "connection" {
        var connection = existing[field] as! [String: Any]; connection["issuer"] = "another-issuer"; existing[field] = connection
      } else { existing[field] = "changed" }
      review["existing_service"] = existing
      envelope["review"] = review; envelope["review_digest"] = OwnerSetupPlan.sha256(try OwnerReviewCanonicalJSON.encode(review))
      raw["preparation"] = envelope
      XCTAssertThrowsError(try ServiceOwnerPreparation.decode(data(raw), service: service), field)
    }
  }
  func testAnotherLegitimateServiceOfSameGraphCannotUsePreparation() throws {
    let (raw, service) = try fixture()
    let url = try XCTUnwrap(Bundle.module.url(forResource: "service-owner-preparation", withExtension: "json"))
    let fixture = try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as! [String: Any]
    var other = fixture["service"] as! [String: Any]
    let origin = "https://127.0.0.1:19444"
    var profile = other["connection"] as! [String: Any]
    var authority = profile["authority"] as! [String: Any]
    authority["receiver"] = origin; profile["authority"] = authority; profile["receiver"] = origin
    other["connection"] = profile; other["endpoint"] = origin
    other["instance_id"] = try LocalService.instanceID(resourceID: service.resource_id, interface: .walletAPI, endpoint: origin)
    let selected = try LocalService.decode(data(other))
    XCTAssertThrowsError(try ServiceOwnerPreparation.decode(data(raw), service: selected))
  }
  func testIncompleteStatusNeverReportsAdministrationReady() throws {
    let (preparation, service) = try fixture()
    var raw: [String: Any] = ["schema": "devgraph.service-owner-status.v1", "prepared": false,
      "blocked": false, "owner_registered": false, "activation_attempted": false, "active": false]
    let empty = try ServiceOwnerStatus.decode(data(raw), service: service)
    XCTAssertNil(empty.preparation); XCTAssertFalse(empty.active)
    raw["active"] = true
    XCTAssertThrowsError(try ServiceOwnerStatus.decode(data(raw), service: service))
    raw["prepared"] = true; raw["plan"] = preparation["plan"]; raw["preparation"] = preparation["preparation"]
    XCTAssertThrowsError(try ServiceOwnerStatus.decode(data(raw), service: service))
    raw["owner_registered"] = true; raw["activation_attempted"] = true
    XCTAssertTrue(try ServiceOwnerStatus.decode(data(raw), service: service).active)
  }
}
#endif
