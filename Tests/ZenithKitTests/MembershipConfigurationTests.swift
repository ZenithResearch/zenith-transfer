import Foundation
import XCTest
@testable import ZenithKit

final class MembershipConfigurationTests: XCTestCase {
  private func settings() throws -> [String: Any] {
    ["name": "Example membership", "endpoint": "https://membership.example/v3/memberships",
      "trust": ["v3": ["schema": "castalia.zenith-membership-trust-policy.v1", "version": 1,
        "roots": [["issuerId": "example", "keyId": "example-key", "signatureSuite": "Ed25519",
          "publicKey": String(repeating: "ab", count: 32)]]]]]
  }
  private func data(_ value: [String: Any]) throws -> Data { try JSONSerialization.data(withJSONObject: value) }
  func testProviderConfigurationPersistsWithoutApprovingTrustOrChangingBundledDefaults() throws {
    let suite = "membership-provider-test-" + UUID().uuidString
    let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
    defer { defaults.removePersistentDomain(forName: suite) }
    let value = try MembershipConfiguration.decodeFile(data(settings()))
    defaults.set(try JSONEncoder().encode(value), forKey: MembershipConfiguration.settingsKey)
    let reloaded = try XCTUnwrap(MembershipConfiguration.proposed(in: defaults))
    XCTAssertEqual(reloaded.endpoint, value.endpoint)
    XCTAssertEqual(try JSONSerialization.jsonObject(with: reloaded.trustData) as? NSDictionary,
      try JSONSerialization.jsonObject(with: value.trustData) as? NSDictionary)
    // Malformed saved settings must not silently select another provider.
    defaults.set(Data("{}".utf8), forKey: MembershipConfiguration.settingsKey)
    XCTAssertNil(MembershipConfiguration.proposed(in: defaults))
  }
  func testRejectsUnsafeOrCredentialBearingProviderConfiguration() throws {
    for endpoint in ["http://membership.example", "https://user:password@membership.example", "https://membership.example/?token=secret", "https://membership.example/#token"] {
      var value = try settings(); value["endpoint"] = endpoint
      XCTAssertThrowsError(try MembershipConfiguration.decodeFile(data(value)))
    }
    var credential = try settings(); credential["authKey"] = "not-accepted"
    XCTAssertThrowsError(try MembershipConfiguration.decodeFile(data(credential)))
    XCTAssertThrowsError(try MembershipConfiguration.decodeFile(Data(repeating: 32, count: 65_537)))
    let duplicate = "{\"name\":\"first\",\"name\":\"second\",\"endpoint\":\"https://example.test\",\"trust\":{}}"
    XCTAssertThrowsError(try MembershipConfiguration.decodeFile(Data(duplicate.utf8)))
  }
}
