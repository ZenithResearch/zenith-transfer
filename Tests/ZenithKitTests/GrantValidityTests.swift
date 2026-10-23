import Foundation
import XCTest
@testable import ZenithKit

final class GrantValidityTests: XCTestCase {
  private func vectors() throws -> [String: Any] {
    let url = try XCTUnwrap(Bundle.module.url(forResource: "grant-validity-v1", withExtension: "json"))
    return try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
  }
  private func validity(_ value: Any) throws -> GrantValidity {
    try GrantValidity.decode(JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]))
  }
  func testPortableContractVectors() throws {
    let vectors = try vectors()
    for item in try XCTUnwrap(vectors["valid"] as? [[String: Any]]) {
      let value = try validity(try XCTUnwrap(item["value"]))
      for check in try XCTUnwrap(item["checks"] as? [[String: Any]]) {
        XCTAssertEqual(value.contains((check["now"] as! NSNumber).uint64Value), check["active"] as! Bool)
      }
      for check in try XCTUnwrap(item["deadlines"] as? [[String: Any]]) {
        let now = (check["now"] as! NSNumber).uint64Value
        let lifetime = (check["lifetime"] as! NSNumber).uint64Value
        if check["deadline"] is NSNull { XCTAssertThrowsError(try value.credentialDeadline(now: now, lifetime: lifetime)) }
        else { XCTAssertEqual(try value.credentialDeadline(now: now, lifetime: lifetime), (check["deadline"] as! NSNumber).uint64Value) }
      }
    }
    for item in try XCTUnwrap(vectors["invalid"] as? [[String: Any]]) {
      XCTAssertThrowsError(try GrantValidity.decode(Data((item["raw"] as! String).utf8)), "\(item["id"]!)")
    }
    for item in try XCTUnwrap(vectors["subsets"] as? [[String: Any]]) {
      XCTAssertEqual(try validity(item["child"]!).contained(by: validity(item["parent"]!)), item["allowed"] as! Bool)
    }
  }
  func testNoCredentialFromInactiveGrantOrInvalidLifetime() throws {
    let value = try validity(["schema": "castalia.grant-validity.v1", "mode": "dated", "not_before": 100, "not_after": 200])
    let cases: [(UInt64, UInt64)] = [(99,60),(200,60),(100,0),(100,3601),(9_007_199_254_740_992,60)]
    for (now, lifetime) in cases {
      XCTAssertThrowsError(try value.credentialDeadline(now: now, lifetime: lifetime))
    }
  }
}
