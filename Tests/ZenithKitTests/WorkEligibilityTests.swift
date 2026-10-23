import Foundation
import XCTest
@testable import ZenithKit
final class WorkEligibilityTests: XCTestCase {
  func testGraphEligibilityDoesNotMeanMembership() throws {
    let base: [String: Any] = ["configured":true,"unlocked":true,"revision":1,"public_key":String(repeating:"a",count:64),"backup_verified":true,"membership_active":false,"graph_access_protocol":"castalia.graph-access.v2"]
    func decode(_ extra: [String:Any]) throws -> WalletState {
      try JSONDecoder().decode(WalletState.self,from:JSONSerialization.data(withJSONObject:base.merging(extra){_,new in new}))
    }
    XCTAssertFalse(try decode(["graph_access_protocol":"unknown"]).canRequestWorkAccess)
    XCTAssertTrue(try decode([:]).canRequestWorkAccess)
    XCTAssertFalse(try decode([:]).membershipActive)
    XCTAssertFalse(try decode(["unlocked":false]).canRequestWorkAccess)
    XCTAssertFalse(try decode(["backup_verified":false]).canRequestWorkAccess)
    XCTAssertTrue(try decode(["backup_verified":false,"backup_eligible":true]).canRequestWorkAccess)
  }
}
