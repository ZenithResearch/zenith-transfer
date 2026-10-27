import XCTest
@testable import ZenithKit

final class FutureArenaReadTests: XCTestCase {
  func testFutureSelectorIsExplicitAndRejectedByOldReader() throws {
    let dynamic: [[String: Any]] = [["scope": "devgraph.arena.read", "all_arenas": true]]
    let grants = try parseGrants(dynamic, protocol: .collectionArenaV6)
    XCTAssertEqual(grants[0].all_arenas, true)
    XCTAssertNil(grants[0].arena_ids)
    XCTAssertThrowsError(try parseGrants(dynamic, protocol: .arenaV5))
    let fixed: [[String: Any]] = [["scope": "devgraph.arena.read", "arena_ids": ["first"]]]
    XCTAssertNil(try parseGrants(fixed, protocol: .arenaV5)[0].all_arenas)
    XCTAssertNil(try parseGrants(fixed, protocol: .collectionArenaV6)[0].all_arenas)
    for bad in [
      ["scope": "devgraph.arena.read", "all_arenas": false],
      ["scope": "devgraph.arena.read", "all_arenas": 1],
      ["scope": "devgraph.arena.read", "all_arenas": true, "arena_ids": ["first"]],
      ["scope": "devgraph.arena.read", "all_arenas": true, "delegate": true],
    ] as [[String: Any]] {
      XCTAssertThrowsError(try parseGrants([bad], protocol: .collectionArenaV6))
    }
  }
  func testHolderCanKeepDynamicScopeOrNarrowToSelectedArenaWithoutBorrowingList() throws {
    let constraints: [String: Any] = ["scope": "devgraph.arena.read", "all_arenas": true]
    var permission: [String: Any] = ["operation": "devgraph.arena.get", "resource": "https://work.zenith-research.ca/devgraph", "scope": ["mode": "all"], "constraints": constraints]
    let dynamic = try parseGrants(holderReadConstraints([permission]), protocol: .collectionArenaV6, holder: true)[0]
    XCTAssertEqual(dynamic.all_arenas, true)
    XCTAssertEqual(dynamic.operations, ["get"])
    permission["scope"] = ["mode": "paths", "roots": [[["kind": "Arena", "id": "later"]]]]
    let fixed = try parseGrants(holderReadConstraints([permission]), protocol: .arenaV5, holder: true)[0]
    XCTAssertNil(fixed.all_arenas)
    XCTAssertEqual(fixed.arena_ids, ["later"])
    XCTAssertEqual(fixed.operations, ["get"])
    permission["scope"] = ["mode": "paths", "roots": [[["kind": "Project", "id": "p"]]]]
    XCTAssertThrowsError(try holderReadConstraints([permission]))
  }
}
