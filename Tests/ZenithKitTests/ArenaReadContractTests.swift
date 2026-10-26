import Foundation
import XCTest
@testable import ZenithKit

final class ArenaReadContractTests: XCTestCase {
  func testArenaMetadataIsNotDecodedAsWorkOrGivenInventedPriority() throws {
    let raw = Data(#"{"kind":"Arena","id":"one","title":"One","description":"","version":2,"archived":true}"#.utf8)
    let arena = try JSONDecoder().decode(ArenaRecord.self, from: raw)
    try arena.validate()
    XCTAssertTrue(arena.archived)
    XCTAssertThrowsError(try JSONDecoder().decode(WorkRecord.self, from: raw))
  }
  func testVersionedArenaDecodePreservesOperationsAndRefusesLegacyOrHiddenFields() throws {
    let raw: [String: Any] = ["scope": "devgraph.arena.read", "arena_ids": ["research"]]
    for version in [WorkReadProtocol.nativeV2, .monitorV3, .pathV4] {
      XCTAssertThrowsError(try parseGrants([raw], protocol: version))
    }
    let grant = try XCTUnwrap(parseGrants([raw], protocol: .arenaV5).first)
    XCTAssertTrue(grant.isArena)
    XCTAssertEqual(grant.operations, ["list", "get"])
    XCTAssertEqual(grant.work_kinds, [])
    for key in ["operations", "work_kinds", "onward_delegation", "resource_paths"] {
      var invalid = raw; invalid[key] = ["get"]
      XCTAssertThrowsError(try parseGrants([invalid], protocol: .arenaV5))
    }
  }
  func testHolderArenaPermissionCannotBorrowListOrEscapeExplicitIDs() throws {
    var p: [String: Any] = ["operation": "devgraph.arena.get", "resource": "https://work.zenith-research.ca/devgraph",
      "constraints": ["scope": "devgraph.arena.read", "arena_ids": ["one", "two"]],
      "scope": ["mode": "paths", "roots": [[["kind": "Arena", "id": "one"]]]]]
    let decoded = try parseGrants(holderReadConstraints([p]), protocol: .arenaV5, holder: true)
    XCTAssertEqual(decoded.first?.operations, ["get"])
    XCTAssertEqual(decoded.first?.arena_ids, ["one"])
    for root in [["kind": "Project", "id": "one"], ["kind": "Arena", "id": "private"]] {
      p["scope"] = ["mode": "paths", "roots": [[root]]]
      XCTAssertThrowsError(try holderReadConstraints([p]))
    }
  }
}
