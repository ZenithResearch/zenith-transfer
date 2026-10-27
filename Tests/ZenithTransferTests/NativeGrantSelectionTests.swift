#if os(macOS)
import Foundation
import XCTest
@testable import ZenithKit
@testable import ZenithTransfer

final class NativeGrantSelectionTests: XCTestCase {
  func testArenaRecordAuthorityCannotEscapeSelectedHierarchy() throws {
    let f = try fixtures()[0]
    var ceiling = f["ceiling"] as! [String: Any]
    ceiling["schema"] = "devgraph.access-draft.v6"
    ceiling.removeValue(forKey: "not_before"); ceiling.removeValue(forKey: "not_after")
    ceiling["validity"] = ["schema": "castalia.grant-validity.v1", "mode": "until_revoked", "not_before": 1]
    ceiling["read_grants"] = [["scope": "devgraph.arena.read", "arena_ids": ["one", "two"]]]
    let path = try WorkResourcePath(path: ["Arena/one", "Project/project"])
    let scopes = [WorkScopeOption(resource_path: path, resource: "Project/project", title: "Project", parent: nil)]
    var choice = NativeGrantChoice(); choice.paths = [path]; choice.arenaIDs = ["one"]
    func make() throws -> [String: Any] {
      try NativeGrantSelection.make(ceiling: ceiling, ceilingDigest: GrantJSON.digest(ceiling),
        recipient: NativeGrantRecipient(f["recipient"] as! [String: Any]), choice: choice, scopes: scopes, now: f["now"] as! Int)
    }
    let selected = try make()["read"] as! [String: Any]
    let grants = selected["read_grants"] as! [[String: Any]]
    XCTAssertEqual(grants.count, 1)
    XCTAssertEqual(grants[0]["arena_ids"] as? [String], ["one"])
    XCTAssertNil(grants[0]["work_kinds"], "Arena metadata must not grant sibling Work")
    choice.arenaIDs = ["two"]
    XCTAssertThrowsError(try make(), "An allowed Arena outside this selected scope must still be rejected")
    choice.wholeGraph = true; choice.paths = []
    XCTAssertNoThrow(try make(), "Global coverage can explicitly select the second Arena")
  }
  func testStandaloneWorkScopeDoesNotInferArenaRecordAccess() throws {
    var choice = NativeGrantChoice()
    choice.paths = [try WorkResourcePath(path: ["Project/standalone"])]
    XCTAssertTrue(NativeGrantSelection.arenaCoverage(choice, available: ["one", "two"]).isEmpty)
    choice.paths = [try WorkResourcePath(path: ["Arena/one"]), try WorkResourcePath(path: ["Arena/two", "Project/project"])]
    XCTAssertEqual(NativeGrantSelection.arenaCoverage(choice, available: ["one"]), ["one"])
    choice.paths = []
    XCTAssertTrue(NativeGrantSelection.arenaCoverage(choice, available: ["one"]).isEmpty)
  }
  func testAllArenaScopeCannotExceedMemberWireLimit() throws {
    let f = try fixtures()[0]
    var ceiling = f["ceiling"] as! [String: Any]
    ceiling["schema"] = "devgraph.access-draft.v7"
    ceiling.removeValue(forKey: "not_before"); ceiling.removeValue(forKey: "not_after")
    ceiling["validity"] = ["schema": "castalia.grant-validity.v1", "mode": "until_revoked", "not_before": 1]
    ceiling["read_grants"] = [["scope": "devgraph.arena.read", "all_arenas": true]]
    let scopes = try (0..<257).map { index in
      WorkScopeOption(resource_path: try WorkResourcePath(path: ["Arena/arena-\(index)"]),
        resource: "Arena/arena-\(index)", title: "Arena", parent: nil)
    }
    var choice = NativeGrantChoice(); choice.wholeGraph = true
    choice.arenaIDs = NativeGrantSelection.arenaCoverage(choice, available: (0..<257).map { "arena-\($0)" })
    XCTAssertThrowsError(try NativeGrantSelection.make(ceiling: ceiling, ceilingDigest: GrantJSON.digest(ceiling),
      recipient: NativeGrantRecipient(f["recipient"] as! [String: Any]), choice: choice, scopes: scopes, now: f["now"] as! Int))
  }
  private func fixtures() throws -> [[String: Any]] {
    let url = try XCTUnwrap(Bundle.module.url(forResource: "native-grants", withExtension: "json", subdirectory: "Fixtures"))
    return try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [[String: Any]])
  }
  func testAllArenaOwnerCeilingProducesOnlyExplicitMemberIDs() throws {
    let f = try fixtures()[0]
    var ceiling = f["ceiling"] as! [String:Any]
    ceiling["schema"] = "devgraph.access-draft.v7"
    ceiling.removeValue(forKey:"not_before"); ceiling.removeValue(forKey:"not_after")
    ceiling["validity"] = ["schema":"castalia.grant-validity.v1","mode":"until_revoked","not_before":1]
    var reads = ceiling["read_grants"] as! [[String:Any]]
    reads.append(["scope":"devgraph.arena.read","all_arenas":true]); ceiling["read_grants"] = reads
    let path = try WorkResourcePath(path:["Arena/future-arena"])
    let scopes = [WorkScopeOption(resource_path:path,resource:"Arena/future-arena",title:"Future Arena",parent:nil)]
    var choice = NativeGrantChoice(); choice.wholeGraph = true; choice.untilRevoked = true; choice.arenaIDs = ["future-arena"]
    let result = try NativeGrantSelection.make(ceiling:ceiling,ceilingDigest:try GrantJSON.digest(ceiling),recipient:NativeGrantRecipient(f["recipient"] as! [String:Any]),choice:choice,scopes:scopes,now:f["now"] as! Int)
    let read = result["read"] as! [String:Any]
    XCTAssertEqual(read["schema"] as? String,"devgraph.access-draft.v6")
    let granted = (read["read_grants"] as! [[String:Any]])[0]
    XCTAssertEqual(granted["arena_ids"] as? [String],["future-arena"])
    XCTAssertNil(granted["all_arenas"])
    choice.arenaIDs = ["not-shared-in-catalog"]
    XCTAssertThrowsError(try NativeGrantSelection.make(ceiling:ceiling,ceilingDigest:try GrantJSON.digest(ceiling),recipient:NativeGrantRecipient(f["recipient"] as! [String:Any]),choice:choice,scopes:scopes,now:f["now"] as! Int))
  }
  func testSelectionsMatchEstablishedProducerWithoutCombiningRuleAuthority() throws {
    for item in try fixtures() {
      let paths = try JSONDecoder().decode([WorkResourcePath].self, from: GrantJSON.data(item["paths"]!))
      let scopes = paths.map { WorkScopeOption(resource_path: $0, resource: $0.path.last!, title: "Fixture", parent: nil) }
      var choice = NativeGrantChoice()
      choice.arenaIDs = Set(item["arenas"] as? [String] ?? []); choice.reads = Set(item["reads"] as! [String]); choice.writes = Set(item["writes"] as! [String]); choice.kinds = Set(item["kinds"] as! [String])
      choice.paths = paths; choice.wholeGraph = paths.isEmpty
      choice.untilRevoked = item["end"] is NSNull
      if let end = GrantJSON.integer(item["end"]) { choice.expiry = Date(timeIntervalSince1970: Double(end)) }
      let actual = try NativeGrantSelection.make(ceiling: item["ceiling"] as! [String: Any], ceilingDigest: item["digest"] as! String,
        recipient: NativeGrantRecipient(item["recipient"] as! [String: Any]), choice: choice, scopes: scopes, now: item["now"] as! Int)
      XCTAssertEqual(String(decoding: try GrantJSON.data(actual), as: UTF8.self), String(decoding: try GrantJSON.data(item["expected"]!), as: UTF8.self), item["name"] as! String)
    }
  }
  func testMissingScopeUnknownBranchesAndNoIntersectionNeverBecomeGlobal() throws {
    let f = try fixtures()[0], ceiling = f["ceiling"] as! [String: Any], recipient = try NativeGrantRecipient(f["recipient"] as! [String: Any])
    var choice = NativeGrantChoice(); choice.kinds = ["Task"]; choice.reads = ["get"]
    func make(_ c: [String: Any], _ scopes: [WorkScopeOption] = []) throws {
      _ = try NativeGrantSelection.make(ceiling: c, ceilingDigest: f["digest"] as! String, recipient: recipient, choice: choice, scopes: scopes, now: f["now"] as! Int)
    }
    XCTAssertThrowsError(try make(ceiling))
    let outside = try WorkResourcePath(path: ["Arena/outside"])
    choice.paths = [outside]; XCTAssertThrowsError(try make(ceiling))
    var bound = ceiling
    var read = (ceiling["read_grants"] as! [[String: Any]])[0]
    read["resource_paths"] = [["schema": "devgraph.resource-path.v1", "path": ["Arena/inside"]]]
    read["schema"] = "devgraph.path-read-grant.v1"; bound["read_grants"] = [read]
    XCTAssertThrowsError(try make(bound, [WorkScopeOption(resource_path: outside, resource: "Arena/outside", title: "Outside", parent: nil)]))
    choice.wholeGraph = true; XCTAssertThrowsError(try make(ceiling), "Global and path selection must be mutually exclusive")
  }
  func testDelegationAndFutureAuthorityFieldsAreRejectedRatherThanCarriedThrough() throws {
    let f = try fixtures()[0], recipient = try NativeGrantRecipient(f["recipient"] as! [String: Any])
    var choice = NativeGrantChoice(); choice.wholeGraph = true; choice.kinds = ["Task"]; choice.reads = ["get"]
    func rejects(_ ceiling: [String: Any]) {
      XCTAssertThrowsError(try NativeGrantSelection.make(ceiling: ceiling, ceilingDigest: f["digest"] as! String, recipient: recipient, choice: choice, scopes: [], now: f["now"] as! Int))
    }
    var ceiling = f["ceiling"] as! [String: Any]; ceiling["allow_delegation"] = true; rejects(ceiling)
    ceiling = f["ceiling"] as! [String: Any]
    var read = ceiling["read_grants"] as! [[String: Any]]; read[0]["allow_delegation"] = true; ceiling["read_grants"] = read; rejects(ceiling)
    ceiling = f["ceiling"] as! [String: Any]
    ceiling["write_grants"] = [["operation": "access.delegate", "resources": [["kind": "Task"]]]]; rejects(ceiling)
  }
  func testUnboundedExpiryCannotEscapeDatedPolicyAndExplicitRecipientBinding() throws {
    let f = try fixtures()[3]; var choice = NativeGrantChoice(); choice.wholeGraph = true; choice.kinds = ["Task"]; choice.reads = ["get"]
    var ceiling = f["ceiling"] as! [String: Any]; let recipient = try NativeGrantRecipient(f["recipient"] as! [String: Any])
    func make() throws { _ = try NativeGrantSelection.make(ceiling: ceiling, ceilingDigest: f["digest"] as! String, recipient: recipient, choice: choice, scopes: [], now: f["now"] as! Int) }
    XCTAssertThrowsError(try make())
    choice.untilRevoked = false; choice.expiry = Date(timeIntervalSince1970: Double(f["now"] as! Int) + 2000); XCTAssertThrowsError(try make())
    choice.expiry = Date(timeIntervalSince1970: Double(f["now"] as! Int) + 100)
    ceiling["subject_public_key"] = String(repeating: "f", count: 64); XCTAssertThrowsError(try make())
  }
  func testArenaSelectionIsExplicitIndependentAndBoundedByV6Ceiling() throws {
    let f = try fixtures()[0]
    var ceiling = f["ceiling"] as! [String: Any]
    ceiling["schema"] = "devgraph.access-draft.v6"
    ceiling.removeValue(forKey: "not_before"); ceiling.removeValue(forKey: "not_after")
    ceiling["validity"] = ["schema": "castalia.grant-validity.v1", "mode": "until_revoked", "not_before": 1]
    var reads = ceiling["read_grants"] as! [[String: Any]]
    reads.append(["scope": "devgraph.arena.read", "arena_ids": ["one", "two"]])
    ceiling["read_grants"] = reads
    let recipient = try NativeGrantRecipient(f["recipient"] as! [String: Any])
    func make(_ choice: NativeGrantChoice) throws -> [[String: Any]] {
      let s = try NativeGrantSelection.make(ceiling: ceiling, ceilingDigest: f["digest"] as! String,
        recipient: recipient, choice: choice, scopes: [], now: f["now"] as! Int)
      return (s["read"] as! [String: Any])["read_grants"] as! [[String: Any]]
    }
    var choice = NativeGrantChoice(); choice.wholeGraph = true; choice.arenaIDs = ["one"]
    let arenaOnly = try make(choice)
    XCTAssertEqual(arenaOnly.count, 1)
    XCTAssertEqual(arenaOnly[0]["arena_ids"] as? [String], ["one"])
    XCTAssertNil(arenaOnly[0]["operations"])
    choice.arenaIDs = ["private"]
    XCTAssertThrowsError(try make(choice))
    choice.arenaIDs = []; choice.reads = ["get"]; choice.kinds = ["Task"]
    XCTAssertTrue(try make(choice).allSatisfy { $0["scope"] as? String == "devgraph.work.read" })
    choice.arenaIDs = ["two"]
    XCTAssertEqual(try make(choice).count, 2)
    ceiling["schema"] = "devgraph.access-draft.v5"
    XCTAssertThrowsError(try make(choice), "Old draft cannot hide Arena authority")
  }
  func testAmbiguousJSONAndNumbersFailBeforeDictionaryCollapse() throws {
    for invalid in [#"{"a":1,"\u0061":2}"#, #"{"a":1.0}"#, #"{"a":-1}"#, #"{"a":9007199254740992}"#, #"{"a":01}"#] {
      XCTAssertThrowsError(try GrantJSON.object(Data(invalid.utf8)))
    }
    XCTAssertNil(GrantJSON.integer(true)); XCTAssertNil(GrantJSON.integer(1.5)); XCTAssertEqual(GrantJSON.integer(1), 1)
    XCTAssertEqual(try GrantJSON.object(Data(#"{"a":1,"b":false}"#.utf8))["a"] as? Int, 1)
  }
}
#endif
