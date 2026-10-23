#if os(macOS)
import Foundation
import XCTest
@testable import ZenithKit
@testable import ZenithTransfer

final class NativeGrantSelectionTests: XCTestCase {
  private func fixtures() throws -> [[String: Any]] {
    let url = try XCTUnwrap(Bundle.module.url(forResource: "native-grants", withExtension: "json", subdirectory: "Fixtures"))
    return try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [[String: Any]])
  }
  func testSelectionsMatchEstablishedProducerWithoutCombiningRuleAuthority() throws {
    for item in try fixtures() {
      let paths = try JSONDecoder().decode([WorkResourcePath].self, from: GrantJSON.data(item["paths"]!))
      let scopes = paths.map { WorkScopeOption(resource_path: $0, resource: $0.path.last!, title: "Fixture", parent: nil) }
      var choice = NativeGrantChoice()
      choice.reads = Set(item["reads"] as! [String]); choice.writes = Set(item["writes"] as! [String]); choice.kinds = Set(item["kinds"] as! [String])
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
  func testAmbiguousJSONAndNumbersFailBeforeDictionaryCollapse() throws {
    for invalid in [#"{"a":1,"\u0061":2}"#, #"{"a":1.0}"#, #"{"a":-1}"#, #"{"a":9007199254740992}"#, #"{"a":01}"#] {
      XCTAssertThrowsError(try GrantJSON.object(Data(invalid.utf8)))
    }
    XCTAssertNil(GrantJSON.integer(true)); XCTAssertNil(GrantJSON.integer(1.5)); XCTAssertEqual(GrantJSON.integer(1), 1)
    XCTAssertEqual(try GrantJSON.object(Data(#"{"a":1,"b":false}"#.utf8))["a"] as? Int, 1)
  }
}
#endif
