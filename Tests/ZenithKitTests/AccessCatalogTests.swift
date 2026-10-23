import Foundation
import XCTest
@testable import ZenithKit

final class AccessCatalogTests: XCTestCase {
  private func data() throws -> Data {
    try Data(contentsOf:XCTUnwrap(Bundle.module.url(forResource:"devgraph-access-catalog",withExtension:"json")))
  }
  private func catalog() throws -> WorkAccessCatalog {
    try WorkAccessCatalog.decode(data(),receiver:"https://example.test",issuer:"fixture")
  }
  func testProducerDigestUnicodeAndExactPathPreference() throws {
    let catalog = try catalog()
    XCTAssertEqual(catalog.presets.first?.name,"Contributor · Recherche 雲")
    let selected = try XCTUnwrap(catalog.scopes.first { $0.kind == "Project" }).resource_path
    let choice = try WorkAccessPreference(catalog:catalog,presetID:"contributor",paths:[selected])
    let raw = try XCTUnwrap(JSONSerialization.jsonObject(with:JSONEncoder().encode(choice)) as? [String:Any])
    XCTAssertEqual(raw["id"] as? String,"contributor")
    XCTAssertEqual(choice.resource_paths?.first?.path,["Arena/a","Initiative/root-a","Project/project-a"])
    let none = try WorkAccessPreference(catalog:catalog,presetID:nil,paths:[])
    let nulls = try XCTUnwrap(JSONSerialization.jsonObject(with:JSONEncoder().encode(none)) as? [String:Any])
    XCTAssertTrue(nulls["id"] is NSNull);XCTAssertTrue(nulls["version"] is NSNull)
    XCTAssertNil(nulls["resource_paths"])
    XCTAssertThrowsError(try WorkAccessPreference(catalog:catalog,presetID:"administrator",paths:[]))
    XCTAssertThrowsError(try WorkAccessPreference(catalog:catalog,presetID:nil,paths:[selected,selected]))
    XCTAssertThrowsError(try WorkAccessPreference(catalog:catalog,presetID:nil,paths:[WorkResourcePath(path:["Arena/private"])]))
  }
  func testCatalogTamperWrongReceiverAndUnknownPathFailClosed() throws {
    var raw = try XCTUnwrap(JSONSerialization.jsonObject(with:data()) as? [String:Any])
    var presets = raw["presets"] as! [[String:Any]];presets[0]["name"]="Altered";raw["presets"]=presets
    XCTAssertThrowsError(try WorkAccessCatalog.decode(JSONSerialization.data(withJSONObject:raw),receiver:"https://example.test",issuer:"fixture"))
    XCTAssertThrowsError(try WorkAccessCatalog.decode(data(),receiver:"https://other.test",issuer:"fixture"))
    XCTAssertThrowsError(try WorkResourcePath(path:["Project/p","Arena/a"]))
    XCTAssertThrowsError(try WorkResourcePath(path:["Task/t"]))
  }
  func testOriginalPreferenceIsImmutableAndOnlyKnownStatusCanStartAnotherRequest() throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at:directory) }
    let store = try WorkAccessRequestStore(directory:directory),catalog = try catalog()
    let choice = try WorkAccessPreference(catalog:catalog,presetID:"project-manager",paths:[])
    let first = try store.begin(receiver:catalog.receiver,subject:"a",installation:"b",preference:choice)
    XCTAssertEqual(try store.begin(receiver:catalog.receiver,subject:"a",installation:"b",preference:nil),first)
    for status in ["pending","unknown","approved_pending_activation"] {
      let result = WorkAccessRequestResult(schema:"devgraph.access-request-result.v4",request_id:first.requestID,status:status,authority_issued:false)
      XCTAssertThrowsError(try store.startNew(receiver:catalog.receiver,subject:"a",installation:"b",after:result))
    }
    let result = WorkAccessRequestResult(schema:"devgraph.access-request-result.v4",request_id:first.requestID,status:"active",authority_issued:false)
    try store.startNew(receiver:catalog.receiver,subject:"a",installation:"b",after:result)
    let next = try store.begin(receiver:catalog.receiver,subject:"a",installation:"b")
    XCTAssertNotEqual(next.requestID,first.requestID)
    let saved = try Data(contentsOf:directory.appendingPathComponent("history/"+first.requestID+".json"))
    XCTAssertEqual(try JSONDecoder().decode(WorkAccessRequestRecord.self,from:saved),first)
  }
  func testHierarchicalUnionAndIndependentGlobalPreference() throws {
    let a = try WorkResourcePath(path:["Arena/a"])
    let ap = try WorkResourcePath(path:["Arena/a","Project/p"])
    let bi = try WorkResourcePath(path:["Arena/b","Initiative/i"])
    XCTAssertEqual(try WorkScopeSelection.normalized([ap,bi,a]),[bi,a])
    XCTAssertFalse(WorkScopeSelection.covers(a,bi))
    XCTAssertThrowsError(try WorkScopeSelection.normalized((0..<17).map { try WorkResourcePath(path:["Project/p\($0)"]) }))
    let catalog = try catalog()
    let global = try WorkAccessPreference(catalog:catalog,presetID:"project-manager",paths:[])
    XCTAssertNil(global.resource_paths)
    XCTAssertEqual(global.id,"project-manager")
  }
  func testResourceTreeUsesTitlesWithoutInventingHiddenAncestors() throws {
    let catalog = try catalog(), tree = WorkScopeSelection.tree(catalog.scopes)
    XCTAssertEqual(tree.count,1)
    XCTAssertEqual(tree.first?.children?.first?.children?.first?.id,"Project/project-a")
    XCTAssertEqual(WorkScopeSelection.label(try XCTUnwrap(catalog.scopes.last).resource_path,scopes:catalog.scopes),"Arena: A → Initiative: Fixture → Project: Fixture")
    let scope = WorkScopeOption(resource_path:try WorkResourcePath(path:["Project/p"]),resource:"Project/p",title:"Visible project",parent:nil)
    let standalone = WorkScopeSelection.tree([scope])
    XCTAssertEqual(standalone.count,1)
    XCTAssertNil(standalone.first?.children)
  }

}
