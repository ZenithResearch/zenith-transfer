#if os(macOS)
import Foundation
import AppKit
import SwiftUI
import XCTest
@testable import ZenithKit
@testable import CastaliaCustody
@testable import ZenithTransfer

final class NativePermissionRulesTests: XCTestCase {
  private func context() throws -> ([String: Any], NativeGrantRecipient) {
    let url = try XCTUnwrap(Bundle.module.url(forResource: "native-grants", withExtension: "json", subdirectory: "Fixtures"))
    let fixture = (try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as! [[String: Any]])[0]
    var ceiling = fixture["ceiling"] as! [String: Any]
    ceiling["write_grants"] = DevGraphPermissionCatalog.writes.map { action in
      ["operation": action.id, "resources": action.kinds.map { ["kind": $0] }] as [String: Any]
    }
    return (ceiling, try NativeGrantRecipient(fixture["recipient"] as! [String: Any]))
  }
  private func compile(_ rules: [NativeGrantChoice], ceiling: [String: Any], recipient: NativeGrantRecipient,
                       scopes: [WorkScopeOption] = []) throws -> [String: Any] {
    try NativeGrantSelection.makeRules(ceiling: ceiling, ceilingDigest: GrantJSON.digest(ceiling),
      recipient: recipient, rules: rules, scopes: scopes, now: 100)
  }
  func testIndependentReadAndWriteHierarchiesNeverProduceCrossProduct() throws {
    let (ceiling, recipient) = try context()
    let a = try WorkResourcePath(path: ["Arena/a"]), b = try WorkResourcePath(path: ["Arena/b", "Project/b"])
    let scopes = [a, b].map { WorkScopeOption(resource_path: $0, resource: $0.path.last!, title: "Fixture", parent: nil) }
    var read = NativeGrantChoice(); read.kinds = ["Task"]; read.reads = ["get"]; read.paths = [a]
    var write = NativeGrantChoice(); write.kinds = ["Task"]; write.writes = ["devgraph.work.patch.v2"]; write.paths = [b]
    let result = try compile([read, write], ceiling: ceiling, recipient: recipient, scopes: scopes)
    if let directory = ProcessInfo.processInfo.environment["NATIVE_PERMISSION_REPORT_DIRECTORY"] {
      try GrantJSON.data(result).write(to: URL(fileURLWithPath: directory).appendingPathComponent("read-a-write-b.json"))
    }
    let reads = (result["read"] as! [String: Any])["read_grants"] as! [[String: Any]]
    let writes = (result["write"] as! [String: Any])["write_grants"] as! [[String: Any]]
    XCTAssertEqual(try NativeGrantSelection.paths(reads[0]), [a])
    XCTAssertEqual(try NativeGrantSelection.paths(writes[0]), [b])
    XCTAssertEqual(writes[0]["operation"] as? String, "devgraph.work.patch.v2")
    XCTAssertNil(result["preset"], "Several independent rules cannot claim one flat preset")
  }
  func testHierarchyColumnsCompileWithoutCrossingReadAndWriteScopes() throws {
    let (ceiling, recipient) = try context()
    let parent = try WorkResourcePath(path: ["Arena/a"])
    let child = try WorkResourcePath(path: ["Arena/a", "Project/p"])
    let sibling = try WorkResourcePath(path: ["Arena/b"])
    var selection = NativeHierarchyPermissions()
    try selection.set(parent, .read, enabled: true)
    try selection.set(child, .write, enabled: true)
    XCTAssertTrue(selection.inherited(child, .read))
    XCTAssertFalse(selection.includes(parent, .write))
    XCTAssertFalse(selection.includes(sibling, .read))
    let rules = try selection.rules(permissions: NativeGrantPermissions(ceiling), validity: NativeGrantChoice())
    let scopes = [parent, child].map { WorkScopeOption(resource_path: $0, resource: $0.path.last!, title: "Fixture", parent: nil) }
    let result = try compile(rules, ceiling: ceiling, recipient: recipient, scopes: scopes)
    let reads = (result["read"] as! [String: Any])["read_grants"] as! [[String: Any]]
    let writes = (result["write"] as! [String: Any])["write_grants"] as! [[String: Any]]
    XCTAssertEqual(try NativeGrantSelection.paths(reads[0]), [parent])
    XCTAssertEqual(try NativeGrantSelection.paths(writes[0]), [child])
    XCTAssertEqual(Set(writes.compactMap { $0["operation"] as? String }), NativeHierarchyPermissions.writeActions)
  }
  func testHierarchyParentNormalizationDoesNotRemoveOtherColumn() throws {
    let parent = try WorkResourcePath(path: ["Arena/a"])
    let child = try WorkResourcePath(path: ["Arena/a", "Project/p"])
    var selection = NativeHierarchyPermissions()
    try selection.set(child, .read, enabled: true)
    try selection.set(child, .write, enabled: true)
    try selection.set(parent, .read, enabled: true)
    XCTAssertEqual(selection.readPaths, [parent]); XCTAssertEqual(selection.writePaths, [child])
    try selection.set(parent, .read, enabled: false)
    XCTAssertTrue(selection.readPaths.isEmpty); XCTAssertEqual(selection.writePaths, [child])
  }
  func testHierarchyDoesNotAddParentArenaRecordForProjectRead() throws {
    var (ceiling, _) = try context()
    ceiling["schema"] = "devgraph.access-draft.v6"
    var rows = ceiling["read_grants"] as! [[String: Any]]
    rows.append(["scope": "devgraph.arena.read", "arena_ids": ["a"]]); ceiling["read_grants"] = rows
    let permissions = try NativeGrantPermissions(ceiling)
    let parent = try WorkResourcePath(path: ["Arena/a"])
    let child = try WorkResourcePath(path: ["Arena/a", "Project/p"])
    var selection = NativeHierarchyPermissions()
    try selection.set(child, .read, enabled: true)
    XCTAssertTrue(try selection.rules(permissions: permissions, validity: NativeGrantChoice())[0].arenaIDs.isEmpty)
    try selection.set(parent, .read, enabled: true)
    XCTAssertEqual(try selection.rules(permissions: permissions, validity: NativeGrantChoice())[0].arenaIDs, ["a"])
  }
  func testHierarchyRejectsUnavailableWriteAndNeverEnablesCreationOrDelegation() throws {
    var (ceiling, _) = try context(); ceiling["write_grants"] = [[String: Any]]()
    var selection = NativeHierarchyPermissions()
    try selection.set(WorkResourcePath(path: ["Arena/a"]), .write, enabled: true)
    XCTAssertThrowsError(try selection.rules(permissions: NativeGrantPermissions(ceiling), validity: NativeGrantChoice()))
    XCTAssertEqual(NativeHierarchyPermissions.writeActions, ["devgraph.work.patch.v2"])
  }
  func testHierarchyBranchBudgetPreservesPreviousDraftOnFailure() throws {
    var selection = NativeHierarchyPermissions()
    for i in 0..<16 { try selection.set(WorkResourcePath(path: ["Arena/a-\(i)"]), .read, enabled: true) }
    let previous = selection
    XCTAssertThrowsError(try selection.set(WorkResourcePath(path: ["Arena/overflow"]), .read, enabled: true))
    XCTAssertEqual(selection, previous)
  }
  func testClosedWalletDiagnosticsDistinguishContextAndValidationFailures() {
    XCTAssertTrue(NativeCredentialDiagnostic.message(WalletFailure.core("service_binding_expired")).contains("connection expired"))
    XCTAssertTrue(NativeCredentialDiagnostic.message(WalletFailure.core("invalid_operator_recovery")).contains("invalid_operator_recovery"))
    XCTAssertTrue(NativeCredentialDiagnostic.message(WalletFailure.core("invalid_access_request")).contains("No decision was signed"))
    XCTAssertFalse(NativeCredentialDiagnostic.message(WalletFailure.core("private arbitrary payload")).contains("private arbitrary payload"))
  }
  @MainActor func testHierarchyAdvancedHandoffPreservesExactScopesAndValidity() throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: directory) }
    let repository = try WalletRepository(directory: directory.appendingPathComponent("wallet"))
    let configuration = try WorkAccessConfiguration(name: "Design team", receiver: URL(string: "https://fixture.example")!, issuer: "fixture", keyID: "key", publicKey: String(repeating: "12", count: 32))
    let resource = try RegisteredResource(configuration: configuration)
    let bridge = TransferOperatorBridge(resource: resource, repository: repository,
      journalDirectory: directory.appendingPathComponent("actions"), rpcExchange: { _, _ in XCTFail("Editing must not send a request"); throw NativeGrantError.invalid })
    defer { bridge.cancel() }
    var (ceiling, recipient) = try context()
    ceiling["receiver"] = configuration.authorityOrigin; ceiling["issuer"] = configuration.issuer
    let parent = try WorkResourcePath(path: ["Arena/design"])
    let child = try WorkResourcePath(path: ["Arena/design", "Project/dashboard"])
    let other = try WorkResourcePath(path: ["Arena/research"])
    let scopes = [WorkScopeOption(resource_path: parent, resource: "Arena/design", title: "Design", parent: nil),
      WorkScopeOption(resource_path: child, resource: "Project/dashboard", title: "Dashboard", parent: "Arena/design"),
      WorkScopeOption(resource_path: other, resource: "Arena/research", title: "Research", parent: nil)]
    var catalog: [String: Any] = ["schema":"devgraph.access-catalog.v1", "issuer":configuration.issuer,
      "receiver":configuration.authorityOrigin, "revision":1, "presets":[Any](), "published_paths":[Any](), "policy_digest_sha256":String(repeating:"a",count:64)]
    catalog["catalog_digest_sha256"] = try GrantJSON.digest(catalog)
    let raw: [String: Any] = ["ceiling":ceiling, "ceiling_digest_sha256":try GrantJSON.digest(ceiling),
      "inbox":["items":[recipient.raw],"total":1], "catalog":catalog,
      "scopes":scopes.map { ["resource_path":["schema":$0.resource_path.schema,"path":$0.resource_path.path],"resource":$0.resource,"title":$0.title,"parent":$0.parent as Any? ?? NSNull()] as [String:Any] }, "activation":["write":true,"mixed":true]]
    let inbox = try NativeOperatorInbox(raw, resource: resource)
    let model = NativeCredentialModel(bridge: bridge); model.inbox = inbox; model.select(recipient)
    XCTAssertTrue(model.hierarchyMode)
    model.setHierarchy(scopes[0], access: .read, enabled: true)
    model.setHierarchy(scopes[1], access: .write, enabled: true)
    model.expanded = [scopes[0].id]
    let before = try compile(model.permissionRules, ceiling: ceiling, recipient: recipient, scopes: scopes)
    if let output = ProcessInfo.processInfo.environment["NATIVE_HIERARCHY_QA_DIRECTORY"] {
      let view = NSHostingView(rootView: NativeHierarchyPermissionView(editor: model, inbox: inbox, serviceName: "DevGraph · Design team").padding(24).frame(width:900).background(Color.white).environment(\.colorScheme, .light))
      view.frame = NSRect(x:0,y:0,width:900,height:520); view.layoutSubtreeIfNeeded()
      let bitmap = try XCTUnwrap(view.bitmapImageRepForCachingDisplay(in: view.bounds))
      view.cacheDisplay(in:view.bounds,to:bitmap)
      try XCTUnwrap(bitmap.representation(using:.png, properties:[:])).write(to:URL(fileURLWithPath:output).appendingPathComponent("hierarchy-light.png"))
    }
    model.useAdvancedRules()
    XCTAssertFalse(model.hierarchyMode)
    let after = try compile(model.permissionRules, ceiling: ceiling, recipient: recipient, scopes: scopes)
    XCTAssertTrue(GrantJSON.equal(before, after))
    XCTAssertNil(try bridge.retainedNativeAction()); XCTAssertNil(bridge.consent)
  }
  func testAllTwentyNamedMutationsCompileWithTheirExplicitResourceKinds() throws {
    let (ceiling, recipient) = try context()
    XCTAssertEqual(DevGraphPermissionCatalog.writes.count, 20)
    var outputs: [[String: Any]] = []
    for action in DevGraphPermissionCatalog.writes {
      var choice = NativeGrantChoice(); choice.wholeGraph = true; choice.writes = [action.id]; choice.kinds = Set(action.kinds)
      let result = try compile([choice], ceiling: ceiling, recipient: recipient)
      outputs.append(result)
      let grants = (result["write"] as! [String: Any])["write_grants"] as! [[String: Any]]
      XCTAssertEqual(grants.map { $0["operation"] as! String }, [action.id])
      XCTAssertEqual(Set((grants[0]["resources"] as! [[String: Any]]).map { $0["kind"] as! String }), Set(action.kinds))
    }
    if let directory = ProcessInfo.processInfo.environment["NATIVE_PERMISSION_REPORT_DIRECTORY"] {
      try GrantJSON.data(outputs).write(to: URL(fileURLWithPath: directory).appendingPathComponent("all-mutations.json"))
    }
  }
  func testDecisionResourcesRemainExplicitAndCreationNeverEscapesHierarchy() throws {
    let (ceiling, recipient) = try context()
    var choice = NativeGrantChoice(); choice.kinds = ["Proposal", "Decision"]; choice.writes = ["devgraph.work.accept.v2"]
    choice.exactResources = ["Proposal": ["idea"], "Decision": ["decision"]]
    let result = try compile([choice], ceiling: ceiling, recipient: recipient)
    let grants = (result["write"] as! [String: Any])["write_grants"] as! [[String: Any]]
    let resources = grants[0]["resources"] as! [[String: Any]]
    XCTAssertEqual(resources.first { $0["kind"] as? String == "Decision" }?["ids"] as? [String], ["decision"])
    let a = try WorkResourcePath(path: ["Arena/a"])
    choice.exactResources = nil; choice.paths = [a]; choice.writes = ["devgraph.work.create.v2"]; choice.kinds = ["Task"]
    XCTAssertThrowsError(try compile([choice], ceiling: ceiling, recipient: recipient,
      scopes: [WorkScopeOption(resource_path: a, resource: "Arena/a", title: "A", parent: nil)]))
  }
  func testArenaWriteUsesExactArenaIDsInsteadOfWorkPathWildcard() throws {
    let (ceiling, recipient) = try context()
    let a = try WorkResourcePath(path: ["Arena/a", "Project/p"])
    var choice = NativeGrantChoice(); choice.paths = [a]; choice.kinds = ["Arena"]; choice.writes = ["devgraph.arena.patch.v1"]
    let result = try compile([choice], ceiling: ceiling, recipient: recipient,
      scopes: [WorkScopeOption(resource_path: a, resource: "Project/p", title: "P", parent: nil)])
    let grants = (result["write"] as! [String: Any])["write_grants"] as! [[String: Any]]
    XCTAssertNil(grants[0]["resource_paths"])
    XCTAssertEqual((grants[0]["resources"] as! [[String: Any]])[0]["ids"] as? [String], ["a"])
  }
  func testExactWorkIDsDoNotLeakArenaOrProvenanceSelectorsIntoReadGrant() throws {
    var (ceiling, recipient) = try context()
    ceiling["schema"] = "devgraph.access-draft.v6"
    var reads = ceiling["read_grants"] as! [[String: Any]]
    reads.append(["scope": "devgraph.arena.read", "arena_ids": ["a"]]); ceiling["read_grants"] = reads
    var choice = NativeGrantChoice(); choice.kinds = ["Task", "Arena", "Decision"]
    choice.reads = ["get"]; choice.arenaIDs = ["a"]
    choice.exactResources = ["Task": ["task"], "Arena": ["a"], "Decision": ["review"]]
    let result = try compile([choice], ceiling: ceiling, recipient: recipient)
    let grants = (result["read"] as! [String: Any])["read_grants"] as! [[String: Any]]
    XCTAssertEqual(grants.first { $0["scope"] as? String == "devgraph.work.read" }?["work_ids"] as? [String], ["Task/task"])
    XCTAssertEqual(grants.first { $0["scope"] as? String == "devgraph.arena.read" }?["arena_ids"] as? [String], ["a"])
  }
  func testFutureArenaSelectionStaysDynamicAndFixedSelectionsStayFixed() throws {
    var (ceiling, recipient) = try context()
    ceiling["schema"] = "devgraph.access-draft.v7"
    ceiling["read_grants"] = [["scope": "devgraph.arena.read", "all_arenas": true]]
    var choice = NativeGrantChoice(); choice.wholeGraph = true; choice.allArenas = true
    let output = try compile([choice], ceiling: ceiling, recipient: recipient)
    let draft = output["read"] as! [String: Any]
    XCTAssertEqual(draft["schema"] as? String, "devgraph.access-draft.v8")
    let row = (draft["read_grants"] as! [[String: Any]])[0]
    XCTAssertEqual(row["all_arenas"] as? Bool, true); XCTAssertNil(row["arena_ids"])
    choice.allArenas = false; choice.arenaIDs = ["existing"]
    let path = try WorkResourcePath(path: ["Arena/existing"])
    let fixed = try compile([choice], ceiling: ceiling, recipient: recipient,
      scopes: [WorkScopeOption(resource_path: path, resource: "Arena/existing", title: "Existing", parent: nil)])["read"] as! [String: Any]
    XCTAssertEqual(fixed["schema"] as? String, "devgraph.access-draft.v6")
    XCTAssertNil((fixed["read_grants"] as! [[String: Any]])[0]["all_arenas"])
    ceiling["schema"] = "devgraph.access-draft.v6"
    ceiling["read_grants"] = [["scope": "devgraph.arena.read", "arena_ids": ["existing"]]]
    choice.allArenas = true; choice.arenaIDs = []
    XCTAssertThrowsError(try compile([choice], ceiling: ceiling, recipient: recipient))
  }
  func testDynamicArenaAndFixedWorkRulesKeepNewSchemaInEitherOrder() throws {
    var (ceiling, recipient) = try context()
    ceiling["schema"] = "devgraph.access-draft.v7"
    var grants = ceiling["read_grants"] as! [[String: Any]]
    grants.append(["scope": "devgraph.arena.read", "all_arenas": true])
    ceiling["read_grants"] = grants
    var dynamic = NativeGrantChoice(); dynamic.wholeGraph = true; dynamic.allArenas = true
    var work = NativeGrantChoice(); work.wholeGraph = true; work.kinds = ["Task"]; work.reads = ["get"]
    for rules in [[dynamic, work], [work, dynamic]] {
      let draft = try compile(rules, ceiling: ceiling, recipient: recipient)["read"] as! [String: Any]
      XCTAssertEqual(draft["schema"] as? String, "devgraph.access-draft.v8")
      let rows = draft["read_grants"] as! [[String: Any]]
      XCTAssertEqual(rows.count, 2)
      XCTAssertEqual(rows.filter { $0["all_arenas"] as? Bool == true }.count, 1)
      XCTAssertEqual(rows.filter { $0["scope"] as? String == "devgraph.work.read" }.count, 1)
    }
  }
  @MainActor func testSwitchingRulesPreservesSelectionsAndExactIDTyping() throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: directory) }
    let repository = try WalletRepository(directory: directory.appendingPathComponent("wallet"))
    let configuration = try WorkAccessConfiguration(name: "Fixture", receiver: URL(string: "https://fixture.example")!, issuer: "fixture", keyID: "key", publicKey: String(repeating: "12", count: 32))
    let bridge = TransferOperatorBridge(resource: try RegisteredResource(configuration: configuration), repository: repository,
      journalDirectory: directory.appendingPathComponent("actions"), rpcExchange: { _, _ in XCTFail("Editing must not send a request"); throw NativeGrantError.invalid })
    defer { bridge.cancel() }
    let model = NativeCredentialModel(bridge: bridge)
    model.ruleDrafts = [NativeCredentialModel.RuleDraft()]
    model.choice.kinds = ["Task"]; model.choice.reads = ["get"]
    model.changeScope("exact"); model.setExactIDs("Task", text: "alpha, ")
    XCTAssertEqual(model.exactIDText["Task"], "alpha, ", "A trailing delimiter must remain typeable")
    model.setExactIDs("Task", text: "alpha, beta")
    model.addRule(); model.changeScope("global"); model.choice.writes = ["devgraph.work.patch.v2"]
    model.selectRule(0)
    XCTAssertEqual(model.choice.reads, ["get"])
    XCTAssertTrue(model.choice.writes.isEmpty)
    XCTAssertEqual(model.choice.exactResources?["Task"], ["alpha", "beta"])
    XCTAssertEqual(model.exactIDText["Task"], "alpha, beta")
    model.selectRule(1)
    XCTAssertTrue(model.choice.reads.isEmpty)
    XCTAssertEqual(model.choice.writes, ["devgraph.work.patch.v2"])
    model.removeRule()
    XCTAssertEqual(model.permissionRules.count, 1)
    XCTAssertEqual(model.choice.reads, ["get"])
    XCTAssertEqual(model.scopeMode, "exact")
  }
  func testAggregateReadBudgetAndParentRuleConditionsAreEnforced() throws {
    let (ceiling, recipient) = try context()
    var scoped: [WorkScopeOption] = [], rules: [NativeGrantChoice] = []
    for index in 0..<11 {
      let path = try WorkResourcePath(path: ["Arena/a-\(index)"])
      scoped.append(WorkScopeOption(resource_path: path, resource: path.path.last!, title: "A", parent: nil))
      var rule = NativeGrantChoice(); rule.paths = [path]; rule.kinds = ["Task"]; rule.reads = ["get", "list", "relationships"]
      rules.append(rule)
    }
    XCTAssertThrowsError(try compile(rules, ceiling: ceiling, recipient: recipient, scopes: scoped))
    var limited = ceiling
    limited["write_grants"] = [["operation": "devgraph.work.patch.v2", "resources": [["kind": "Task", "ids": ["inside"]]], "arena_ids": ["a"]]]
    var rule = NativeGrantChoice(); rule.exactResources = ["Task": ["outside"]]; rule.kinds = ["Task"]; rule.writes = ["devgraph.work.patch.v2"]
    XCTAssertThrowsError(try compile([rule], ceiling: limited, recipient: recipient))
    rule.exactResources = ["Task": ["inside"]]
    let draft = try compile([rule], ceiling: limited, recipient: recipient)["write"] as! [String: Any]
    XCTAssertEqual((draft["write_grants"] as! [[String: Any]])[0]["arena_ids"] as? [String], ["a"])
  }
  func testUnrepresentableRuleFailsWithoutSilentlyDroppingItsOperation() throws {
    let (ceiling, recipient) = try context()
    let a = try WorkResourcePath(path: ["Arena/a"])
    var choice = NativeGrantChoice(); choice.paths = [a]; choice.kinds = ["Decision"]; choice.writes = ["devgraph.work.accept.v2"]
    XCTAssertThrowsError(try compile([choice], ceiling: ceiling, recipient: recipient,
      scopes: [WorkScopeOption(resource_path: a, resource: "Arena/a", title: "A", parent: nil)]))
    choice.paths = []; choice.exactResources = ["Decision": []]
    XCTAssertThrowsError(try compile([choice], ceiling: ceiling, recipient: recipient))
  }
}
#endif
