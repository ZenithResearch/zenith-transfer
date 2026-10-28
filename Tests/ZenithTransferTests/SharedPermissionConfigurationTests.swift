#if os(macOS)
import AppKit
import SwiftUI
import XCTest
@testable import ZenithKit
@testable import CastaliaCustody
@testable import ZenithTransfer

final class SharedPermissionConfigurationTests: XCTestCase {
  private func context() throws -> (RegisteredResource, NativeOperatorInbox, [String: Any], WorkResourcePath) {
    let config = try WorkAccessConfiguration(name: "Synthetic graph", receiver: URL(string: "https://fixture.example")!, issuer: "fixture", keyID: "fixture", publicKey: String(repeating: "12", count: 32))
    let resource = try RegisteredResource(configuration: config)
    let url = try XCTUnwrap(Bundle.module.url(forResource: "native-grants", withExtension: "json", subdirectory: "Fixtures"))
    let fixture = try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [[String: Any]]).first!
    let ceiling = fixture["ceiling"] as! [String: Any]
    let path = try WorkResourcePath(path: ["Arena/design", "Project/dashboard"])
    var catalog: [String: Any] = ["schema":"devgraph.access-catalog.v1", "issuer":config.issuer, "receiver":config.authorityOrigin,
      "revision":1, "presets":[["id":"reader", "name":"Reader", "version":1, "read_operations":["get", "list"], "write_operations":[String]()]],
      "published_paths":[Any](), "policy_digest_sha256":String(repeating:"a", count:64)]
    catalog["catalog_digest_sha256"] = try GrantJSON.digest(catalog)
    let row: [String: Any] = ["resource_path":["schema":path.schema, "path":path.path], "resource":"Project/dashboard", "title":"Dashboard", "parent":"Arena/design"]
    let otherPath = try WorkResourcePath(path:["Arena/research","Project/lab"])
    let other: [String:Any] = ["resource_path":["schema":otherPath.schema,"path":otherPath.path],"resource":"Project/lab","title":"Lab","parent":"Arena/research"]
    let raw: [String: Any] = ["ceiling":ceiling, "ceiling_digest_sha256":try GrantJSON.digest(ceiling),
      "catalog":catalog, "scopes":[row,other], "inbox":["items":[fixture["recipient"]!], "total":1], "activation":["read":true,"write":true,"mixed":true]]
    return (resource, try NativeOperatorInbox(raw, resource:resource), fixture["recipient"] as! [String:Any], path)
  }
  private func recipient(_ raw: [String: Any], inbox: NativeOperatorInbox, preset: Bool, paths: [WorkResourcePath]? = nil) throws -> NativeGrantRecipient {
    var request = raw
    var preference: [String: Any] = ["catalog_digest_sha256":inbox.catalog!.catalog_digest_sha256,
      "id":preset ? "reader" as Any : NSNull(), "version":preset ? 1 as Any : NSNull()]
    if let paths { preference["resource_paths"] = try JSONSerialization.jsonObject(with: JSONEncoder().encode(paths)) }
    request["intent"] = ["schema":"devgraph.access-intent.v2", "preference":preference]
    return try NativeGrantRecipient(request)
  }
  func testPresetAdapterRoundTripsExistingRecipesAndRefusesUnsupportedActions() throws {
    for preset in CredentialPresetRevision.builtins {
      XCTAssertEqual(try TransferPresetPermissionAdapter.stored(TransferPresetPermissionAdapter.canonical(preset.writeOperations)), preset.writeOperations)
    }
    XCTAssertThrowsError(try TransferPresetPermissionAdapter.stored(["devgraph.arena.create.v1"]))
    XCTAssertThrowsError(try TransferPresetPermissionAdapter.stored(["devgraph.work.patch.v2", "devgraph.work.accept.v2"]))
  }
  func testMissingIntentAndMissingPreferenceFieldsNeverSelectAll() throws {
    let (_, inbox, raw, _) = try context()
    let none = try NativeRequestedConfiguration(recipient:NativeGrantRecipient(raw), inbox:inbox)
    XCTAssertFalse(none.hasRequestedFields)
    let unspecified = try NativeRequestedConfiguration(recipient:recipient(raw,inbox:inbox,preset:false),inbox:inbox)
    XCTAssertFalse(unspecified.locksScope); XCTAssertFalse(unspecified.locksPermissions)
    XCTAssertNil(unspecified.paths); XCTAssertNil(unspecified.reference)
    let emptyPaths = try recipient(raw,inbox:inbox,preset:false,paths:[])
    let empty = try NativeRequestedConfiguration(recipient:emptyPaths,inbox:inbox)
    XCTAssertFalse(empty.hasRequestedFields)
    var expanded = emptyPaths.raw
    var intent = expanded["intent"] as! [String:Any]
    intent["read_grants"] = [Any](); intent["write_grants"] = [Any](); expanded["intent"] = intent
    XCTAssertFalse(try NativeRequestedConfiguration(recipient:NativeGrantRecipient(expanded),inbox:inbox).hasRequestedFields)
    intent["write_grants"] = [["operation":"unrequested"]]; expanded["intent"] = intent
    XCTAssertThrowsError(try NativeRequestedConfiguration(recipient:NativeGrantRecipient(expanded),inbox:inbox))
  }
  func testPresetOnlyAllowsNineteenBranchesAcrossRulesWithoutChangingRequestedActions() throws {
    let (_,inbox,raw,_) = try context()
    let recipient = try recipient(raw,inbox:inbox,preset:true)
    let value = try NativeRequestedConfiguration(recipient:recipient,inbox:inbox)
    let paths = try (0..<19).map { try WorkResourcePath(path:["Project/p-\($0)"]) }
    let scopes = paths.map { WorkScopeOption(resource_path:$0,resource:$0.path.last!,title:"Fixture",parent:nil) }
    var first=NativeGrantChoice(); first.reads=["get","list"];first.kinds=["Task"];first.paths=Array(paths.prefix(16))
    var second=first;second.paths=Array(paths.suffix(3))
    try value.validate([first,second])
    let compiled=try NativeGrantSelection.makeRules(ceiling:inbox.ceiling,ceilingDigest:inbox.digest,recipient:recipient,rules:[first,second],scopes:scopes,now:100)
    let grants=(compiled["read"] as! [String:Any])["read_grants"] as! [[String:Any]]
    XCTAssertEqual(Set(try grants.flatMap { try NativeGrantSelection.paths($0) }),Set(paths))
    second.writes=["devgraph.work.patch.v2"]
    XCTAssertThrowsError(try value.validate([first,second]))
  }
  func testPathOnlyAllowsDifferentActionsByRequestedBranchButPreservesExactUnion() throws {
    let (_,inbox,raw,path) = try context()
    let other=try WorkResourcePath(path:["Arena/research","Project/lab"])
    let request=try recipient(raw,inbox:inbox,preset:false,paths:[path,other])
    let value=try NativeRequestedConfiguration(recipient:request,inbox:inbox)
    var first=NativeGrantChoice(); first.reads=["get"];first.kinds=["Task"];first.paths=[path]
    var second=NativeGrantChoice(); second.writes=["devgraph.work.patch.v2"];second.kinds=["Task"];second.paths=[other]
    try value.validate([first,second])
    XCTAssertThrowsError(try value.validate([first]))
    let compiled=try NativeGrantSelection.makeRules(ceiling:inbox.ceiling,ceilingDigest:inbox.digest,recipient:request,rules:[first,second],scopes:inbox.scopes,now:100)
    try value.validateCompiled(compiled)
    second.paths=[try WorkResourcePath(path:["Arena/research"])]
    XCTAssertThrowsError(try value.validate([first,second]))
  }
  func testPartialPresetPinsActionsAndLeavesScopeAndValidityEditable() throws {
    let (_, inbox, raw, _) = try context()
    let value = try NativeRequestedConfiguration(recipient:recipient(raw,inbox:inbox,preset:true),inbox:inbox)
    XCTAssertTrue(value.locksPermissions); XCTAssertFalse(value.locksScope)
    XCTAssertEqual(value.reference?["version"] as? UInt64,1)
    var choice = NativeGrantChoice(); choice.reads = ["get","list"]; choice.wholeGraph = true
    try value.validate([choice])
    choice.untilRevoked = false; choice.expiry = Date(timeIntervalSince1970:200)
    try value.validate([choice])
    choice.writes = ["devgraph.work.patch.v2"]
    XCTAssertThrowsError(try value.validate([choice]))
  }
  func testPathsLockExactlyAndCannotBeWidenedNarrowedOrDroppedOnCompile() throws {
    let (_, inbox, raw, path) = try context()
    let value = try NativeRequestedConfiguration(recipient:recipient(raw,inbox:inbox,preset:false,paths:[path]),inbox:inbox)
    XCTAssertTrue(value.locksScope); XCTAssertFalse(value.locksPermissions)
    var choice = NativeGrantChoice(); choice.paths = [path]; choice.reads = ["get"]; choice.kinds = ["Task"]
    try value.validate([choice])
    let compiled = try NativeGrantSelection.makeRules(ceiling:inbox.ceiling,ceilingDigest:inbox.digest,recipient:NativeGrantRecipient(raw),rules:[choice],scopes:inbox.scopes,now:100)
    try value.validateCompiled(compiled)
    choice.paths = []; choice.wholeGraph = true
    XCTAssertThrowsError(try value.validate([choice]))
    var tampered = compiled
    var read = tampered["read"] as! [String:Any]
    var rows = read["read_grants"] as! [[String:Any]]
    rows[0].removeValue(forKey:"resource_paths"); read["read_grants"] = rows; tampered["read"] = read
    XCTAssertThrowsError(try value.validateCompiled(tampered))
  }
  func testStaleCatalogMismatchedPresetAndUnknownRequestedFieldsFailClosed() throws {
    let (_, inbox, raw, path) = try context()
    let request = try recipient(raw,inbox:inbox,preset:true,paths:[path])
    for change in ["digest","version","id","unknown","nested"] {
      var value = request.raw
      var intent = value["intent"] as! [String:Any]
      var preference = intent["preference"] as! [String:Any]
      switch change {
      case "digest": preference["catalog_digest_sha256"] = String(repeating:"f",count:64)
      case "version": preference["version"] = 2
      case "id": preference["id"] = "missing"
      case "unknown": preference["delegation"] = true
      default:
        var rows = preference["resource_paths"] as! [[String:Any]]
        rows[0]["unrecognized"] = true; preference["resource_paths"] = rows
      }
      intent["preference"] = preference; value["intent"] = intent
      XCTAssertThrowsError(try NativeRequestedConfiguration(recipient:NativeGrantRecipient(value),inbox:inbox),change)
    }
    var legacy = raw; legacy["intent"] = ["read_grants":[Any](),"write_grants":[Any]()]
    XCTAssertThrowsError(try NativeRequestedConfiguration(recipient:NativeGrantRecipient(legacy),inbox:inbox))
  }
  @MainActor func testModelKeepsRequestedFieldsWhileCompletingMissingChoicesWithoutRPC() throws {
    let (resource,inbox,raw,path) = try context()
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at:root) }
    let repo = try WalletRepository(directory:root.appendingPathComponent("wallet"))
    let bridge = TransferOperatorBridge(resource:resource,repository:repo,journalDirectory:root.appendingPathComponent("journal"),rpcExchange:{_,_ in XCTFail("Configuration must not send requests");throw NativeGrantError.invalid})
    defer { bridge.cancel() }
    let model = NativeCredentialModel(bridge:bridge); model.inbox = inbox
    model.select(try recipient(raw,inbox:inbox,preset:true,paths:[path]))
    XCTAssertNil(model.requestConfigurationError); XCTAssertFalse(model.hierarchyMode)
    XCTAssertEqual(model.choice.paths,[path]); XCTAssertEqual(model.choice.reads,["get","list"])
    model.changeScope("global"); XCTAssertFalse(model.choice.wholeGraph)
    let library = TransferPresetLibrary(directory:root.appendingPathComponent("presets"))
    model.applyPreset("local:" + CredentialPresetRevision.builtins[0].id,library:library)
    XCTAssertEqual(model.presetID,"server:reader")
    model.choice.untilRevoked = false; model.editedPermissions()
    XCTAssertEqual(model.presetID,"server:reader")
    model.addRule(); XCTAssertEqual(model.ruleDrafts.count,2)
    XCTAssertEqual(model.choice.paths,[path]);XCTAssertEqual(model.choice.reads,["get","list"])
    XCTAssertNil(try bridge.retainedNativeAction()); XCTAssertNil(bridge.consent)
    model.select(try NativeGrantRecipient(raw)); XCTAssertFalse(model.hierarchyMode)
    model.beginHierarchySelection(); XCTAssertTrue(model.hierarchyMode)
  }
  @MainActor func testRenderSharedPermissionSurfaceWithSyntheticDataWhenRequested() throws {
    guard let output = ProcessInfo.processInfo.environment["TRANSFER_SHARED_EDITOR_QA"] else { throw XCTSkip("Optional synthetic UI render") }
    for locked in [false,true] {
      let view = NSHostingView(rootView:VStack(alignment:.leading,spacing:16) {
        Text(locked ? "Requested permissions · complete remaining choices" : "Credential preset · permissions").font(.title2)
        TransferPermissionEditor(reads:.constant(["list","get"]),writes:.constant(["devgraph.work.patch.v2"]),arenaRead:.constant(false),locked:locked)
        Text(locked ? "Scope and duration are not specified by this request." : "Scope, Wallet and duration are selected when provisioning access.")
      }.padding(24).frame(width:740,height:650,alignment:.topLeading).background(Color.white).environment(\.colorScheme,.light))
      view.frame=NSRect(x:0,y:0,width:740,height:650);view.layoutSubtreeIfNeeded()
      let bitmap=try XCTUnwrap(view.bitmapImageRepForCachingDisplay(in:view.bounds));view.cacheDisplay(in:view.bounds,to:bitmap)
      try XCTUnwrap(bitmap.representation(using:.png,properties:[:])).write(to:URL(fileURLWithPath:output).appendingPathComponent(locked ? "requested-permissions.png" : "preset-permissions.png"))
    }
    let comparison = NSHostingView(rootView:HStack(alignment:.top,spacing:32) {
      VStack(alignment:.leading,spacing:16) {
        Text("Preset · permission recipe").font(.title2)
        TransferPermissionEditor(reads:.constant(["list","get"]),writes:.constant(["devgraph.work.patch.v2"]),arenaRead:.constant(false))
        Text("Existing preset format: permissions only.").font(.caption)
      }.frame(maxWidth:.infinity,alignment:.leading)
      Divider()
      VStack(alignment:.leading,spacing:16) {
        Text("Individual grant · no requested fields").font(.title2)
        TransferPermissionEditor(reads:.constant(["list","get"]),writes:.constant(["devgraph.work.patch.v2"]),arenaRead:.constant(false),availableWrites:Set(DevGraphPermissionCatalog.writes.map(\.id)))
        Text("Resource scope and duration are chosen for the recipient Wallet.").font(.caption)
      }.frame(maxWidth:.infinity,alignment:.leading)
    }.padding(24).frame(width:1480,height:650,alignment:.topLeading).background(Color.white).environment(\.colorScheme,.light))
    comparison.frame=NSRect(x:0,y:0,width:1480,height:650);comparison.layoutSubtreeIfNeeded()
    let bitmap=try XCTUnwrap(comparison.bitmapImageRepForCachingDisplay(in:comparison.bounds));comparison.cacheDisplay(in:comparison.bounds,to:bitmap)
    try XCTUnwrap(bitmap.representation(using:.png,properties:[:])).write(to:URL(fileURLWithPath:output).appendingPathComponent("shared-configuration-comparison.png"))
  }
}
#endif
