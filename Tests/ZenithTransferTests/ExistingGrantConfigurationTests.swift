#if os(macOS)
import Foundation
import AppKit
import SwiftUI
import XCTest
@testable import CastaliaCustody
@testable import ZenithKit
@testable import ZenithTransfer

final class ExistingGrantConfigurationTests: XCTestCase {
  private func context(paths: Bool = false) throws -> (RegisteredResource, NativeOperatorInbox, [String:Any]) {
    let config = try WorkAccessConfiguration(name:"Synthetic graph", receiver:URL(string:"https://fixture.example")!, issuer:"fixture", keyID:"fixture", publicKey:String(repeating:"12",count:32))
    let resource = try RegisteredResource(configuration:config)
    let url = try XCTUnwrap(Bundle.module.url(forResource:"native-grants", withExtension:"json", subdirectory:"Fixtures"))
    let fixture = (try JSONSerialization.jsonObject(with:Data(contentsOf:url)) as! [[String:Any]])[0]
    let ceiling = fixture["ceiling"] as! [String:Any]
    let recipient = try NativeGrantRecipient(fixture["recipient"] as! [String:Any])
    let a = try WorkResourcePath(path:["Arena/a"]), b = try WorkResourcePath(path:["Arena/b", "Project/b"])
    let scopes = [a,b].map { WorkScopeOption(resource_path:$0, resource:$0.path.last!, title:"Fixture", parent:nil) }
    var read = NativeGrantChoice(); read.kinds = ["Task"]; read.reads = ["get","list"]
    read.wholeGraph = !paths; read.paths = paths ? [a] : []
    var write = NativeGrantChoice(); write.kinds = ["Task"]; write.writes = ["devgraph.work.patch.v2"]
    write.wholeGraph = !paths; write.paths = paths ? [b] : []
    var selection = try NativeGrantSelection.makeRules(ceiling:ceiling, ceilingDigest:GrantJSON.digest(ceiling), recipient:recipient, rules:[read,write], scopes:scopes, now:100)
    for side in ["read","write"] { var draft=selection[side] as! [String:Any];draft["lifetime_seconds"]=120;selection[side]=draft }
    var grant = recipient.raw
    grant["version"] = 2; grant["access_mode"] = "read_write"
    grant["assignment_digest"] = try GrantJSON.digest(selection["read"]!)
    grant["write_assignment_digest"] = try GrantJSON.digest(selection["write"]!)
    grant["configuration"] = ["schema":NativeExistingGrantConfiguration.schema,"selection":selection]
    var catalog:[String:Any] = ["schema":"devgraph.access-catalog.v1","issuer":config.issuer,"receiver":config.authorityOrigin,
      "revision":1,"presets":[["id":"reader","name":"Reader","version":1,"read_operations":["get","list"],"write_operations":[String]()]],"published_paths":[Any](),"policy_digest_sha256":String(repeating:"a",count:64)]
    catalog["catalog_digest_sha256"] = try GrantJSON.digest(catalog)
    let raw:[String:Any] = ["ceiling":ceiling,"ceiling_digest_sha256":try GrantJSON.digest(ceiling),
      "inbox":["items":[Any](),"total":0],"active_grants":[grant],
      "catalog":catalog,"scopes":scopes.map { ["resource_path":["schema":$0.resource_path.schema,"path":$0.resource_path.path],"resource":$0.resource,"title":$0.title,"parent":$0.resource_path.path.dropLast().last.map { $0 as Any } ?? NSNull()] },
      "activation":["read":true,"write":true,"mixed":true,"read_action_schema":"devgraph.access-operator-action.v6",
        "write_action_schema":"devgraph.access-operator-action.v7","configure_existing_grants":NativeExistingGrantConfiguration.schema]]
    return (resource,try NativeOperatorInbox(raw,resource:resource),grant)
  }
  func testHydratesIndependentReadAndWriteScopesWithoutCrossProduct() throws {
    let (_,inbox,grant)=try context(paths:true)
    let value=try NativeExistingGrantConfiguration(grant:grant,inbox:inbox,now:100)
    XCTAssertEqual(value.recipient.version,2);XCTAssertEqual(value.rules.count,2)
    XCTAssertEqual(value.rules[0].paths[0].path,["Arena/a"])
    XCTAssertEqual(value.rules[1].paths[0].path,["Arena/b","Project/b"])
    XCTAssertTrue(value.rules[0].writes.isEmpty);XCTAssertTrue(value.rules[1].reads.isEmpty)
    let compiled=try NativeGrantSelection.makeRules(ceiling:inbox.ceiling,ceilingDigest:inbox.digest,recipient:value.recipient,rules:value.rules,scopes:inbox.scopes,now:100)
    let retained=try value.preservingLimits(compiled)
    for side in ["read","write"] {
      XCTAssertEqual((retained[side] as! [String:Any])["lifetime_seconds"] as? Int,120)
      XCTAssertTrue(NativeExistingGrantConfiguration.sameRows((retained[side] as! [String:Any])[side+"_grants"],(value.selection[side] as! [String:Any])[side+"_grants"]))
    }
    XCTAssertThrowsError(try value.preservingLimits(["read":compiled["read"]!]))
  }
  func testRefusesMissingSnapshotsBadDigestsAndUnrepresentableFilters() throws {
    let (_,inbox,grant)=try context()
    var missing=grant;missing.removeValue(forKey:"configuration")
    XCTAssertThrowsError(try NativeExistingGrantConfiguration(grant:missing,inbox:inbox,now:100))
    var corrupt=grant;corrupt["assignment_digest"]=String(repeating:"0",count:64)
    XCTAssertThrowsError(try NativeExistingGrantConfiguration(grant:corrupt,inbox:inbox,now:100))
    var config=grant["configuration"] as! [String:Any]
    var selection=config["selection"] as! [String:Any]
    var read=selection["read"] as! [String:Any]
    var rows=read["read_grants"] as! [[String:Any]]
    rows[0]["relationship_types"]=["parent"] // Narrower than the current operator ceiling.
    read["read_grants"]=rows;selection["read"]=read;config["selection"]=selection
    var restricted=grant;restricted["configuration"]=config;restricted["assignment_digest"]=try GrantJSON.digest(read)
    XCTAssertThrowsError(try NativeExistingGrantConfiguration(grant:restricted,inbox:inbox,now:100))
  }
  @MainActor func testOpenEditDiscardAndReopenDoNotSignSendOrCreateRequests() throws {
    let (resource,inbox,grant)=try context()
    let root=FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at:root) }
    let repo=try WalletRepository(directory:root.appendingPathComponent("wallet"))
    let bridge=TransferOperatorBridge(resource:resource,repository:repo,journalDirectory:root.appendingPathComponent("journal"),rpcExchange:{_,_ in
      XCTFail("Opening, editing and cancelling must not send an action");throw NativeGrantError.invalid
    })
    defer { bridge.cancel() }
    let model=NativeCredentialModel(bridge:bridge);model.inbox=inbox
    model.configure(grant)
    XCTAssertNotNil(model.existingConfiguration);XCTAssertNil(model.error)
    XCTAssertNil(model.requestedConfiguration);XCTAssertEqual(model.selected?.version,2)
    let original=model.choice
    model.choice.reads=["get"];model.editedPermissions()
    model.discardConfiguration()
    XCTAssertNil(model.selected);XCTAssertNil(model.existingConfiguration)
    model.configure(grant)
    var reopened=model.choice;reopened.expiry=original.expiry // Inactive dated-mode default is not grant authority.
    XCTAssertEqual(reopened,original)
    XCTAssertTrue(GrantJSON.equal(model.inbox?.activeGrants.first,grant))
    XCTAssertNil(try bridge.retainedNativeAction());XCTAssertNil(bridge.consent)
    var missing=grant;missing.removeValue(forKey:"configuration")
    model.configure(missing)
    XCTAssertNil(model.selected);XCTAssertNotNil(model.error)
  }
  @MainActor func testRenderExistingGrantEditorWhenRequested() async throws {
    guard let output=ProcessInfo.processInfo.environment["TRANSFER_EXISTING_GRANT_QA"] else { throw XCTSkip("Optional synthetic UI render") }
    let (resource,inbox,grant)=try context()
    let root=FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    let suite="ExistingGrantRender."+UUID().uuidString
    let defaults=UserDefaults(suiteName:suite)!
    defer { try? FileManager.default.removeItem(at:root);defaults.removePersistentDomain(forName:suite) }
    let wallet=TransferModel(directory:root.appendingPathComponent("app"),defaults:defaults)
    let repo=try XCTUnwrap(wallet.repository)
    _ = try await repo.create(password:"Synthetic rendering password")
    await wallet.refresh()
    let bridge=TransferOperatorBridge(resource:resource,repository:repo,journalDirectory:root.appendingPathComponent("journal"),rpcExchange:{_,_ in
      XCTFail("Rendering must not send an action");throw NativeGrantError.invalid
    })
    defer { bridge.cancel() }
    let editor=NativeCredentialModel(bridge:bridge);editor.inbox=inbox;editor.configure(grant)
    for reviewed in [false,true] {
      if reviewed {
        var proposal=try XCTUnwrap(editor.existingConfiguration).selection
        var read=proposal["read"] as! [String:Any]
        var rows=read["read_grants"] as! [[String:Any]];rows[0]["operations"]=["get"]
        read["read_grants"]=rows;proposal["read"]=read
        editor.review=["selection":proposal]
      }
      let view=NSHostingView(rootView:ResolvedTransferOperatorView(bridge:bridge,editor:editor,walletModel:wallet,serviceName:"Synthetic DevGraph") {}
        .frame(width:1100,height:1400).background(Color(nsColor:.windowBackgroundColor)).environment(\.colorScheme,.light))
      let window=NSWindow(contentRect:NSRect(x:0,y:0,width:1100,height:1400),styleMask:.borderless,backing:.buffered,defer:false)
      window.contentView=view;view.layoutSubtreeIfNeeded()
      try await Task.sleep(nanoseconds:150_000_000)
      let bitmap=try XCTUnwrap(view.bitmapImageRepForCachingDisplay(in:view.bounds));view.cacheDisplay(in:view.bounds,to:bitmap)
      try XCTUnwrap(bitmap.representation(using:.png,properties:[:])).write(to:URL(fileURLWithPath:output).appendingPathComponent(reviewed ? "review-changes.png" : "configure-existing.png"))
      window.contentView=nil
    }
    XCTAssertNil(try bridge.retainedNativeAction());XCTAssertNil(bridge.consent)
  }
}
#endif
