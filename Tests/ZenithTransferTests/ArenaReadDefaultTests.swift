#if os(macOS)
import Foundation
import XCTest
@testable import ZenithKit
@testable import CastaliaCustody
@testable import ZenithTransfer

final class ArenaReadDefaultTests: XCTestCase {
  @MainActor private func withModel(arenas: Bool = true, readAllowed: Bool = true,
    _ body: (NativeCredentialModel, NativeOperatorInbox, [String: Any], URL) throws -> Void) throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    let configuration = try WorkAccessConfiguration(name: "Fixture", receiver: URL(string: "https://fixture.example")!,
      issuer: "fixture", keyID: "fixture", publicKey: String(repeating: "12", count: 32))
    let resource = try RegisteredResource(configuration: configuration)
    let fixtureURL = try XCTUnwrap(Bundle.module.url(forResource: "native-grants", withExtension: "json", subdirectory: "Fixtures"))
    let fixture = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: fixtureURL)) as? [[String: Any]]).first!
    var ceiling = fixture["ceiling"] as! [String: Any]
    if arenas {
      ceiling["schema"] = "devgraph.access-draft.v6"
      ceiling.removeValue(forKey: "not_before"); ceiling.removeValue(forKey: "not_after")
      ceiling["validity"] = ["schema": "castalia.grant-validity.v1", "mode": "until_revoked", "not_before": 1]
      var reads = ceiling["read_grants"] as! [[String: Any]]
      reads.append(["scope": "devgraph.arena.read", "arena_ids": ["design", "research"]])
      ceiling["read_grants"] = reads
    }
    let paths = try [WorkResourcePath(path: ["Arena/design", "Project/dashboard"]),
      WorkResourcePath(path: ["Arena/research", "Project/lab"])]
    var catalog: [String: Any] = ["schema": "devgraph.access-catalog.v1", "issuer": configuration.issuer,
      "receiver": configuration.authorityOrigin, "revision": 1,
      "presets": [["id": "reader", "name": "Reader", "version": 1,
        "read_operations": ["get", "list"], "write_operations": [String]()]],
      "published_paths": [Any](), "policy_digest_sha256": String(repeating: "a", count: 64)]
    catalog["catalog_digest_sha256"] = try GrantJSON.digest(catalog)
    let scopes = paths.map { path -> [String: Any] in
      ["resource_path": ["schema": path.schema, "path": path.path], "resource": path.path.last!,
        "title": "Fixture", "parent": path.path.first!]
    }
    let raw: [String: Any] = ["ceiling": ceiling, "ceiling_digest_sha256": try GrantJSON.digest(ceiling),
      "catalog": catalog, "scopes": scopes, "inbox": ["items": [fixture["recipient"]!], "total": 1],
      "activation": ["read": readAllowed, "write": true, "mixed": true]]
    let inbox = try NativeOperatorInbox(raw, resource: resource)
    let repository = try WalletRepository(directory: root.appendingPathComponent("wallet"))
    let bridge = TransferOperatorBridge(resource: resource, repository: repository,
      journalDirectory: root.appendingPathComponent("journal"), rpcExchange: { _, _ in
        XCTFail("Editing defaults must not send a request"); throw NativeGrantError.invalid
      })
    defer { bridge.cancel() }
    let model = NativeCredentialModel(bridge: bridge); model.inbox = inbox
    try body(model, inbox, fixture["recipient"] as! [String: Any], root)
    XCTAssertNil(try bridge.retainedNativeAction()); XCTAssertNil(bridge.consent)
  }

  @MainActor func testNewReviewDefaultsArenaReadsToChosenScopeOnly() throws {
    try withModel { model, inbox, raw, _ in
      model.select(try NativeGrantRecipient(raw))
      XCTAssertTrue(model.arenaReadEnabled)
      XCTAssertTrue(model.choice.arenaIDs.isEmpty)
      XCTAssertFalse(model.choice.wholeGraph); XCTAssertFalse(model.choice.allArenas)
      XCTAssertTrue(model.choice.writes.isEmpty)
      model.changeScope("paths"); model.choose(inbox.scopes[0], selected: true)
      XCTAssertEqual(model.choice.arenaIDs, ["design"])
      let selection = try NativeGrantSelection.makeRules(ceiling: inbox.ceiling, ceilingDigest: inbox.digest,
        recipient: NativeGrantRecipient(raw), rules: model.permissionRules, scopes: inbox.scopes, now: 100)
      let read = try XCTUnwrap(selection["read"] as? [String: Any])
      let grants = try GrantJSON.rows(read["read_grants"])
      XCTAssertEqual(grants.count, 1)
      XCTAssertEqual(grants[0]["arena_ids"] as? [String], ["design"])
      XCTAssertNil(selection["write"] as? [String: Any])
    }
  }

  @MainActor func testOptOutSurvivesScopeChangesAndRuleSwitching() throws {
    try withModel { model, inbox, raw, _ in
      model.select(try NativeGrantRecipient(raw)); model.changeScope("paths")
      model.choose(inbox.scopes[0], selected: true); model.setArenaRead(false)
      model.choose(inbox.scopes[1], selected: true)
      XCTAssertFalse(model.arenaReadEnabled); XCTAssertTrue(model.choice.arenaIDs.isEmpty)
      model.addRule()
      XCTAssertTrue(model.arenaReadEnabled, "A new independent rule gets the new-draft default")
      model.changeScope("paths"); model.choose(inbox.scopes[1], selected: true)
      XCTAssertEqual(model.choice.arenaIDs, ["research"])
      model.selectRule(0)
      XCTAssertFalse(model.arenaReadEnabled); XCTAssertTrue(model.choice.arenaIDs.isEmpty)
      model.selectRule(1); XCTAssertEqual(model.choice.arenaIDs, ["research"])
    }
  }

  @MainActor func testIssuerWithoutArenaPermissionKeepsDefaultOff() throws {
    try withModel(arenas: false) { model, inbox, raw, _ in
      model.select(try NativeGrantRecipient(raw)); model.changeScope("paths")
      model.choose(inbox.scopes[0], selected: true)
      XCTAssertFalse(model.arenaReadEnabled); XCTAssertTrue(model.choice.arenaIDs.isEmpty)
      model.addRule(); XCTAssertFalse(model.arenaReadEnabled)
    }
  }

  @MainActor func testDisabledReadActivationKeepsArenaDefaultOff() throws {
    try withModel(readAllowed: false) { model, _, raw, _ in
      model.select(try NativeGrantRecipient(raw))
      XCTAssertFalse(model.arenaReadEnabled); XCTAssertTrue(model.choice.arenaIDs.isEmpty)
      model.addRule(); XCTAssertFalse(model.arenaReadEnabled)
    }
  }

  @MainActor func testRequestedPresetStaysExactAndPathOnlyRequestsTrackArenaCoverage() throws {
    try withModel { model, inbox, raw, _ in
      func requested(preset: Bool) throws -> NativeGrantRecipient {
        var request = raw
        request["intent"] = ["schema": "devgraph.access-intent.v2", "preference": [
          "catalog_digest_sha256": inbox.catalog!.catalog_digest_sha256,
          "id": preset ? "reader" as Any : NSNull(), "version": preset ? 1 as Any : NSNull(),
          "resource_paths": try JSONSerialization.jsonObject(with: JSONEncoder().encode(inbox.scopes.map(\.resource_path)))]]
        return try NativeGrantRecipient(request)
      }
      model.select(try requested(preset: true))
      XCTAssertFalse(model.arenaReadEnabled); XCTAssertTrue(model.choice.arenaIDs.isEmpty)
      model.addRule(); XCTAssertFalse(model.arenaReadEnabled)
      try model.requestedConfiguration?.validate(model.permissionRules)
      model.select(try requested(preset: false))
      XCTAssertTrue(model.arenaReadEnabled); XCTAssertEqual(model.choice.arenaIDs, ["design", "research"])
      model.allocateRequestedPath(inbox.scopes[1].resource_path, enabled: false)
      XCTAssertEqual(model.choice.arenaIDs, ["design"])
      model.addRule()
      XCTAssertTrue(model.arenaReadEnabled); XCTAssertEqual(model.choice.arenaIDs, ["design", "research"])
    }
  }

  @MainActor func testNewPresetDefaultsOnButStoredRecipesKeepTheirContents() throws {
    XCTAssertTrue(TransferPresetEditor.initialArenaRead(source: nil))
    for preset in CredentialPresetRevision.builtins {
      XCTAssertEqual(TransferPresetEditor.initialArenaRead(source: preset), preset.arenaRead == true)
    }
    let saved = try CredentialPresetRevision(presetID: "custom-arena", revision: 1, name: "Arena reader",
      description: "Fixture", readOperations: [], writeOperations: [], arenaRead: true)
    XCTAssertTrue(TransferPresetEditor.initialArenaRead(source: saved))
  }
}
#endif
