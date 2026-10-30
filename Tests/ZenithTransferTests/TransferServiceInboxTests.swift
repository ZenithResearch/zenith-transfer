#if os(macOS)
import Foundation
import CryptoKit
import XCTest
@testable import ZenithKit
@testable import CastaliaCustody
@testable import ZenithTransfer

final class TransferServiceInboxTests: XCTestCase {
  private let graph = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
  private func resource(_ host: String, key: String = "12") throws -> RegisteredResource {
    try RegisteredResource(configuration: WorkAccessConfiguration(name: "Fixture graph", receiver: URL(string: "https://" + host)!, issuer: "fixture", keyID: "key", publicKey: String(repeating: key, count: 32)))
  }
  private func server(_ resource: RegisteredResource, graph: String? = nil) throws -> LocalService {
    let graph = graph ?? self.graph
    return LocalService(instance_id: try LocalService.instanceID(resourceID: graph, interface: .walletAPI, endpoint: resource.id), resource_id: graph, interface: .walletAPI, name: "Fixture graph", endpoint: resource.id, connection: resource.configuration, updated_at: 1)
  }
  private func request(_ id: String = "a", version: Int = 1) -> [String: Any] {
    ["request_id": String(repeating: id, count: 32), "request_digest_sha256": String(repeating: "b", count: 64), "subject_public_key": String(repeating: "c", count: 64), "installation_id": String(repeating: "d", count: 32), "version": version]
  }
  private func inbox(_ resource: RegisteredResource, requests: [[String: Any]], total: Int? = nil, next: String? = nil) throws -> [String: Any] {
    let ceiling: [String: Any] = ["schema":"devgraph.access-draft.v5", "issuer":"fixture", "receiver":resource.id, "lifetime_seconds":300, "validity":["schema":"castalia.grant-validity.v1", "mode":"until_revoked", "not_before":1], "read_grants":[["scope":"devgraph.work.read", "operations":["list","get"], "relationship_types":[], "work_kinds":["Task"], "include_archived":false]], "write_grants":[]]
    var grant = request(); grant["assignment_digest"] = String(repeating: "e", count: 64); grant["access_mode"] = "read"
    return ["ceiling":ceiling, "ceiling_digest_sha256":try GrantJSON.digest(ceiling), "inbox":["items":requests,"total":total ?? requests.count,"next_cursor":next as Any? ?? NSNull()], "active_grants":[grant]]
  }
  func testOneGraphGroupsPrivateLocalAndTailnetServersWithoutMergingAnotherGraph() throws {
    let a = try server(resource("loopback.example")), b = try server(resource("tailnet.example"))
    let other = try server(resource("other.example"), graph: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
    let privateAPI = LocalService(instance_id: try LocalService.instanceID(resourceID: graph, interface: .privateAPI, endpoint: "http://127.0.0.1:8080"), resource_id: graph, interface: .privateAPI, name: "Fixture graph", endpoint: "http://127.0.0.1:8080", connection: nil, updated_at: 1)
    let groups = TransferLogicalService.groups([b, privateAPI, other, a])
    XCTAssertEqual(groups.count, 2)
    let actual = try XCTUnwrap(groups.first { $0.graphID == graph })
    XCTAssertEqual(actual.servers.count, 3); XCTAssertEqual(actual.walletServers.count, 2)
    XCTAssertTrue(actual.hasConsistentAuthority)
    XCTAssertTrue(actual.contains(try resource("tailnet.example")))
    XCTAssertFalse(actual.contains(try resource("tailnet.example", key: "34")))
    XCTAssertFalse(actual.contains(try resource("same-name.example")))
    XCTAssertEqual(actual.screenID, TransferLogicalService.groups([privateAPI, a, b])[0].screenID)
    let changed = TransferLogicalService.groups([a, try server(resource("tailnet.example", key: "34"))])[0]
    XCTAssertFalse(changed.hasConsistentAuthority)
    XCTAssertNotEqual(actual.screenID, changed.screenID)
  }
  func testUnifiedRowsKeepSameRequestIDsFromDifferentLegacyStoresDistinctAndPreserveGrants() throws {
    let a = try resource("a.example"), b = try resource("b.example")
    var first = ServiceInboxSnapshot(), second = ServiceInboxSnapshot()
    try first.accept(NativeOperatorInbox(inbox(a, requests:[request()]), resource:a), authority:a.id, append:false)
    try second.accept(NativeOperatorInbox(inbox(b, requests:[request()]), resource:b), authority:b.id, append:false)
    XCTAssertEqual(Set((first.requests + second.requests).map(\.id)).count, 2)
    XCTAssertEqual(Set((first.grants + second.grants).map(\.id)).count, 2)
    XCTAssertTrue(GrantJSON.equal(first.requests[0].raw, second.requests[0].raw))
    XCTAssertNotEqual(first.requests[0].authority, second.requests[0].authority)
  }
  func testPaginationAppendsWithoutLosingEarlierRequestsAndRefusesChangedSnapshots() throws {
    let a = try resource("a.example")
    var value = ServiceInboxSnapshot()
    try value.accept(NativeOperatorInbox(inbox(a, requests:[request()], total:2, next:String(repeating:"a",count:32)), resource:a), authority:a.id, append:false)
    XCTAssertNotNil(value.next)
    try value.accept(NativeOperatorInbox(inbox(a, requests:[request("f")], total:2), resource:a), authority:a.id, append:true)
    XCTAssertNil(value.next); XCTAssertEqual(value.requests.count,2); XCTAssertEqual(value.grants.count,1)
    XCTAssertThrowsError(try value.accept(NativeOperatorInbox(inbox(a, requests:[request(version:2)]), resource:a), authority:a.id, append:true))
    XCTAssertEqual(value.requests.count,2)
    var changed = try inbox(a, requests:[request("f")])
    var ceiling = changed["ceiling"] as! [String:Any]; ceiling["lifetime_seconds"] = 60
    changed["ceiling"] = ceiling; changed["ceiling_digest_sha256"] = try GrantJSON.digest(ceiling)
    XCTAssertThrowsError(try value.accept(NativeOperatorInbox(changed, resource:a), authority:a.id, append:true))
  }
  @MainActor func testAllInboxPartsUseLocalRPCAndWalletProofsWithoutIssuingAnyGrant() async throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at:root) }
    let wallet = try WalletRepository(directory:root.appendingPathComponent("wallet"))
    _ = try await wallet.create(password:"Synthetic test Wallet password")
    let backup = try await wallet.exportRecovery(password:"Synthetic backup password")
    _ = try await wallet.verifyBackup(file:backup,password:"Synthetic backup password")
    let resources = try [resource("a.example"), resource("b.example")]
    var received: [String] = []
    let endpoints = resources.map { resource in
      ServiceInboxEndpoint(resource: resource, repository: wallet, journalDirectory:root.appendingPathComponent("actions"), exchange: { operation, bytes in
        let input = try GrantJSON.object(bytes)
        if operation == "challenge" {
          let action = input["action"] as! [String:Any]
          XCTAssertEqual(action["action"] as? String,"inbox")
          let now = Int(Date().timeIntervalSince1970)
          let challenge: [String:Any] = ["schema":"castalia.access-request-challenge.v1", "challenge_id":UUID().uuidString.replacingOccurrences(of:"-",with:"").lowercased(), "nonce":String(repeating:"A",count:43), "issuer":"fixture", "receiver":resource.id, "subject_public_key":input["subject_public_key"]!, "installation_id":input["installation_id"]!, "operation":"access.inbox", "issued_at":now, "expires_at":now+120, "details":["action":action,"policy_revision":1,"policy_digest_sha256":String(repeating:"b",count:64)]]
          return PrivateHTTPResponse(status:200,data:try GrantJSON.data(challenge))
        }
        XCTAssertEqual(operation,"execute"); XCTAssertNotNil(input["signature"])
        let action = ((input["challenge"] as! [String:Any])["details"] as! [String:Any])["action"] as! [String:Any]
        XCTAssertEqual(action["action"] as? String,"inbox")
        received.append(resource.id)
        let paginated = resource.id == resources[0].id
        let cursor = String(repeating:"a",count:32)
        var output = try self.inbox(resource,requests:[self.request(action["after_id"] == nil ? "a" : "f")],
          total:paginated ? 2 : 1, next:paginated && action["after_id"] == nil ? cursor : nil)
        output["schema"] = "devgraph.access-operator-result.v2"; output["action_id"] = action["action_id"]; output["authority_issued"] = false
        // Browsing the aggregate must not automatically migrate old authority.
        output["owner_arena_upgrade"] = ["enabled":false,"policy_digest_sha256":String(repeating:"f",count:64)]
        return PrivateHTTPResponse(status:200,data:try GrantJSON.data(output))
      })
    }
    defer { endpoints.forEach { $0.bridge.cancel() } }
    let service = TransferLogicalService.groups(try resources.map { try server($0) })[0]
    let model = TransferServiceInboxModel(service:service); model.endpoints = endpoints
    let load = Task { await model.refresh() }
    for endpoint in endpoints {
      for _ in 0..<300 { if endpoint.bridge.consent != nil { break }; try await Task.sleep(nanoseconds:10_000_000) }
      XCTAssertEqual(endpoint.bridge.consent?.operation,"access.inbox")
      XCTAssertEqual(endpoint.bridge.transportLabel,"Local secS RPC · Wallet-authenticated")
      endpoint.bridge.resolve(true)
    }
    await load.value
    XCTAssertEqual(received,resources.map(\.id))
    XCTAssertEqual(model.requests.count,2); XCTAssertEqual(model.grants.count,2); XCTAssertFalse(model.complete)
    let more = Task { await model.more(endpoints[0]) }
    for _ in 0..<300 { if endpoints[0].bridge.consent != nil { break }; try await Task.sleep(nanoseconds:10_000_000) }
    XCTAssertEqual(endpoints[0].bridge.consent?.operation,"access.inbox")
    endpoints[0].bridge.resolve(true)
    await more.value
    XCTAssertEqual(model.requests.count,3); XCTAssertTrue(model.complete)
    XCTAssertEqual(endpoints[0].snapshot.requests.map { $0.raw["request_id"] as? String },
      [String(repeating:"a",count:32),String(repeating:"f",count:32)])
    XCTAssertEqual(received,resources.map(\.id)+[resources[0].id])
    for endpoint in endpoints { XCTAssertNil(try endpoint.bridge.retainedNativeAction()) }
    // A failed component must not make a partial inbox look complete.
    endpoints[1].loaded = false
    XCTAssertFalse(model.complete)
  }
  @MainActor func testRefreshDistinguishesUnsignedOriginalFromPossibleDispatchWithoutReplacingEither() async throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at:root) }
    let wallet = try WalletRepository(directory:root.appendingPathComponent("wallet"))
    let resource = try resource("fixture.example"), directory = root.appendingPathComponent("actions")
    let journal = try OperatorJournal(directory:directory, origin:resource.id)
    for dispatched in [false, true] {
      let record: [String:Any] = ["schema":"devgraph.operator-pending.v1", "origin":resource.id,
        "identity":["subject_public_key":String(repeating:"a",count:64), "installation_id":String(repeating:"b",count:32)],
        "action":["schema":"devgraph.access-operator-action.v1", "action":"inbox", "action_id":String(repeating:"c",count:32)],
        "assignment_digest":NSNull(), "dispatched":dispatched]
      let original = try GrantJSON.data(record)
      try journal.save(original)
      let endpoint = ServiceInboxEndpoint(resource:resource, repository:wallet, journalDirectory:directory, exchange:{ _,_ in
        XCTFail("Refreshing a retained action must not prepare, sign or send another action")
        throw NativeGrantError.invalid
      })
      defer { endpoint.bridge.cancel() }
      await endpoint.load()
      XCTAssertEqual(endpoint.error, (dispatched ? NativeGrantError.recovery : .notSent).errorDescription)
      XCTAssertEqual(endpoint.editor.state, dispatched ? .unknown : .prepared)
      XCTAssertEqual(try journal.load(), original)
      XCTAssertNil(endpoint.bridge.consent)
    }
  }
  @MainActor func testCompletedRetainedInboxUpdatesAggregateAndRetiresOnlyItsStaleError() async throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at:root) }
    let wallet = try WalletRepository(directory:root.appendingPathComponent("wallet"))
    _ = try await wallet.create(password:"Synthetic test Wallet password")
    let backup = try await wallet.exportRecovery(password:"Synthetic backup password")
    _ = try await wallet.verifyBackup(file:backup,password:"Synthetic backup password")
    let resource = try resource("fixture.example")
    var preparedIDs: [String] = [], executions = 0
    let endpoint = ServiceInboxEndpoint(resource:resource, repository:wallet,
      journalDirectory:root.appendingPathComponent("actions"), exchange:{ operation, bytes in
        let input = try GrantJSON.object(bytes)
        if operation == "challenge" {
          let action = input["action"] as! [String:Any]
          XCTAssertEqual(action["action"] as? String,"inbox")
          preparedIDs.append(action["action_id"] as! String)
          let now = Int(Date().timeIntervalSince1970)
          let challenge: [String:Any] = ["schema":"castalia.access-request-challenge.v1", "challenge_id":UUID().uuidString.replacingOccurrences(of:"-",with:"").lowercased(), "nonce":String(repeating:"A",count:43), "issuer":"fixture", "receiver":resource.id, "subject_public_key":input["subject_public_key"]!, "installation_id":input["installation_id"]!, "operation":"access.inbox", "issued_at":now, "expires_at":now+120, "details":["action":action,"policy_revision":1,"policy_digest_sha256":String(repeating:"b",count:64)]]
          return PrivateHTTPResponse(status:200,data:try GrantJSON.data(challenge))
        }
        XCTAssertEqual(operation,"execute"); XCTAssertNotNil(input["signature"])
        executions += 1
        let action = ((input["challenge"] as! [String:Any])["details"] as! [String:Any])["action"] as! [String:Any]
        var output = try self.inbox(resource,requests:[self.request("f")])
        output["schema"] = "devgraph.access-operator-result.v2"; output["action_id"] = action["action_id"]; output["authority_issued"] = false
        return PrivateHTTPResponse(status:200,data:try GrantJSON.data(output))
      })
    defer { endpoint.bridge.cancel() }
    let service = TransferLogicalService.groups([try server(resource)])[0]
    let aggregate = TransferServiceInboxModel(service:service)
    aggregate.endpoints = [endpoint]
    // Cancel the real synthetic consent, then retry the aggregate refresh.
    let first = Task { await endpoint.load() }
    for _ in 0..<300 { if endpoint.bridge.consent != nil { break }; try await Task.sleep(nanoseconds:10_000_000) }
    XCTAssertEqual(endpoint.bridge.consent?.operation,"access.inbox")
    endpoint.bridge.resolve(false)
    await first.value
    XCTAssertEqual(endpoint.editor.state,.prepared)
    await endpoint.load()
    XCTAssertEqual(endpoint.error, NativeGrantError.notSent.errorDescription)
    XCTAssertFalse(aggregate.complete)
    // Resume through the actual child editor, native client, journal and Combine.
    endpoint.editor.resume()
    for _ in 0..<300 { if endpoint.bridge.consent != nil { break }; try await Task.sleep(nanoseconds:10_000_000) }
    XCTAssertEqual(endpoint.bridge.consent?.operation,"access.inbox")
    endpoint.bridge.resolve(true)
    for _ in 0..<300 { if !endpoint.editor.busy { break }; try await Task.sleep(nanoseconds:10_000_000) }
    for _ in 0..<10 { await Task.yield() }
    XCTAssertEqual(endpoint.editor.state,.idle)
    XCTAssertNil(endpoint.editor.error)
    XCTAssertNil(endpoint.error)
    XCTAssertTrue(endpoint.loaded)
    XCTAssertEqual(aggregate.requests.map { $0.raw["request_id"] as? String }, [String(repeating:"f",count:32)])
    XCTAssertTrue(aggregate.complete)
    XCTAssertEqual(preparedIDs.count,2)
    XCTAssertEqual(Set(preparedIDs).count,1,"Resume must retain the original action ID")
    XCTAssertEqual(executions,1,"State reconciliation must not submit another action")
    XCTAssertNil(try endpoint.bridge.retainedNativeAction())
  }
  @MainActor private func retainedEndpoint(_ root: URL, resource: RegisteredResource,
    after: String? = nil, actionName: String = "inbox", dispatched: Bool = false
  ) throws -> (ServiceInboxEndpoint, OperatorJournal, Data) {
    let wallet = try WalletRepository(directory:root.appendingPathComponent("wallet"))
    let directory = root.appendingPathComponent("actions")
    let journal = try OperatorJournal(directory:directory, origin:resource.id)
    var action: [String:Any] = ["schema":"devgraph.access-operator-action.v1", "action":actionName,
      "action_id":String(repeating:"c",count:32)]
    if let after { action["after_id"] = after }
    let data = try GrantJSON.data(["schema":"devgraph.operator-pending.v1", "origin":resource.id,
      "identity":["subject_public_key":String(repeating:"a",count:64), "installation_id":String(repeating:"b",count:32)],
      "action":action, "assignment_digest":NSNull(), "dispatched":dispatched])
    try journal.save(data)
    let endpoint = ServiceInboxEndpoint(resource:resource, repository:wallet, journalDirectory:directory,
      exchange:{ _,_ in XCTFail("Reconciliation must not send or sign"); throw NativeGrantError.invalid })
    return (endpoint,journal,data)
  }
  @MainActor func testRetainedPageCompletionPreservesEarlierRowsAndDeduplicatesOverlap() async throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at:root) }
    let resource = try resource("fixture.example"), cursor = String(repeating:"a",count:32)
    let (endpoint,journal,record) = try retainedEndpoint(root,resource:resource,after:cursor)
    defer { endpoint.bridge.cancel() }
    try endpoint.snapshot.accept(NativeOperatorInbox(inbox(resource,requests:[request()],total:2,next:cursor),resource:resource),authority:resource.id,append:false)
    await endpoint.load()
    try journal.clear(matching:record) // Synthetic verified completion boundary.
    endpoint.editor.inbox = try NativeOperatorInbox(inbox(resource,requests:[request(),request("f")],total:2),resource:resource)
    endpoint.editor.state = .idle
    for _ in 0..<10 { await Task.yield() }
    XCTAssertNil(endpoint.error); XCTAssertTrue(endpoint.loaded)
    XCTAssertNil(endpoint.snapshot.next)
    XCTAssertEqual(endpoint.snapshot.requests.map { $0.raw["request_id"] as? String },
      [String(repeating:"a",count:32),String(repeating:"f",count:32)])
    XCTAssertEqual(endpoint.snapshot.total,2)
  }
  @MainActor func testRetainedTailWithoutItsEarlierPageCannotClaimCompleteCoverage() async throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at:root) }
    let resource = try resource("fixture.example")
    let (endpoint,journal,record) = try retainedEndpoint(root,resource:resource,after:String(repeating:"a",count:32))
    defer { endpoint.bridge.cancel() }
    await endpoint.load(); try journal.clear(matching:record)
    endpoint.editor.inbox = try NativeOperatorInbox(inbox(resource,requests:[request("f")],total:2),resource:resource)
    endpoint.editor.state = .idle
    for _ in 0..<10 { await Task.yield() }
    XCTAssertFalse(endpoint.loaded); XCTAssertTrue(endpoint.snapshot.requests.isEmpty)
    XCTAssertEqual(endpoint.error,"The original page was checked. Review the inbox again to load all pages.")
  }
  @MainActor func testRetainedPageWithChangedRowsKeepsPreviousSnapshotIncomplete() async throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at:root) }
    let resource = try resource("fixture.example"), cursor = String(repeating:"a",count:32)
    let (endpoint,journal,record) = try retainedEndpoint(root,resource:resource,after:cursor)
    defer { endpoint.bridge.cancel() }
    try endpoint.snapshot.accept(NativeOperatorInbox(inbox(resource,requests:[request()],total:2,next:cursor),resource:resource),authority:resource.id,append:false)
    await endpoint.load(); try journal.clear(matching:record)
    endpoint.editor.inbox = try NativeOperatorInbox(inbox(resource,requests:[request(version:2)],total:2),resource:resource)
    endpoint.editor.state = .idle
    for _ in 0..<10 { await Task.yield() }
    XCTAssertFalse(endpoint.loaded); XCTAssertNotNil(endpoint.error)
    XCTAssertEqual(endpoint.snapshot.requests.first?.raw["version"] as? Int,1)
    XCTAssertEqual(endpoint.snapshot.next,cursor)
  }
  @MainActor func testRetainedPageCannotAppendToADifferentPriorCursor() async throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at:root) }
    let resource = try resource("fixture.example")
    let (endpoint,journal,record) = try retainedEndpoint(root,resource:resource,after:String(repeating:"a",count:32))
    defer { endpoint.bridge.cancel() }
    let previous = String(repeating:"b",count:32)
    try endpoint.snapshot.accept(NativeOperatorInbox(inbox(resource,requests:[request()],total:2,next:previous),resource:resource),authority:resource.id,append:false)
    await endpoint.load(); try journal.clear(matching:record)
    endpoint.editor.inbox = try NativeOperatorInbox(inbox(resource,requests:[request("f")],total:2),resource:resource)
    endpoint.editor.state = .idle
    for _ in 0..<10 { await Task.yield() }
    XCTAssertFalse(endpoint.loaded)
    XCTAssertEqual(endpoint.snapshot.next,previous)
    XCTAssertEqual(endpoint.snapshot.requests.map { $0.raw["request_id"] as? String },[String(repeating:"a",count:32)])
    XCTAssertEqual(endpoint.error,"The original page was checked. Review the inbox again to load all pages.")
  }
  @MainActor func testPreparedMutationAndUnknownOutcomeAreNeverClearedByAnInboxPublication() async throws {
    for dispatched in [false,true] {
      let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
      defer { try? FileManager.default.removeItem(at:root) }
      let resource = try resource("fixture.example")
      let (endpoint,journal,record) = try retainedEndpoint(root,resource:resource,actionName:"approve",dispatched:dispatched)
      defer { endpoint.bridge.cancel() }
      await endpoint.load()
      let originalError = endpoint.error
      endpoint.editor.inbox = try NativeOperatorInbox(inbox(resource,requests:[]),resource:resource)
      for _ in 0..<10 { await Task.yield() }
      XCTAssertEqual(endpoint.editor.state,dispatched ? .unknown : .prepared)
      XCTAssertEqual(try journal.load(),record)
      XCTAssertEqual(endpoint.error,originalError); XCTAssertFalse(endpoint.loaded)
    }
  }
  @MainActor func testVerifiedInboxCompletionDoesNotEraseEditorOrBridgeFailures() async throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at:root) }
    let resource = try resource("fixture.example")
    let (endpoint,journal,record) = try retainedEndpoint(root,resource:resource)
    defer { endpoint.bridge.cancel() }
    await endpoint.load(); try journal.clear(matching:record)
    endpoint.editor.error = "Separate editor failure"
    endpoint.bridge.failure = "Separate bridge failure"
    endpoint.editor.inbox = try NativeOperatorInbox(inbox(resource,requests:[]),resource:resource)
    endpoint.editor.state = .idle
    for _ in 0..<10 { await Task.yield() }
    XCTAssertNil(endpoint.error); XCTAssertTrue(endpoint.loaded)
    XCTAssertEqual(endpoint.editor.error,"Separate editor failure")
    XCTAssertEqual(endpoint.bridge.failure,"Separate bridge failure")
  }
  func testCanonicalAliasesCollapseButLegacyStoresAndOriginalJournalsRemainVisible() throws {
    let key = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 1, count: 32))
    let publicKey = key.publicKey.rawRepresentation.map { String(format: "%02x", $0) }.joined()
    func base(_ origin: String) throws -> WorkAccessConfiguration {
      try WorkAccessConfiguration(name: "Graph", receiver: URL(string: origin)!, issuer: "fixture", keyID: "key", publicKey: publicKey)
    }
    func bound(_ origin: String) throws -> WorkAccessConfiguration {
      let value = try base(origin), now = UInt64(Date().timeIntervalSince1970)
      let claims = ServiceAccessPoint.Claims(schema: "secs.service-access-point.v1", issuer: "fixture", key_id: "key", service: "fixture:graph", origin: origin, authority_receiver: "https://authority.example", prefix: "/service/v1", not_before: now-1, not_after: now+1000)
      let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
      let signature = try key.signature(for: Data("secs.service-access-point.v1\0".utf8) + encoder.encode(claims)).map { String(format: "%02x", $0) }.joined()
      return try value.withServiceAccessPoint(ServiceAccessPoint(claims: claims, signature: signature))
    }
    let a = try bound("https://a.example"), b = try bound("https://b.example")
    let routes = try ServiceInboxRoutePlan.make([
      .init(configuration:a,retained:false), .init(configuration:b,retained:false),
      .init(configuration:try base("https://a.example"),retained:true),
      .init(configuration:try base("https://b.example"),retained:false),
      .init(configuration:try base("https://authority.example"),retained:true)])
    XCTAssertEqual(routes.count,3, "Two legacy stores and the single canonical store must remain visible")
    let canonical = try XCTUnwrap(routes.first { $0.configuration.authorityOrigin == "https://authority.example" })
    XCTAssertNil(canonical.configuration.serviceID, "An original journal must keep its exact legacy receiver for recovery")
    XCTAssertEqual(canonical.origins.count,3)
    let aliasesOnly = try ServiceInboxRoutePlan.make([.init(configuration:a,retained:false),.init(configuration:b,retained:false)])
    XCTAssertEqual(aliasesOnly.count,1); XCTAssertEqual(aliasesOnly[0].configuration.serviceID,"fixture:graph")
    XCTAssertThrowsError(try ServiceInboxRoutePlan.make([.init(configuration:try base("https://authority.example"),retained:false),.init(configuration:try resource("authority.example").configuration,retained:false)]))
  }
  @MainActor func testOptionalInstalledServiceConsolidationUsesMetadataOnly() async throws {
    guard ProcessInfo.processInfo.environment["TRANSFER_INSTALLED_SERVICE_CHECK"] == "1" else {
      throw XCTSkip("Explicit read-only installed service qualification")
    }
    let groups = TransferLogicalService.groups(LocalServiceDiscovery.scan().services)
      .filter { $0.walletServers.count >= 2 && $0.servers.contains { $0.interface == .privateAPI } }
    let service = try XCTUnwrap(groups.count == 1 ? groups.first : nil)
    XCTAssertTrue(service.hasConsistentAuthority)
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    // No imported identity, key generation, signing or inbox request occurs.
    let emptyWallet = try WalletRepository(directory: root.appendingPathComponent("wallet"))
    let model = TransferServiceInboxModel(service: service)
    defer { model.close() }
    await model.prepare(repository: emptyWallet)
    XCTAssertTrue(model.failures.isEmpty)
    XCTAssertFalse(model.endpoints.isEmpty)
    XCTAssertEqual(Set(model.endpoints.flatMap(\.origins)), Set(service.walletServers.map(\.endpoint)))
    XCTAssertTrue(model.endpoints.allSatisfy { $0.bridge.transportLabel == "Local secS RPC · Wallet-authenticated" && $0.bridge.failure == nil && $0.bridge.consent == nil })
    XCTAssertTrue(model.requests.isEmpty); XCTAssertTrue(model.grants.isEmpty)
  }
  @MainActor func testLocalOnlyManagementRefusesAnUnregisteredRemoteServer() async throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at:root) }
    let wallet = try WalletRepository(directory:root.appendingPathComponent("wallet"))
    let bridge = TransferOperatorBridge(resource:try resource("unregistered.invalid"),repository:wallet,journalDirectory:root.appendingPathComponent("actions"),requireLocal:true)
    defer { bridge.cancel() }
    XCTAssertNotNil(bridge.failure)
    XCTAssertNil(try bridge.retainedNativeAction())
    XCTAssertNil(bridge.consent)
  }
}
#endif
