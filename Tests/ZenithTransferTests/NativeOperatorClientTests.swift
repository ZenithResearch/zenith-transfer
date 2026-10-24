#if os(macOS)
import Foundation
import XCTest
import ZenithKit
@testable import ZenithTransfer

private final class NativeOperatorResponse: URLProtocol {
  static var handler: (([String: Any], String) throws -> [String: Any])?
  static var observer: ((URLRequest) -> Void)?
  override class func canInit(with request: URLRequest) -> Bool { true }
  override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
  override func startLoading() {
    do {
      Self.observer?(request)
      var body = request.httpBody
      if body == nil, let stream = request.httpBodyStream {
        stream.open(); defer { stream.close() }; var data = Data(); var bytes = [UInt8](repeating: 0, count: 4096)
        while stream.hasBytesAvailable { let n = stream.read(&bytes, maxLength: bytes.count); if n <= 0 { break }; data.append(contentsOf: bytes.prefix(n)) }; body = data
      }
      let result = try Self.handler!(GrantJSON.object(body ?? Data()), request.url!.path)
      let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: nil)!
      client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
      client?.urlProtocol(self, didLoad: try GrantJSON.data(result)); client?.urlProtocolDidFinishLoading(self)
    } catch { client?.urlProtocol(self, didFailWithError: error) }
  }
  override func stopLoading() {}
}

final class NativeOperatorClientTests: XCTestCase {
  @MainActor private func fixture(_ root: URL) async throws -> (WalletRepository, RegisteredResource, PrivateTransport) {
    let repo = try WalletRepository(directory: root.appendingPathComponent("wallet"))
    _ = try await repo.create(password: "Disposable native fixture password")
    let backup = try await repo.exportRecovery(password: "Disposable fixture backup password")
    _ = try await repo.verifyBackup(file: backup, password: "Disposable fixture backup password")
    let config = try WorkAccessConfiguration(name: "Fixture", receiver: URL(string: "https://fixture.example")!, issuer: "fixture", keyID: "key", publicKey: String(repeating: "12", count: 32))
    let session = URLSessionConfiguration.ephemeral; session.protocolClasses = [NativeOperatorResponse.self]
    return (repo, try RegisteredResource(configuration: config), PrivateTransport(configuration: session))
  }
  private func challenge(_ input: [String: Any], tamper: Bool = false) -> [String: Any] {
    let action = input["action"] as! [String: Any], name = action["action"] as! String, now = Int(Date().timeIntervalSince1970)
    return ["schema": "castalia.access-request-challenge.v1", "challenge_id": UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased(), "nonce": String(repeating: "A", count: 43), "issuer": "fixture", "receiver": "https://fixture.example", "subject_public_key": input["subject_public_key"]!, "installation_id": input["installation_id"]!, "operation": tamper ? "access.status" : (["inbox":"access.inbox", "review":"access.review", "approve":"access.decide", "status":"access.status"][name] ?? "access.decide"), "issued_at": now, "expires_at": now + 120, "details": ["action": action, "policy_revision": 1, "policy_digest_sha256": String(repeating: "b", count: 64)]]
  }
  @MainActor private func consent(_ client: NativeOperatorClient, operation: String) async throws -> [String: Any] {
    let task = Task { try await client.confirm() }
    for _ in 0..<100 { if client.bridge.consent != nil { break }; try await Task.sleep(nanoseconds: 10_000_000) }
    XCTAssertEqual(client.bridge.consent?.operation, operation)
    guard client.bridge.consent != nil else { task.cancel(); throw NativeGrantError.invalid }
    client.bridge.resolve(true); return try await task.value
  }
  @MainActor func testNativeInboxReviewActivationAndOriginalRecoveryUseSameJournalAndWallet() async throws {
    try await exerciseInboxRecovery(localRPC: false)
  }
  @MainActor func testLocalRPCUsesSameWalletReviewActivationAndOriginalRecoveryWithoutHTTP() async throws {
    var httpCalls = 0
    NativeOperatorResponse.observer = { _ in httpCalls += 1 }
    defer { NativeOperatorResponse.observer = nil }
    try await exerciseInboxRecovery(localRPC: true)
    XCTAssertEqual(httpCalls, 0)
  }
  @MainActor func testRejectedPreparationReportsSafeCodeWithoutSavingOrSigningAnAction() async throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    let (repo, resource, _) = try await fixture(root)
    let bridge = TransferOperatorBridge(resource: resource, repository: repo,
      journalDirectory: root.appendingPathComponent("actions"), rpcExchange: { operation, _ in
        XCTAssertEqual(operation, "challenge")
        return PrivateHTTPResponse(status: 400, data: try GrantJSON.data(["error": "invalid_operator_selection"]))
      })
    defer { bridge.cancel() }
    let client = try NativeOperatorClient(bridge: bridge)
    do { try await client.prepare(["action": "inbox"]); XCTFail("Rejected preparation must fail") }
    catch let error as NativeOperatorServerError {
      XCTAssertTrue(error.errorDescription?.contains("invalid_operator_selection") == true)
    }
    XCTAssertEqual(client.state, .idle)
    XCTAssertNil(try bridge.retainedNativeAction()); XCTAssertNil(bridge.consent)
    let untrusted = NativeOperatorServerError(status: 400, code: "private arbitrary server text")
    XCTAssertFalse(untrusted.errorDescription!.contains("private arbitrary server text"))
  }
  @MainActor private func exerciseInboxRecovery(localRPC: Bool) async throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root); NativeOperatorResponse.handler = nil }
    let (repo, resource, transport) = try await fixture(root), journals = root.appendingPathComponent("actions")
    let rpc: ((String, Data) async throws -> PrivateHTTPResponse)? = localRPC ? { operation, raw in
      let path = operation == "challenge" ? "/devgraph/access-operator/v1/challenges" : "/devgraph/access-operator/v1/actions"
      let value = try NativeOperatorResponse.handler!(GrantJSON.object(raw), path)
      return PrivateHTTPResponse(status: 200, data: try GrantJSON.data(value))
    } : nil
    var bridge = TransferOperatorBridge(resource: resource, repository: repo, transport: localRPC ? nil : transport, journalDirectory: journals, rpcExchange: rpc)
    XCTAssertEqual(bridge.transportLabel, localRPC ? "Local secS RPC · Wallet-authenticated" : "HTTPS · Wallet-authenticated")
    defer { bridge.cancel() }
    var client = try NativeOperatorClient(bridge: bridge)
    let ceiling: [String: Any] = ["schema":"devgraph.access-draft.v5", "issuer":"fixture", "receiver":resource.id, "lifetime_seconds":300, "validity":["schema":"castalia.grant-validity.v1", "mode":"until_revoked", "not_before":1], "read_grants":[["scope":"devgraph.work.read", "operations":["list","get"], "relationship_types":[], "work_kinds":["Task"], "include_archived":false]], "write_grants":[]]
    let recipient: [String: Any] = ["request_id":String(repeating:"a",count:32),"request_digest_sha256":String(repeating:"b",count:64),"subject_public_key":String(repeating:"c",count:64),"installation_id":String(repeating:"d",count:32),"version":1]
    var decisions = 0, actions = 0, originalResult: [String: Any]?
    NativeOperatorResponse.handler = { input, path in
      if path.hasSuffix("/challenges") { return self.challenge(input) }
      actions += 1; XCTAssertNotNil(input["signature"])
      let action = ((input["challenge"] as! [String: Any])["details"] as! [String: Any])["action"] as! [String: Any]
      let envelope: [String: Any] = ["schema":"devgraph.access-operator-result.v2", "action_id":action["action_id"]!, "authority_issued":false]
      var result = envelope
      switch action["action"] as! String {
      case "inbox":
        result["ceiling"] = ceiling; result["ceiling_digest_sha256"] = try GrantJSON.digest(ceiling)
        result["inbox"] = ["items":[recipient],"total":1,"next_cursor":NSNull()]
        result["activation"] = ["read":true,"read_action_schema":"devgraph.access-operator-action.v6"]
      case "review":
        let selection = action["selection"]!
        result.merge(["request_id":action["request_id"]!, "request_digest_sha256":action["request_digest_sha256"]!, "expected_version":1, "review_id":action["action_id"]!, "selection":selection, "selection_digest_sha256":try GrantJSON.digest(selection), "plans":["activation":["assignment_digest":try NativeOperatorClient.assignmentDigest(action), "previous_assignment_digest":NSNull()]]]) { _, b in b }
      case "approve":
        decisions += 1
        result.merge(["request_id":action["request_id"]!, "request_digest_sha256":action["request_digest_sha256"]!, "version":2, "status":"active", "activation":["active":true,"credential_issued":false,"assignment_digest":try NativeOperatorClient.assignmentDigest(action)]]) { _, b in b }
        originalResult = result
        return ["schema":"devgraph.access-operator-result.v2","authority_issued":false] // Response lost/corrupted after commit.
      case "status":
        result["original_action_id"] = action["original_action_id"]!; result["status"] = "reconciled"; result["result"] = originalResult!
      default: throw NativeGrantError.invalid
      }
      return result
    }
    try await client.prepare(["action":"inbox"])
    XCTAssertEqual(actions,0, "Preparation cannot dispatch an operator action")
    let inbox = try NativeOperatorInbox(await consent(client, operation: "access.inbox"), resource: resource)
    var choice = NativeGrantChoice(); choice.wholeGraph = true; choice.reads = ["get"]; choice.kinds = ["Task"]
    let selection = try NativeGrantSelection.make(ceiling: inbox.ceiling, ceilingDigest: inbox.digest, recipient: inbox.requests[0], choice: choice, scopes: [], now: client.now)
    var fields: [String: Any] = ["schema":"devgraph.access-operator-action.v6","action":"review","request_id":recipient["request_id"]!,"request_digest_sha256":recipient["request_digest_sha256"]!,"expected_version":1,"previous_assignment_digest":NSNull(),"selection":selection]
    try await client.prepare(fields)
    let review = try await consent(client, operation: "access.review")
    XCTAssertTrue(GrantJSON.equal(review["selection"], selection)); XCTAssertEqual(decisions,0)
    fields["action"] = "approve"; fields["review_id"] = review["review_id"]!
    try await client.prepare(fields)
    do { _ = try await consent(client, operation: "access.decide"); XCTFail("Incomplete receipt must stay unknown") } catch {}
    XCTAssertEqual(client.state,.unknown); XCTAssertEqual(decisions,1)
    let journal = try OperatorJournal(directory: journals, origin: resource.id), retained = try XCTUnwrap(journal.load())
    XCTAssertFalse(String(decoding:retained,as:UTF8.self).contains("signature"))
    XCTAssertEqual(try GrantJSON.object(retained)["dispatched"] as? Bool,true)
    do { try await client.prepare(["action":"inbox"]); XCTFail("Must recover before new action") } catch {}
    _ = await repo.lock(); bridge.walletStateDidChange(false)
    XCTAssertEqual(try journal.load(),retained)
    bridge.cancel()
    _ = try await repo.unlock(password:"Disposable native fixture password")
    bridge = TransferOperatorBridge(resource:resource,repository:repo,transport:localRPC ? nil : transport,journalDirectory:journals,rpcExchange:rpc)
    client = try NativeOperatorClient(bridge:bridge)
    XCTAssertEqual(client.state,.unknown)
    try await client.prepareRecovery()
    let recovered = try await consent(client,operation:"access.status")
    XCTAssertEqual(recovered["status"] as? String,"active")
    XCTAssertEqual(decisions,1,"Status recovery never replays activation")
    XCTAssertEqual(actions,4); XCTAssertEqual(client.state,.idle); XCTAssertNil(try journal.load())
  }
  @MainActor func testNetworkPreparationUsesEachSelectedOriginAndIssuer() async throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root); NativeOperatorResponse.handler = nil; NativeOperatorResponse.observer = nil }
    let (repo, first, transport) = try await fixture(root)
    let second = try RegisteredResource(configuration: WorkAccessConfiguration(name: "Other graph",
      receiver: URL(string: "https://other-graph.example")!, issuer: "other-issuer", keyID: "other-key",
      publicKey: String(repeating: "34", count: 32)))
    for selected in [first, second] {
      let bridge = TransferOperatorBridge(resource: selected, repository: repo, transport: transport,
        journalDirectory: root.appendingPathComponent("actions"))
      defer { bridge.cancel() }
      let client = try NativeOperatorClient(bridge: bridge)
      var seen: [URL] = []
      NativeOperatorResponse.observer = { request in
        if let url = request.url { seen.append(url) }
      }
      NativeOperatorResponse.handler = { input, _ in
        var challenge = self.challenge(input)
        challenge["receiver"] = selected.configuration.origin
        challenge["issuer"] = selected.configuration.issuer
        return challenge
      }
      try await client.prepare(["action": "inbox"])
      XCTAssertFalse(seen.isEmpty)
      XCTAssertTrue(seen.allSatisfy { $0.scheme == selected.configuration.receiver.scheme && $0.host == selected.configuration.receiver.host && $0.port == selected.configuration.receiver.port })
      XCTAssertEqual(client.challenge?["receiver"] as? String, selected.id)
      XCTAssertEqual(client.challenge?["issuer"] as? String, selected.configuration.issuer)
      XCTAssertEqual(bridge.resource.configuration.authority, selected.configuration.authority)
      try await client.cancelPrepared()
    }
  }
  @MainActor func testConcurrentPreparationAndTamperedChallengeCannotReplaceOriginal() async throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer {try? FileManager.default.removeItem(at:root);NativeOperatorResponse.handler=nil}
    let (repo,resource,transport) = try await fixture(root)
    let bridge = TransferOperatorBridge(resource:resource,repository:repo,transport:transport,journalDirectory:root.appendingPathComponent("actions"))
    defer {bridge.cancel()}
    let client = try NativeOperatorClient(bridge:bridge)
    NativeOperatorResponse.handler = { input,_ in self.challenge(input) }
    let first = Task { try await client.prepare(["action":"inbox"]) }
    await Task.yield()
    do { try await client.prepare(["action":"inbox"]); XCTFail("Concurrent prepare must be refused") } catch {}
    try await first.value
    let original = try bridge.retainedNativeAction()
    do { try await client.prepare(["action":"inbox"]); XCTFail("Prepared selection cannot be replaced") } catch {}
    XCTAssertEqual(try bridge.retainedNativeAction(),original)
    try await client.cancelPrepared(); XCTAssertNil(try bridge.retainedNativeAction())
    NativeOperatorResponse.handler = { input,_ in self.challenge(input,tamper:true) }
    do {try await client.prepare(["action":"inbox"]);XCTFail("Mislabeled operation must fail") } catch {}
    XCTAssertEqual(client.state,.idle);XCTAssertNil(bridge.consent);XCTAssertNil(try bridge.retainedNativeAction())
  }
}
#endif
