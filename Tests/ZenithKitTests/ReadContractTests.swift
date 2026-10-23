import CryptoKit
import XCTest

@testable import ZenithKit

private func json(_ value: Any) throws -> Data {
  try JSONSerialization.data(
    withJSONObject: value, options: [.sortedKeys, .withoutEscapingSlashes])
}
private func object(_ data: Data) throws -> [String: Any] {
  try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
}
private func hex(_ data: some Sequence<UInt8>) -> String {
  data.map { String(format: "%02x", $0) }.joined()
}
private func fixture() throws -> [String: Any] {
  try object(
    Data(
      contentsOf: XCTUnwrap(
        Bundle.module.url(forResource: "devgraph-monitor-read", withExtension: "json"))))
}

private final class ReadProtocolStub: URLProtocol {
  static let lock = NSLock()
  static var backend: ReadBackend?
  static func use(_ value: ReadBackend?) {
    lock.lock()
    defer { lock.unlock() }
    backend = value
  }
  override class func canInit(with request: URLRequest) -> Bool { true }
  override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
  override func startLoading() {
    Self.lock.lock()
    defer { Self.lock.unlock() }
    do {
      let value = try XCTUnwrap(Self.backend).respond(request)
      let response = try XCTUnwrap(
        HTTPURLResponse(
          url: XCTUnwrap(request.url), statusCode: Self.backend?.statusCode ?? 200,
          httpVersion: nil, headerFields: nil))
      client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
      client?.urlProtocol(self, didLoad: value)
      client?.urlProtocolDidFinishLoading(self)
    } catch { client?.urlProtocol(self, didFailWithError: error) }
  }
  override func stopLoading() {}
}

/// Disposable in-memory issuer. Real Swift -> Rust approval, issuer signature
/// validation, encrypted commit, reload and holder signatures cross the ABI.
/// HTTP is stubbed; this does not qualify secS or a physical phone.
private final class ReadBackend {
  let issuer = Curve25519.Signing.PrivateKey()
  let version: WorkReadProtocol
  let vectors: [String: Any]
  var challenge: [String: Any] = [:]
  var policy: [String: Any] = [:]
  var credential: [String: Any] = [:]
  var calls: [[String: Any]] = []
  var accessActions: [String] = []
  var submitCount = 0
  var failSubmittedResponse = false
  var rejectAccessPreparation = false
  var accessRequestID: String?
  var wrongResultVersion = false
  var statusCode = 200
  init(_ version: WorkReadProtocol) throws {
    self.version = version
    vectors = try fixture()
  }
  var config: WorkAccessConfiguration {
    get throws {
      try WorkAccessConfiguration(
        name: "Test work", receiver: URL(string: "https://example.test")!,
        issuer: "fixture", keyID: "test-key", publicKey: hex(issuer.publicKey.rawRepresentation))
    }
  }
  func respond(_ request: URLRequest) throws -> Data {
    var body = request.httpBody ?? Data()
    if let stream = request.httpBodyStream {
      stream.open()
      defer { stream.close() }
      var buffer = [UInt8](repeating: 0, count: 4096)
      while stream.hasBytesAvailable {
        let count = stream.read(&buffer, maxLength: buffer.count)
        guard count >= 0 else { throw WalletFailure.core("invalid_response") }
        if count == 0 { break }
        body.append(contentsOf: buffer.prefix(count))
      }
    }
    let input = try object(body)
    switch request.url!.path {
    case "/devgraph/access-requests/v2/challenges":
      statusCode=200
      if rejectAccessPreparation { statusCode=400;return try json(["error":"invalid_access_request"]) }
      let action=try XCTUnwrap(input["request"] as? [String:Any])
      accessActions.append(try XCTUnwrap(action["action"] as? String))
      let now=UInt64(Date().timeIntervalSince1970)
      challenge=["schema":"castalia.access-request-challenge.v1","challenge_id":String(repeating:"aa",count:16),
        "nonce":String(repeating:"A",count:43),"issuer":"fixture","receiver":"https://example.test",
        "subject_public_key":action["subject_public_key"]!,"installation_id":action["installation_id"]!,
        "operation":action["action"] as? String == "submit" ? "access.request":"access.status",
        "issued_at":now,"expires_at":now+120,"details":action]
      return try json(challenge)
    case "/devgraph/access-requests/v2/actions":
      let approved=try XCTUnwrap(input["challenge"] as? [String:Any])
      XCTAssertEqual(try json(approved),try json(challenge))
      XCTAssertNotNil(input["proof"])
      let publicKey=try Curve25519.Signing.PublicKey(rawRepresentation:data(hex:XCTUnwrap(approved["subject_public_key"] as? String)))
      let encoded=try XCTUnwrap(input["signature"] as? String)
      let signature=try XCTUnwrap(Data(base64Encoded:encoded.replacingOccurrences(of:"-",with:"+").replacingOccurrences(of:"_",with:"/")+"=="))
      XCTAssertTrue(publicKey.isValidSignature(signature,for:Data("castalia/access-request-approval/v1\0".utf8)+(try json(approved))))
      let action=try XCTUnwrap(approved["details"] as? [String:Any])
      let identifier=try XCTUnwrap(action["request_id"] as? String)
      if action["action"] as? String == "submit" { submitCount += 1; accessRequestID=identifier }
      if failSubmittedResponse { failSubmittedResponse=false; statusCode=503 }
      return try json(["schema":"devgraph.access-request-result.v1","request_id":identifier,"status":accessRequestID == identifier ? "pending":"unknown","authority_issued":false])
    case "/devgraph/native-read/v2/challenges":
      challenge = try makeChallenge(identity: input)
      return try json(challenge)
    case "/devgraph/native-read/v2/enrollments":
      let approved = try XCTUnwrap(input["challenge"] as? [String: Any])
      XCTAssertEqual(try json(approved), try json(challenge))
      let owner = try XCTUnwrap(approved["subject_public_key"] as? String)
      let publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: data(hex: owner))
      var base64 = try XCTUnwrap(input["signature"] as? String).replacingOccurrences(
        of: "-", with: "+"
      ).replacingOccurrences(of: "_", with: "/")
      base64 += String(repeating: "=", count: (4 - base64.count % 4) % 4)
      let signature = try XCTUnwrap(Data(base64Encoded: base64))
      XCTAssertTrue(
        publicKey.isValidSignature(
          signature, for: Data("castalia/read-access-approval/v1\0".utf8) + (try json(approved))))
      let now = UInt64(Date().timeIntervalSince1970)
      let claims: [String: Any] = [
        "schema": "castalia.read-credential.v1",
        "credential_id": String(repeating: "33", count: 16),
        "holder_public_key": owner, "installation_id": approved["installation_id"]!,
        "issuer": "fixture", "key_id": "test-key", "receiver": "https://example.test",
        "audience": "devgraph",
        "policy_digest": hex(SHA256.hash(data: try json(policy))),
        "permissions": policy["permissions"]!,
        "issued_at": now, "expires_at": approved["credential_expires_at"]!,
      ]
      credential = [
        "claims": claims,
        "signature": hex(
          try issuer.signature(
            for: Data("castalia.read-credential.v1/signature\0".utf8) + (try json(claims)))),
      ]
      return try json([
        "schema": wrongResultVersion ? "devgraph.native-read-result.v2" : version.resultSchema,
        "credential": credential, "manifest": [:],
      ])
    case version.requestPath:
      XCTAssertEqual(try json(input["credential"]!), try json(credential))
      let call = try XCTUnwrap(input["call"] as? [String: Any])
      calls.append(call)
      var proof = try XCTUnwrap(input["proof"] as? [String: Any])
      let signature = try data(hex: XCTUnwrap(proof.removeValue(forKey: "signature") as? String))
      let owner = try XCTUnwrap(challenge["subject_public_key"] as? String)
      let key = try Curve25519.Signing.PublicKey(rawRepresentation: data(hex: owner))
      XCTAssertEqual(proof["call_digest"] as? String, hex(SHA256.hash(data: try json(call))))
      XCTAssertEqual(
        proof["credential_digest"] as? String, hex(SHA256.hash(data: try json(credential))))
      XCTAssertTrue(
        key.isValidSignature(
          signature, for: Data("castalia.read-presentation.v1/signature\0".utf8) + (try json(proof))
        ))
      if version == .nativeV2 {
        let item: [String: Any] = [
          "kind": "Task", "id": "legacy", "title": "Legacy work", "description": "Legacy detail",
          "priority": 0, "version": 1,
        ]
        if call["operation"] as? String == "devgraph.work.get" { return try json(item) }
        return try json(["items": [item]])
      }
      let parameters = try XCTUnwrap(call["parameters"] as? [String: Any])
      let path = try XCTUnwrap(parameters["path"] as? String)
      if path.hasPrefix("/work/") { return try json(vectors["related"]!) }
      if path.hasPrefix("/todos/v2/Todo/") { return try json(vectors["detail"]!) }
      return try json(vectors[path.contains("after=") ? "next_page" : "page"]!)
    default: throw WalletFailure.core("unsupported_read_scope")
    }
  }
  func makeChallenge(identity: [String: Any]) throws -> [String: Any] {
    var grant = try XCTUnwrap(vectors["grant"] as? [String: Any])
    if version == .nativeV2 {
      grant["operations"] = ["list", "get"]
      grant["work_kinds"] = ["Task"]
    }
    if version == .pathV4 {
      grant["schema"] = "devgraph.path-read-grant.v1"
      grant["resource_paths"] = [["schema":"devgraph.resource-path.v1","path":["Arena/research","Project/test"]]]
    }
    let operations = grant["operations"] as! [String]
    let permissions = operations.map {
      [
        "operation": "devgraph.work." + $0, "resource": "https://work.zenith-research.ca/devgraph",
        "constraints": grant,
      ] as [String: Any]
    }
    policy = [
      "schema": "castalia.read-policy.v1", "issuer": "fixture", "key_id": "test-key",
      "public_key": hex(issuer.publicKey.rawRepresentation),
      "receiver": "https://example.test", "audience": "devgraph", "max_lifetime_seconds": 600,
      "permissions": permissions,
    ]
    let now = UInt64(Date().timeIntervalSince1970)
    return [
      "schema": "castalia.read-access-challenge.v1",
      "request_id": String(repeating: "11", count: 16),
      "nonce": String(repeating: "A", count: 43),
      "subject_public_key": identity["subject_public_key"]!,
      "installation_id": identity["installation_id"]!, "issuer": "fixture",
      "receiver": "https://example.test",
      "details": [
        "schema": version.rawValue, "policy_digest": String(repeating: "44", count: 32),
        "read_grants": [grant], "authority_policy": policy,
      ],
      "issued_at": now, "expires_at": now + 120, "credential_expires_at": now + 600,
    ]
  }
}
private func data(hex: String) throws -> Data {
  guard hex.count % 2 == 0 else { throw WalletFailure.core("invalid_response") }
  return try Data(
    stride(from: 0, to: hex.count, by: 2).map { offset in
      let start = hex.index(hex.startIndex, offsetBy: offset)
      return try XCTUnwrap(UInt8(hex[start..<hex.index(start, offsetBy: 2)], radix: 16))
    })
}

final class ReadContractTests: XCTestCase {
  func testProducerPagesPreserveCanonicalProgressMetadataAndSnapshotCursor() throws {
    let vectors = try fixture()
    let first = try decodeMonitorPage(json(vectors["page"]!), kind: "Todo", after: nil)
    XCTAssertEqual(first.items.first?.progressLabel, "In progress")
    XCTAssertEqual(first.items.first?.priority, 2)
    XCTAssertEqual(first.items.first?.description, "")
    let next = try decodeMonitorPage(json(vectors["next_page"]!), kind: "Todo", after: first.next)
    XCTAssertNil(next.next)
    XCTAssertEqual(next.items.first?.progressLabel, "Progress not recorded")
    let detail = try JSONDecoder().decode(WorkRecord.self, from: json(vectors["detail"]!))
    XCTAssertEqual(detail.description, "Full Todo description")
    XCTAssertEqual(detail.version, 1)
  }
  func testChangedSnapshotWrongKindDuplicateAndRepeatedCursorsFailClosed() throws {
    let vectors = try fixture()
    let page = try XCTUnwrap(vectors["page"] as? [String: Any])
    let first = try decodeMonitorPage(json(page), kind: "Todo", after: nil)
    XCTAssertThrowsError(try decodeMonitorPage(json(page), kind: "Task", after: nil))
    XCTAssertThrowsError(try decodeMonitorPage(json(page), kind: "Todo", after: first.next))
    var changed = try XCTUnwrap(vectors["next_page"] as? [String: Any])
    changed["revision"] = String(repeating: "aa", count: 32)
    XCTAssertThrowsError(try decodeMonitorPage(json(changed), kind: "Todo", after: first.next))
    var duplicate = page
    let item = try XCTUnwrap((page["items"] as? [[String: Any]])?.first)
    duplicate["items"] = [item, item]
    XCTAssertThrowsError(try decodeMonitorPage(json(duplicate), kind: "Todo", after: nil))
  }
  func testLegacyScopeCannotSilentlyAdmitTodoRelationshipsOrMutation() throws {
    let grant = try JSONDecoder().decode(WorkReadGrant.self, from: json(fixture()["grant"]!))
    XCTAssertThrowsError(try grant.validate())
    XCTAssertNoThrow(try grant.validate(protocol: .monitorV3))
    var value = try XCTUnwrap(fixture()["grant"] as? [String: Any])
    value["operations"] = ["create"]
    let mutation = try JSONDecoder().decode(WorkReadGrant.self, from: json(value))
    XCTAssertThrowsError(try mutation.validate(protocol: .monitorV3))
  }
  func testConsentRejectsUnknownVersionsAndHiddenPermissionExpansion() throws {
    let backend = try ReadBackend(.monitorV3)
    let identity: [String: Any] = [
      "subject_public_key": String(repeating: "12", count: 32),
      "installation_id": String(repeating: "34", count: 16),
    ]
    let challenge = try backend.makeChallenge(identity: identity)
    let now = UInt64(Date().timeIntervalSince1970)
    XCTAssertEqual(
      try decodeReadProposal(
        json(challenge), identity: json(identity), configuration: backend.config, now: now
      ).readProtocol, .monitorV3)
    for change in ["unknown", "hidden"] {
      var corrupt = challenge
      var details = corrupt["details"] as! [String: Any]
      if change == "unknown" {
        details["schema"] = "devgraph.native-read-scope.v999"
      } else {
        var policy = details["authority_policy"] as! [String: Any]
        var permissions = policy["permissions"] as! [[String: Any]]
        permissions[0]["operation"] = "devgraph.work.create"
        policy["permissions"] = permissions
        details["authority_policy"] = policy
      }
      corrupt["details"] = details
      XCTAssertThrowsError(
        try decodeReadProposal(
          json(corrupt), identity: json(identity), configuration: backend.config, now: now))
    }
  }
  func testNativeV2GraphAccessWithoutCommunityMembership() async throws {
    let backend = try ReadBackend(.pathV4)
    ReadProtocolStub.use(backend); defer { ReadProtocolStub.use(nil) }
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: directory) }
    let repository = try WalletRepository(directory: directory)
    _ = try await repository.create(password: "disposable graph access password")
    let backup = try await repository.exportRecovery(password: "disposable recovery password")
    let state = try await repository.verifyBackup(file: backup, password: "disposable recovery password")
    XCTAssertEqual(state.graphAccessProtocol, "castalia.graph-access.v2")
    XCTAssertTrue(state.canRequestWorkAccess)
    XCTAssertFalse(state.membershipActive)
    let identity = try object(await repository.graphAccessIdentityV2())
    XCTAssertEqual(Set(identity.keys), ["subject_public_key","installation_id"])
    let session = URLSessionConfiguration.ephemeral; session.protocolClasses = [ReadProtocolStub.self]
    let client = try DevgraphReadClient(repository: repository,configuration: backend.config,transport: PrivateTransport(configuration: session))
    let proposal = try await client.prepare()
    try await client.connect(proposal)
    let page = try await client.page(kind: "Todo")
    XCTAssertEqual(page.items.count,1)
    await repository.lock()
    _ = try await repository.unlock(password: "disposable graph access password")
    let restored = try await client.manifest()
    XCTAssertEqual(restored.subject_public_key,identity["subject_public_key"] as? String)
  }
  func testModernAndLegacyEnrollmentPersistenceAndSignedReadsThroughNativeCore() async throws {
    for version in [WorkReadProtocol.nativeV2, .monitorV3, .pathV4] {
      let backend = try ReadBackend(version)
      ReadProtocolStub.use(backend)
      defer { ReadProtocolStub.use(nil) }
      let directory = FileManager.default.temporaryDirectory.appendingPathComponent(
        UUID().uuidString)
      defer { try? FileManager.default.removeItem(at: directory) }
      let repository = try await makeMember(directory: directory, issuer: backend.issuer)
      let session = URLSessionConfiguration.ephemeral
      session.protocolClasses = [ReadProtocolStub.self]
      let client = try DevgraphReadClient(
        repository: repository, configuration: backend.config,
        transport: PrivateTransport(configuration: session))
      let proposal = try await client.prepare()
      XCTAssertEqual(proposal.readProtocol, version)
      if version != .nativeV2 {
        backend.wrongResultVersion = true
        do {
          try await client.connect(proposal)
          XCTFail("Mismatched result must not persist")
        } catch { XCTAssertEqual(error as? WalletFailure, .core("invalid_credential")) }
        do {
          _ = try await client.manifest()
          XCTFail("No credential may be stored")
        } catch { XCTAssertTrue(error is WalletFailure) }
        backend.wrongResultVersion = false
        try await client.connect(client.prepare())
      } else {
        try await client.connect(proposal)
      }
      await repository.lock()
      _ = try await repository.unlock(password: "disposable read password")
      let saved = try await client.manifest()
      XCTAssertEqual(saved.readProtocol, version)
      let kind = version != .nativeV2 ? "Todo" : "Task"
      let page = try await client.page(kind: kind)
      XCTAssertEqual(page.items.count, 1)
      if version != .nativeV2 {
        let second = try await client.page(kind: kind, after: XCTUnwrap(page.next))
        XCTAssertEqual(second.items.first?.id, "second")
        XCTAssertNil(second.next)
        let related = try await client.related(kind: "Todo", id: "first", relationship: "blocked")
        XCTAssertEqual(related.items.first?.rowID, "Task/task")
        let beforeDenied = backend.calls.count
        do {
          _ = try await client.related(kind: "Todo", id: "first", relationship: "dependencies")
          XCTFail("Ungranted relation")
        } catch { XCTAssertEqual(error as? WalletFailure, .core("unsupported_read_scope")) }
        XCTAssertEqual(backend.calls.count, beforeDenied)
      }
      let detail = try await client.get(kind: kind, id: XCTUnwrap(page.items.first?.id))
      XCTAssertFalse(detail.description.isEmpty)
      if version != .nativeV2 {
        backend.statusCode = 409
        do {
          _ = try await client.page(kind: kind, after: page.next)
          XCTFail("Changed snapshot")
        } catch { XCTAssertEqual(error as? WalletFailure, .core("work_view_changed")) }
      }
      XCTAssertTrue(
        backend.calls.allSatisfy {
          ($0["operation"] as? String)?.hasPrefix("devgraph.work.") == true
        })
    }
  }
  func testNativeAccessRequestPreparationConsentSignatureAndLockInvalidation() async throws {
    let issuer = Curve25519.Signing.PrivateKey()
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: directory) }
    let repository = try await makeMember(directory: directory, issuer: issuer)
    let identity = try object(await repository.readAccessIdentity())
    let pin = try ReadBackend(.monitorV3).config.authority
    let now = UInt64(Date().timeIntervalSince1970)
    let challenge: [String:Any] = ["schema":"castalia.access-request-challenge.v1",
      "challenge_id":String(repeating:"aa",count:16),"nonce":String(repeating:"A",count:43),
      "issuer":pin.issuer,"receiver":pin.receiver,"subject_public_key":identity["subject_public_key"]!,
      "installation_id":identity["installation_id"]!,"operation":"access.request","issued_at":now,"expires_at":now+120,
      "details":["request_id":String(repeating:"bb",count:16),"intent":NSNull()]]
    let preview = try await repository.prepareAccessRequest(json(challenge),pin:pin,now:now)
    let ticket = repository.lifecycleTicket()
    let approved = try object(await repository.approveAccessRequest(preview,now:now,ticket:ticket))
    XCTAssertNotNil(approved["proof"])
    XCTAssertEqual(try json(approved["challenge"]!),try json(challenge))
    let signature = try XCTUnwrap(approved["signature"] as? String)
    let bytes = try XCTUnwrap(Data(base64Encoded:signature.replacingOccurrences(of:"-",with:"+").replacingOccurrences(of:"_",with:"/")+"=="))
    let owner = try Curve25519.Signing.PublicKey(rawRepresentation:data(hex:XCTUnwrap(identity["subject_public_key"] as? String)))
    XCTAssertTrue(owner.isValidSignature(bytes,for:Data("castalia/access-request-approval/v1\0".utf8)+(try json(challenge))))
    do { _ = try await repository.approveAccessRequest(preview,now:now,ticket:ticket); XCTFail("one use") } catch { }
    let pending = try await repository.prepareAccessRequest(json(challenge),pin:pin,now:now)
    await repository.lock()
    _ = try await repository.unlock(password:"disposable read password")
    do { _ = try await repository.approveAccessRequest(pending,now:now,ticket:ticket); XCTFail("lock must invalidate") } catch { }
  }

  func testLostAccessRequestResponseUsesOriginalIDAndStatusOnly() async throws {
    let backend=try ReadBackend(.monitorV3)
    ReadProtocolStub.use(backend); defer { ReadProtocolStub.use(nil) }
    let directory=FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at:directory) }
    let repository=try await makeMember(directory:directory.appendingPathComponent("wallet"),issuer:backend.issuer)
    let session=URLSessionConfiguration.ephemeral; session.protocolClasses=[ReadProtocolStub.self]
    let client=try DevgraphReadClient(repository:repository,configuration:backend.config,transport:PrivateTransport(configuration:session))
    let store=try WorkAccessRequestStore(directory:directory.appendingPathComponent("requests"))
    let catalog = try WorkAccessCatalog.decode(Data(contentsOf:XCTUnwrap(Bundle.module.url(forResource:"devgraph-access-catalog",withExtension:"json"))),receiver:"https://example.test",issuer:"fixture")
    let preference = try WorkAccessPreference(catalog:catalog,presetID:"contributor",paths:[XCTUnwrap(catalog.scopes.last).resource_path])
    backend.rejectAccessPreparation=true
    do { _ = try await client.prepareAccessRequest(store:store,preference:preference);XCTFail("Rejected preparation") } catch { }
    let stranded = try await client.hasAccessRequest(store:store)
    XCTAssertFalse(stranded)
    backend.rejectAccessPreparation=false
    let first=try await client.prepareAccessRequest(store:store,preference:preference)
    XCTAssertEqual(first.preference,preference)
    let details = try XCTUnwrap(backend.challenge["details"] as? [String:Any])
    XCTAssertEqual(details["schema"] as? String,"devgraph.access-request-action.v2")
    XCTAssertFalse(first.checkingStatus)
    backend.failSubmittedResponse=true
    do { _ = try await client.submitAccessRequest(first); XCTFail("Lost response") } catch { }
    let recovered=try await client.prepareAccessRequest(store:WorkAccessRequestStore(directory:directory.appendingPathComponent("requests")))
    XCTAssertTrue(recovered.checkingStatus)
    XCTAssertEqual(recovered.preference,preference)
    XCTAssertEqual(recovered.requestID,first.requestID)
    let result=try await client.submitAccessRequest(recovered)
    XCTAssertEqual(result.status,"pending")
    XCTAssertEqual(backend.submitCount,1)
    XCTAssertEqual(backend.accessActions,["submit","status"])
  }

  private func makeMember(directory: URL, issuer: Curve25519.Signing.PrivateKey) async throws
    -> WalletRepository
  {
    let repository = try WalletRepository(directory: directory)
    let state = try await repository.create(password: "disposable read password")
    let file = try await repository.exportRecovery(password: "disposable backup password")
    _ = try await repository.verifyBackup(file: file, password: "disposable backup password")
    let root: [String: Any] = [
      "issuerId": "fixture", "keyId": "test-key", "signatureSuite": "Ed25519",
      "publicKey": hex(issuer.publicKey.rawRepresentation),
    ]
    _ = try await repository.approveTrust(
      json([
        "v3": [
          "schema": "castalia.zenith-membership-trust-policy.v1", "version": 1, "roots": [root],
        ]
      ]))
    let owner = try data(hex: XCTUnwrap(state.publicKey))
    let membershipID = Data(
      SHA256.hash(data: Data("castalia/zenith-membership-id/v3\0".utf8) + owner))
    var transcript = Data("castalia/zenith-membership-credential/v3\0".utf8)
    transcript += withUnsafeBytes(of: UInt64(3).littleEndian) { Data($0) }
    transcript += membershipID + owner
    for text in ["active", "fixture", "test-key", "ed25519"] {
      transcript += withUnsafeBytes(of: UInt32(text.utf8.count).littleEndian) { Data($0) }
      transcript += Data(text.utf8)
    }
    let signature = try issuer.signature(for: transcript).base64EncodedString()
      .replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
      .replacingOccurrences(of: "=", with: "")
    _ = try await repository.activateMembership(
      json([
        "schema": "castalia.zenith-membership-credential.v3", "version": 3,
        "membershipId": hex(membershipID), "ownerPublicKey": hex(owner), "status": "active",
        "issuerId": "fixture",
        "issuerKeyId": "test-key", "signatureSuite": "Ed25519", "issuerSignature": signature,
      ]), scoped: false)
    return repository
  }
}
