#if os(macOS)
import XCTest
@testable import CastaliaCustody
import CryptoKit
@testable import ZenithKit

final class HolderSessionTests: XCTestCase {
  func testFrozenSharedFixtureBytes() throws {
    let url = try XCTUnwrap(Bundle.module.url(forResource: "holder-session-v1", withExtension: "json"))
    XCTAssertEqual(HS.digest(try Data(contentsOf: url)), "15537a80cc14ace50d1d47400c53851bf7ba272e1861fd7b7ad051cb8c400046")
  }
  func testUntilRevokedParentHasNoInventedExpiryOrMode() throws {
    var f = try fixture(), root = f["parent_grant"] as! [String: Any], claims = root["claims"] as! [String: Any]
    claims["validity"] = ["schema": "castalia.grant-validity.v1", "mode": "until_revoked", "not_before": 90]
    root["claims"] = claims; f["parent_grant"] = root
    XCTAssertNil(try intent(f).parent.notAfter)
    claims["validity"] = ["schema": "castalia.grant-validity.v1", "mode": "ongoing", "not_before": 90]
    root["claims"] = claims; f["parent_grant"] = root
    XCTAssertThrowsError(try intent(f))
  }
  private func fixture() throws -> [String: Any] {
    let url = try XCTUnwrap(Bundle.module.url(forResource: "holder-session-v1", withExtension: "json"))
    return try HS.object(Data(contentsOf: url))
  }
  private func intent(_ f: [String: Any], permissions: Data? = nil) throws -> HolderSessionPrepareIntent {
    let c = try XCTUnwrap(f["challenge"] as? [String: Any])
    let root = try XCTUnwrap(f["parent_grant"] as? [String: Any])
    let claims = try XCTUnwrap(root["claims"] as? [String: Any])
    let reference: [String: Any] = [
      "schema": "castalia.holder-session-parent-reference.v1", "issuer_pin": f["pin"]!,
      "service": c["service"]!, "parent_grant_id": c["parent_grant_id"]!,
      "parent_grant_digest": c["parent_grant_digest"]!, "parent_revision": c["parent_revision"]!,
      "holder_public_key": c["holder_public_key"]!, "installation_id": c["installation_id"]!,
      "validity": claims["validity"]!, "max_credential_lifetime_seconds": 300,
    ]
    let parent = try HolderSessionParentReference.decode(HS.encode(reference), service: "service:example", now: 103)
    let session = try HolderSessionIdentity.decode(HS.encode([
      "session_handle": String(repeating: "aa", count: 16), "session_public_key": c["session_public_key"]!,
      "session_installation_id": c["session_installation_id"]!, "maximum_expires_at": 600, "service": c["service"]!,
    ]), service: "service:example", expiresAt: 600)
    return try .init(parent: parent, session: session, context: .init(origin: "https://graph.example", audience: "example"),
      requestID: c["request_id"] as! String, requestedTTL: 300, permissions: permissions)
  }
  private func challenge(_ f: [String: Any]) throws -> HolderSessionChallenge {
    try .decode(HS.encode(f["challenge"]!), intent: intent(f), now: 103)
  }
  private func profile(_ f: [String: Any]) throws -> HolderSessionAgentProfile {
    try .decode(HS.encode(["schema": "castalia.holder-session-agent-profile.v1", "provider": f["pin"]!,
      "context": f["context"]!, "maximum_session_seconds": 600]))
  }
  private func response(_ value: Any, command: HolderSessionAgentCommand, fixture f: [String: Any], now: UInt64 = 103) throws -> Data {
    try HolderSessionAgentWire.response(HS.encode(["schema": "castalia.holder-session-agent-result.v1",
      "request_id": String(repeating: "ab", count: 16), "ok": true, "value": value]),
      requestID: String(repeating: "ab", count: 16), command: command, profile: profile(f), now: now)
  }
  func testJCSMatchesSignedVectorAndUTF16KeyOrdering() throws {
    let f = try fixture(), c = try challenge(f)
    let credential = try HolderSessionCredential.decode(HS.encode(f["credential"]!), challenge: c, now: 103)
    XCTAssertEqual(c.digest, "80a724c1c1b99e6484fda03ffa5cd5055a8d0c83b822d78091d37ac36d71b4c4")
    XCTAssertEqual(credential.digest, "0a163a65405bb9b858a26da71b665d699ab22b6290248206f6ec6b63f212fd19")
    XCTAssertEqual(String(data: try HS.encode(["\u{e000}": 1, "\u{10000}": 2]), encoding: .utf8), "{\"\u{10000}\":2,\"\u{e000}\":1}")
  }
  func testLateOriginalResultDoesNotReopenConsentOrExtendExpiry() throws {
    let f = try fixture(), c = try challenge(f)
    XCTAssertThrowsError(try HolderSessionChallenge.decode(HS.encode(f["challenge"]!), intent: intent(f), now: 220))
    let retained = try HolderSessionChallenge.decode(HS.encode(f["challenge"]!), intent: intent(f), now: 221, retained: true)
    XCTAssertEqual(retained.digest, c.digest)
    let token = try HolderSessionCredential.decode(HS.encode(f["credential"]!), challenge: retained, now: 221)
    _ = try response(["installed": true, "expires_at": 400], command: .install(session: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", credential: token), fixture: f, now: 221)
    XCTAssertThrowsError(try HolderSessionCredential.decode(token.data, challenge: c, now: 400))
  }
  func testChallengeRejectsChangedBindings() throws {
    let f = try fixture(), initial = try XCTUnwrap(f["challenge"] as? [String: Any]), i = try intent(f)
    for key in ["service", "issuer", "key_id", "origin", "audience", "parent_grant_id", "parent_grant_digest", "parent_revision", "holder_public_key", "installation_id", "session_installation_id", "session_public_key", "request_id"] {
      var changed = initial; changed[key] = "substituted"
      XCTAssertThrowsError(try HolderSessionChallenge.decode(HS.encode(changed), intent: i, now: 103), key)
    }
    for key in ["review_deadline", "expires_at"] {
      var changed = initial; changed[key] = 999
      XCTAssertThrowsError(try HolderSessionChallenge.decode(HS.encode(changed), intent: i, now: 103), key)
    }
  }
  func testExplicitPermissionsRemainExact() throws {
    let f = try fixture(), c = try XCTUnwrap(f["challenge"] as? [String: Any])
    _ = try HolderSessionChallenge.decode(HS.encode(c), intent: intent(f, permissions: HS.encode(c["permissions"]!)), now: 103)
    var requested = c["permissions"] as! [[String: Any]]; requested[0]["operation"] = "work.list"
    XCTAssertThrowsError(try HolderSessionChallenge.decode(HS.encode(c), intent: intent(f, permissions: HS.encode(requested)), now: 103))
  }
  func testCredentialRejectsTamperingAndOtherIssuer() throws {
    let f = try fixture(), c = try challenge(f)
    var token = f["credential"] as! [String: Any]
    token["signature"] = String(repeating: "00", count: 64)
    XCTAssertThrowsError(try HolderSessionCredential.decode(HS.encode(token), challenge: c, now: 103))
    token = f["credential"] as! [String: Any]; token["parent_grant"] = f["parent_grant"]!
    XCTAssertThrowsError(try HolderSessionCredential.decode(HS.encode(token), challenge: c, now: 103))
  }
  func testHelperProofSignaturesAndCallBinding() throws {
    let f = try fixture(), c = try challenge(f)
    let token = try HolderSessionCredential.decode(HS.encode(f["credential"]!), challenge: c, now: 103)
    let auth = f["authorization"] as! [String: Any], handle = c.intent.session.handle
    _ = try response(["session_signature": auth["session_signature"]!, "challenge_digest": c.digest], command: .possession(session: handle, challenge: c), fixture: f)
    _ = try response(f["status"]!, command: .status(session: handle, challenge: c), fixture: f)
    let presentation: [String: Any] = ["credential": f["credential"]!, "call": f["call"]!, "proof": f["proof"]!]
    _ = try response(presentation, command: .present(session: handle, credential: token, call: HS.encode(f["call"]!)), fixture: f)
    var call = f["call"] as! [String: Any]; call["operation"] = "work.delete"
    XCTAssertThrowsError(try response(presentation, command: .present(session: handle, credential: token, call: HS.encode(call)), fixture: f))
    XCTAssertThrowsError(try response(f["status"]!, command: .status(session: handle, challenge: c), fixture: f, now: 163))
  }
  func testHelperRejectsForgedProofAndWrongContext() throws {
    let f = try fixture(), c = try challenge(f)
    var status = f["status"] as! [String: Any]; status["signature"] = String(repeating: "00", count: 64)
    XCTAssertThrowsError(try response(status, command: .status(session: c.intent.session.handle, challenge: c), fixture: f))
    var changed = f, context = f["context"] as! [String: Any]; context["origin"] = "https://other.example"; changed["context"] = context
    XCTAssertThrowsError(try response(f["status"]!, command: .status(session: c.intent.session.handle, challenge: c), fixture: changed))
    XCTAssertThrowsError(try response(["closed": true, "server_revocation_confirmed": true], command: .close(session: c.intent.session.handle), fixture: f))
  }
  func testStrictInputAndCommandSurface() throws {
    for input in ["{\"a\":1,\"\\u0061\":2}", "{\"a\":1.0}", "{\"a\":1e0}"] {
      XCTAssertThrowsError(try HS.value(Data(input.utf8)))
    }
    XCTAssertThrowsError(try HS.integer(true)); XCTAssertThrowsError(try HS.boolean(1))
    let request = try HS.object(HolderSessionAgentWire.request(.create(expiresAt: 500), requestID: String(repeating: "ab", count: 16)))
    XCTAssertEqual(request["schema"] as? String, "castalia.holder-session-agent-command.v1")
    XCTAssertEqual(Set((request["body"] as! [String: Any]).keys), ["operation", "expires_at"])
    XCTAssertFalse(HolderSessionIntegration.qualified)
  }
  func testPrivatePreparePreservesNullAndRedactsRoot() throws {
    let f = try fixture(), i = try intent(f)
    var body: [String: Any] = ["schema": "secs.holder-session-prepare.v1", "request_id": i.requestID,
      "parent_grant": f["parent_grant"]!, "installation_id": i.parent.installationID,
      "session_public_key": i.session.publicKey, "session_installation_id": i.session.installationID,
      "origin": i.context.origin, "audience": i.context.audience, "permissions": NSNull(), "requested_ttl_seconds": 300]
    func wrap(_ body: [String: Any]) throws -> Data { try HS.encode(["schema": "castalia.holder-session-private-prepare.v1", "body": body]) }
    let payload = try HolderSessionPrivatePayload.prepare(wrap(body), intent: i)
    XCTAssertTrue(try HS.object(payload.bytes)["permissions"] is NSNull)
    XCTAssertEqual(Mirror(reflecting: payload).children.count, 0)
    XCTAssertFalse(String(reflecting: payload).contains(i.parent.holderPublicKey))
    body["permissions"] = (f["challenge"] as! [String: Any])["permissions"]!
    XCTAssertThrowsError(try HolderSessionPrivatePayload.prepare(wrap(body), intent: i))
  }
  func testTypedReviewBindsEveryDisplayedFieldAndPrivateAuthorization() throws {
    let f = try fixture(), c = try challenge(f)
    var summary = try HS.object(c.data)
    summary["schema"] = "castalia.holder-session-review.v1"
    for key in ["challenge_id", "request_id", "nonce", "issuer", "key_id", "service", "issued_at"] { summary.removeValue(forKey: key) }
    summary["issuer_pin"] = f["pin"]!; summary["not_before"] = c.issuedAt
    summary["review_digest_sha256"] = c.digest; summary["hard_expiry"] = true; summary["onward_delegation"] = false
    func wrap(_ summary: [String: Any]) throws -> Data { try HS.encode(["token": String(repeating: "cd", count: 16), "summary": summary]) }
    let review = try HolderSessionAuthorizationReview.decode(wrap(summary), challenge: c, lifecycle: 8, now: 103)
    XCTAssertEqual(review.lifecycle, 8)
    let auth = f["authorization"] as! [String: Any]
    let privateResult = try HolderSessionPrivatePayload.authorization(HS.encode(auth), review: review, sessionSignature: auth["session_signature"] as! String)
    XCTAssertEqual(Mirror(reflecting: privateResult).children.count, 0)
    XCTAssertEqual(Mirror(reflecting: review).children.count, 0)
    var changed = summary; changed["expires_at"] = 401
    XCTAssertThrowsError(try HolderSessionAuthorizationReview.decode(wrap(changed), challenge: c, lifecycle: 8, now: 103))
    changed = summary; changed["hard_expiry"] = 1
    XCTAssertThrowsError(try HolderSessionAuthorizationReview.decode(wrap(changed), challenge: c, lifecycle: 8, now: 103))
    XCTAssertThrowsError(try HolderSessionAuthorizationReview.decode(wrap(summary), challenge: c, lifecycle: 8, now: 220))
    XCTAssertThrowsError(try HolderSessionPrivatePayload.authorization(HS.encode(auth), review: review, sessionSignature: String(repeating: "00", count: 64)))
  }
  func testBrokerWrappersBindOriginalChallengeAndNeverReturnPrivateEnvelopes() throws {
    let f = try fixture(), c = try challenge(f)
    let wrapped = try HS.encode(["schema": "secs.holder-session-challenge-result.v1", "challenge": f["challenge"]!])
    XCTAssertEqual(try HolderSessionBrokerWire.challenge(wrapped, intent: intent(f), now: 103).digest, c.digest)
    var result: [String: Any] = ["schema": "secs.holder-session-result.v1", "request_id": c.intent.requestID,
      "challenge_id": c.challengeID, "state": "issued", "credential": f["credential"]!, "expires_at": c.expiresAt]
    if case .issued(let data) = try HolderSessionBrokerWire.outcome(HS.encode(result), challenge: c, now: 103) {
      XCTAssertEqual(try HS.encode(f["credential"]!), data)
    } else { XCTFail("Expected exact finite result") }
    result["state"] = "pending"; result["credential"] = NSNull()
    if case .unknown = try HolderSessionBrokerWire.outcome(HS.encode(result), challenge: c, now: 103) {} else { XCTFail("Pending does not authorize resubmission") }
    result["challenge_id"] = String(repeating: "00", count: 16)
    XCTAssertThrowsError(try HolderSessionBrokerWire.outcome(HS.encode(result), challenge: c, now: 103))
    result["challenge_id"] = c.challengeID; result["parent_grant"] = f["parent_grant"]!
    XCTAssertThrowsError(try HolderSessionBrokerWire.outcome(HS.encode(result), challenge: c, now: 103))
    let call = try HS.encode(["schema": "devgraph.holder-session-call-result.v1", "service": c.intent.parent.pin.service,
      "operation": "work.get", "result": ["id": "example"]])
    XCTAssertEqual(try HS.object(HolderSessionBrokerWire.businessResult(call, service: c.intent.parent.pin.service, operation: "work.get"))["id"] as? String, "example")
    XCTAssertThrowsError(try HolderSessionBrokerWire.businessResult(call, service: "service:other", operation: "work.get"))
    XCTAssertThrowsError(try HolderSessionBrokerCommand.status(HS.encode(f["authorization"]!)).arguments())
  }
  func testUnqualifiedBridgeDoesNotProbeOrChangeInstalledCore() async throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: directory) }
    let repository = try WalletRepository(directory: directory)
    let before = try await repository.state(), lifecycle = repository.lifecycleTicket()
    do { _ = try await repository.holderSessionParentReference(service: "service:example", now: 103); XCTFail("Unqualified Core must not be probed") }
    catch HolderSessionError.unsupported { }
    let after = try await repository.state()
    XCTAssertEqual(before.revision, after.revision); XCTAssertEqual(before.unlocked, after.unlocked)
    XCTAssertEqual(repository.lifecycleTicket(), lifecycle)
  }
  func testPinnedNativeAgentCreatesClosesAndCannotRestartLostCustody() async throws {
    guard let path = ProcessInfo.processInfo.environment["HOLDER_SESSION_AGENT_TEST_BINARY"] else {
      throw XCTSkip("Opt-in native agent binary not supplied")
    }
    let f = try fixture()
    // XCTest's per-app temporary ancestor can carry an inherited allow ACL,
    // which the Core private-file reader deliberately rejects.
    let directory = URL(fileURLWithPath: "/private/tmp", isDirectory: true).appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: directory) }
    // Foundation's resolvingSymlinksInPath shortens /private/tmp back to /tmp.
    // Keep this explicit physical path for Core's descriptor-relative reader.
    let executable = URL(fileURLWithPath: path), profileFile = directory.appendingPathComponent("profile.json")
    let profileData = try HS.encode(["schema": "castalia.holder-session-agent-profile.v1", "provider": f["pin"]!,
      "context": f["context"]!, "maximum_session_seconds": 600])
    try profileData.write(to: profileFile)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: profileFile.path)
    let launch = HolderSessionAgentLaunch(executable: executable, profileFile: profileFile,
      executableSHA256: HS.digest(try Data(contentsOf: executable)), profileSHA256: HS.digest(profileData))
    let agent = HolderSessionAgentProcess(launch: launch), now = UInt64(Date().timeIntervalSince1970)
    let identity = try await agent.create(expiresAt: now + 60, now: now)
    XCTAssertEqual(identity.service, "service:example")
    XCTAssertEqual(identity.publicKey.count, 64)
    XCTAssertNotEqual(identity.publicKey, (f["challenge"] as! [String: Any])["session_public_key"] as? String)
    try await agent.close(identity, now: now)
    await agent.stop()
    do { _ = try await agent.create(expiresAt: now + 60, now: now); XCTFail("Lost custody must not silently restart") }
    catch { }
    try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: profileFile.path)
    XCTAssertThrowsError(try launch.validate(), "Public-readable custody profile must reject")
  }
  func testRealPinnedCoreApprovalAndHelperCallsAfterWalletLock() async throws {
    guard ProcessInfo.processInfo.environment["HOLDER_SESSION_NATIVE_CORE_TEST"] == "1",
      let path = ProcessInfo.processInfo.environment["HOLDER_SESSION_AGENT_TEST_BINARY"] else {
      throw XCTSkip("Explicit rebuilt Core and helper qualification not selected")
    }
    let directory = URL(fileURLWithPath: "/private/tmp", isDirectory: true).appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: directory) }
    let repository = try WalletRepository(directory: directory.appendingPathComponent("wallet"), holderSessionCoreQualified: true)
    let password = "synthetic native session test password"
    let created = try await repository.create(password: password)
    let backup = try await repository.exportRecovery(password: password)
    _ = try await repository.verifyBackup(file: backup, password: password)
    let issuer = Curve25519.Signing.PrivateKey(), publicKey = issuer.publicKey.rawRepresentation.map { String(format: "%02x", $0) }.joined()
    let pin = HolderIssuerPin(issuer: "provider:example", keyID: "key:one", publicKey: publicKey, service: "service:example")
    let now = UInt64(Date().timeIntervalSince1970), f = try fixture()
    let permissions = (f["challenge"] as! [String: Any])["permissions"]!
    let claims: [String: Any] = ["schema": "secs.holder-grant.v2", "grant_id": String(repeating: "11", count: 16),
      "revision": String(repeating: "22", count: 32), "issuer": pin.issuer, "key_id": pin.key_id, "service": pin.service,
      "holder_public_key": try XCTUnwrap(created.publicKey), "installation_id": NSNull(),
      "validity": ["schema": "castalia.grant-validity.v1", "mode": "until_revoked", "not_before": now - 1],
      "max_credential_lifetime_seconds": 300, "onward_delegation": false, "permissions": permissions]
    func signature(_ value: Any, domain: String) throws -> String {
      try issuer.signature(for: Data((domain + "\0").utf8) + HS.encode(value)).map { String(format: "%02x", $0) }.joined()
    }
    let root = try HS.encode(["claims": claims, "signature": signature(claims, domain: "secs.holder-grant.v2/signature")])
    let grantReview = try await repository.reviewHolderGrant(root, pin: pin, now: now)
    try await repository.saveHolderGrant(grantReview, now: now)
    let reference = try await repository.holderSessionParentReference(service: pin.service, now: now)
    XCTAssertNil(reference.notAfter)
    let context = try HolderSessionContext(origin: "https://graph.example", audience: "example")
    let profile = try HS.encode(["schema": "castalia.holder-session-agent-profile.v1", "provider": HS.object(JSONEncoder().encode(pin)),
      "context": HS.object(JSONEncoder().encode(context)), "maximum_session_seconds": 600])
    let file = directory.appendingPathComponent("profile.json"); try profile.write(to: file)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
    let executable = URL(fileURLWithPath: path)
    let agent = HolderSessionAgentProcess(launch: .init(executable: executable, profileFile: file,
      executableSHA256: HS.digest(try Data(contentsOf: executable)), profileSHA256: HS.digest(profile)))
    let session = try await agent.create(expiresAt: now + 300, now: now)
    let intent = try HolderSessionPrepareIntent(parent: reference, session: session, context: context,
      requestID: String(repeating: "44", count: 16), requestedTTL: 300)
    let privatePrepare = try await repository.buildHolderSessionPrepare(intent, now: now)
    XCTAssertTrue(try HS.object(privatePrepare.bytes)["permissions"] is NSNull)
    let issued = UInt64(Date().timeIntervalSince1970)
    let raw: [String: Any] = ["schema": "secs.holder-session-challenge.v1", "challenge_id": String(repeating: "33", count: 16),
      "request_id": intent.requestID, "nonce": String(repeating: "55", count: 32), "issuer": pin.issuer,
      "key_id": pin.key_id, "service": pin.service, "origin": context.origin, "audience": context.audience,
      "parent_grant_id": reference.grantID, "parent_grant_digest": reference.digest, "parent_revision": reference.revision,
      "holder_public_key": reference.holderPublicKey, "installation_id": reference.installationID,
      "session_public_key": session.publicKey, "session_installation_id": session.installationID,
      "permissions": permissions, "issued_at": issued, "review_deadline": min(issued + 120, session.maximumExpiresAt), "expires_at": session.maximumExpiresAt]
    let challenge = try HolderSessionChallenge.decode(HS.encode(raw), intent: intent, now: issued)
    let review = try await repository.prepareHolderSessionAuthorization(challenge, now: issued)
    let possession = try await agent.possession(challenge, now: issued)
    let authorization = try await repository.approveHolderSessionAuthorization(review, sessionSignature: possession, now: issued)
    XCTAssertEqual(try HS.object(authorization.bytes)["schema"] as? String, "secs.holder-session-authorization.v1")
    let tokenClaims: [String: Any] = ["schema": "secs.holder-session-credential.v1", "credential_id": String(repeating: "88", count: 16),
      "challenge_digest": challenge.digest, "challenge": raw]
    let tokenData = try HS.encode(["claims": tokenClaims, "signature": signature(tokenClaims, domain: "secs.holder-session-credential.v1/signature")])
    let credential = try HolderSessionCredential.decode(tokenData, challenge: challenge, now: issued)
    try await agent.install(credential, now: issued)
    await repository.lock()
    var nonces = Set<String>()
    for _ in 0..<2 {
      let proof = try HS.object(await agent.present(credential, call: HS.encode(f["call"]!), now: UInt64(Date().timeIntervalSince1970)))["proof"] as! [String: Any]
      XCTAssertTrue(nonces.insert(proof["nonce"] as! String).inserted)
    }
    _ = try await agent.status(challenge, now: UInt64(Date().timeIntervalSince1970))
    let locked = try await repository.state(); XCTAssertFalse(locked.unlocked)
    await agent.stop()
  }
  private func flowFixture(dropReply: Bool = false, failDispatch: Bool = false) throws -> (HolderSessionFlow, FlowWallet, FlowIssuer, FlowClock, URL) {
    let f = try fixture(), c = try challenge(f)
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    let store = try FlowStore(directory: root, failDispatch: failDispatch)
    let clock = FlowClock(), wallet = FlowWallet(fixture: f, parent: c.intent.parent)
    let issuer = FlowIssuer(fixture: f, journal: store, dropReply: dropReply)
    let flow = try HolderSessionFlow(clientID: String(repeating: "ab", count: 16), requestID: c.intent.requestID,
      service: "service:example", context: c.intent.context, wallet: wallet, custody: FlowCustody(fixture: f),
      issuer: issuer, journal: store, clock: { clock.now() })
    return (flow, wallet, issuer, clock, root)
  }
  func testSessionCallsContinueWithRootLockedAndStopAtHardEnd() async throws {
    let (flow, wallet, issuer, clock, directory) = try flowFixture()
    defer { try? FileManager.default.removeItem(at: directory) }
    let c = try await flow.prepare(permissions: nil, lifetime: 300, maximumSessionSeconds: 600)
    _ = try await flow.prepareNativeReview()
    try await flow.approveNativeReview(digest: c.digest, expiresAt: c.expiresAt)
    let offeredHandle = await flow.publicCredentialHandle(), handle = try XCTUnwrap(offeredHandle)
    await wallet.lock(); await flow.invalidateConsent()
    let callsBefore = await wallet.calls()
    let f = try fixture(), call = try HS.encode(f["call"]!)
    for _ in 0..<2 {
      let result = try await flow.execute(client: String(repeating: "ab", count: 16), handle: handle, call: call)
      XCTAssertEqual(try HS.object(result)["id"] as? String, "example")
    }
    let callsAfter = await wallet.calls(), exchanges = await issuer.exchanges()
    XCTAssertEqual(callsBefore, callsAfter, "Root Wallet must not participate in session calls")
    XCTAssertEqual(exchanges, 1)
    clock.set(400)
    do { _ = try await flow.execute(client: String(repeating: "ab", count: 16), handle: handle, call: call); XCTFail("Hard expiry") } catch { }
    let phase = await flow.currentPhase(); XCTAssertEqual(phase, .expired)
  }
  func testLostReplyRecoversOriginalAfterConsentDeadlineWithoutWallet() async throws {
    let (flow, wallet, issuer, clock, directory) = try flowFixture(dropReply: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    let c = try await flow.prepare(permissions: nil, lifetime: 300, maximumSessionSeconds: 600)
    _ = try await flow.prepareNativeReview()
    try await flow.approveNativeReview(digest: c.digest, expiresAt: c.expiresAt)
    let unknown = await flow.currentPhase(); XCTAssertEqual(unknown, .outcomeUnknown)
    await wallet.lock(); let callsBefore = await wallet.calls(); clock.set(221)
    try await flow.checkOriginalResult()
    let phase = await flow.currentPhase(), callsAfter = await wallet.calls(), exchanges = await issuer.exchanges()
    XCTAssertEqual(phase, .issued); XCTAssertEqual(callsBefore, callsAfter); XCTAssertEqual(exchanges, 1)
    let handle = await flow.publicCredentialHandle(); XCTAssertNotNil(handle)
  }
  func testDispatchFenceFailureNeverExchangesOrAutomaticallySignsAgain() async throws {
    let (flow, _, issuer, _, directory) = try flowFixture(failDispatch: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    let c = try await flow.prepare(permissions: nil, lifetime: 300, maximumSessionSeconds: 600)
    _ = try await flow.prepareNativeReview()
    do { try await flow.approveNativeReview(digest: c.digest, expiresAt: c.expiresAt); XCTFail("Journal fence must fail") } catch { }
    do { try await flow.approveNativeReview(digest: c.digest, expiresAt: c.expiresAt); XCTFail("Consent consumed") } catch { }
    let count = await issuer.exchanges(); XCTAssertEqual(count, 0)
  }
  func testClientBindingAndCloseDestroyUseWithoutClaimingRevocation() async throws {
    let (flow, _, issuer, _, directory) = try flowFixture()
    defer { try? FileManager.default.removeItem(at: directory) }
    let c = try await flow.prepare(permissions: nil, lifetime: 300, maximumSessionSeconds: 600)
    _ = try await flow.prepareNativeReview()
    try await flow.approveNativeReview(digest: c.digest, expiresAt: c.expiresAt)
    let offeredHandle = await flow.publicCredentialHandle(), handle = try XCTUnwrap(offeredHandle)
    let call = try HS.encode(try fixture()["call"]!)
    do { _ = try await flow.execute(client: String(repeating: "cd", count: 16), handle: handle, call: call); XCTFail("Other client") } catch { }
    try await flow.close()
    do { _ = try await flow.execute(client: String(repeating: "ab", count: 16), handle: handle, call: call); XCTFail("Closed client") } catch { }
    let calls = await issuer.callCount(); XCTAssertEqual(calls, 0)
    let bytes = try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil).map { try Data(contentsOf: $0) }
    XCTAssertEqual(bytes.count, 1)
    for data in bytes {
      let record = try JSONDecoder().decode(HolderSessionFlowRecord.self, from: data)
      XCTAssertTrue(record.dispatched); XCTAssertEqual(record.phase, .closed)
      XCTAssertFalse(String(decoding: data, as: UTF8.self).contains("parent_grant\""))
    }
  }
}

private final class FlowClock: @unchecked Sendable {
  private let lock = NSLock(); private var value: UInt64 = 103
  func now() -> UInt64 { lock.lock(); defer { lock.unlock() }; return value }
  func set(_ value: UInt64) { lock.lock(); defer { lock.unlock() }; self.value = value }
}
private final class FlowStore: HolderSessionRecordStore, @unchecked Sendable {
  private let lock = NSLock(), journal: HolderSessionJournal
  private var last: HolderSessionFlowRecord?
  let failDispatch: Bool
  init(directory: URL, failDispatch: Bool) throws { journal = try .init(directory: directory); self.failDispatch = failDispatch }
  func save(_ record: HolderSessionFlowRecord, replacing: HolderSessionFlowRecord?) throws {
    lock.lock(); defer { lock.unlock() }
    if failDispatch && record.dispatched { throw HolderSessionError.invalid }
    try journal.save(record, replacing: replacing); last = record
  }
  func dispatched() -> Bool { lock.lock(); defer { lock.unlock() }; return last?.dispatched == true }
}
private actor FlowWallet: HolderSessionWalletPort {
  let fixture: [String: Any], reference: HolderSessionParentReference
  private var locked = false, count = 0
  init(fixture: [String: Any], parent: HolderSessionParentReference) { self.fixture = fixture; reference = parent }
  func lock() { locked = true }
  func calls() -> Int { count }
  private func check() throws { guard !locked else { throw HolderSessionError.invalid }; count += 1 }
  func parent(service: String, now: UInt64) throws -> HolderSessionParentReference { try check(); return reference }
  func prepare(_ i: HolderSessionPrepareIntent, now: UInt64) throws -> HolderSessionPrivatePayload {
    try check()
    return try .prepare(HS.encode(["schema": "castalia.holder-session-private-prepare.v1", "body": [
      "schema": "secs.holder-session-prepare.v1", "request_id": i.requestID, "parent_grant": fixture["parent_grant"]!,
      "installation_id": i.parent.installationID, "session_public_key": i.session.publicKey,
      "session_installation_id": i.session.installationID, "origin": i.context.origin, "audience": i.context.audience,
      "permissions": NSNull(), "requested_ttl_seconds": i.requestedTTL]]), intent: i)
  }
  func review(_ challenge: HolderSessionChallenge, now: UInt64) throws -> HolderSessionAuthorizationReview {
    try check(); var s = try HS.object(challenge.data)
    for key in ["challenge_id", "request_id", "nonce", "issuer", "key_id", "service", "issued_at"] { s.removeValue(forKey: key) }
    s["schema"] = "castalia.holder-session-review.v1"; s["issuer_pin"] = fixture["pin"]!
    s["not_before"] = challenge.issuedAt; s["review_digest_sha256"] = challenge.digest; s["hard_expiry"] = true; s["onward_delegation"] = false
    return try .decode(HS.encode(["token": String(repeating: "cd", count: 16), "summary": s]), challenge: challenge, lifecycle: 0, now: now)
  }
  func approve(_ review: HolderSessionAuthorizationReview, signature: String, now: UInt64) throws -> HolderSessionPrivatePayload {
    try check(); return try .authorization(HS.encode(fixture["authorization"]!), review: review, sessionSignature: signature)
  }
}
private actor FlowCustody: HolderSessionCustody {
  let fixture: [String: Any]
  init(fixture: [String: Any]) { self.fixture = fixture }
  func create(expiresAt: UInt64, now: UInt64) throws -> HolderSessionIdentity {
    let c = fixture["challenge"] as! [String: Any]
    return try .decode(HS.encode(["session_handle": String(repeating: "aa", count: 16), "session_public_key": c["session_public_key"]!,
      "session_installation_id": c["session_installation_id"]!, "service": c["service"]!, "maximum_expires_at": expiresAt]),
      service: "service:example", expiresAt: expiresAt)
  }
  func possession(_ challenge: HolderSessionChallenge, now: UInt64) -> String { (fixture["authorization"] as! [String: Any])["session_signature"] as! String }
  func install(_ credential: HolderSessionCredential, now: UInt64) {}
  func present(_ credential: HolderSessionCredential, call: Data, now: UInt64) throws -> Data {
    try HS.encode(["credential": fixture["credential"]!, "call": HS.object(call), "proof": fixture["proof"]!])
  }
  func status(_ challenge: HolderSessionChallenge, now: UInt64) throws -> Data { try HS.encode(fixture["status"]!) }
  func stop() {}
}
private actor FlowIssuer: HolderSessionIssuer {
  let fixture: [String: Any], journal: FlowStore, dropReply: Bool
  private var exchangeCount = 0, calls = 0
  init(fixture: [String: Any], journal: FlowStore, dropReply: Bool) { self.fixture = fixture; self.journal = journal; self.dropReply = dropReply }
  func exchanges() -> Int { exchangeCount }
  func callCount() -> Int { calls }
  func prepare(_ body: HolderSessionPrivatePayload) throws -> Data { try HS.encode(fixture["challenge"]!) }
  func exchange(_ authorization: HolderSessionPrivatePayload, challenge: HolderSessionChallenge) throws -> HolderSessionExchangeResult {
    guard journal.dispatched() else { throw HolderSessionError.invalid }
    exchangeCount += 1; return dropReply ? .unknown : .issued(try HS.encode(fixture["credential"]!))
  }
  func status(_ proof: Data, challenge: HolderSessionChallenge) throws -> HolderSessionExchangeResult { .issued(try HS.encode(fixture["credential"]!)) }
  func execute(_ presentation: Data) throws -> Data { calls += 1; return try HS.encode(["id": "example"]) }
}
#endif
