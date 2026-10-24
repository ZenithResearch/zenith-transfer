import Foundation
import CryptoKit
import XCTest
import CastaliaSignerProtocol

final class SignerProtocolTests: XCTestCase {
  private let client = try! Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x17, count: 32))
  private let signer = try! Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x29, count: 32))
  private let wallet = String(repeating: "a", count: 64)
  private var service: SignerService { try! SignerService(issuer: "devgraph-example-provider", audience: "devgraph", keyID: "read-v1", publicKey: String(repeating: "b", count: 64)) }
  private func request(id: String = UUID().uuidString.lowercased(), operation: SignerOperation = .prepareServiceProof,
    expectedWallet: String? = nil) throws -> SignedSignerRequest {
    let proof = operation == .prepareServiceProof
    return try SignedSignerRequest(body: SignerRequestBody(requestID: id,
      clientKey: SignerWire.hex(client.publicKey.rawRepresentation), expectedWallet: expectedWallet ?? wallet,
      issuedAt: 100, expiresAt: 220, nonce: String(repeating: "c", count: 64), operation: operation,
      service: proof ? service : nil, proofKind: proof ? .operatorAccessV1 : nil,
      payload: proof ? Data("{\"original\":\"exact challenge bytes\"}".utf8) : Data()), key: client)
  }
  private func policy(revoked: Bool = false, walletKey: String? = nil) throws -> SignerClientPolicy {
    try SignerClientPolicy(clientKey: SignerWire.hex(client.publicKey.rawRepresentation), walletKey: walletKey ?? wallet,
      operations: Set(SignerOperation.allCases), services: [service], revoked: revoked)
  }
  func testExactRequestAndResponseRoundTripBindWalletClientAndPayload() throws {
    let original = try request()
    let decoded = try SignedSignerRequest.decode(original.encoded(), now: 101)
    XCTAssertEqual(decoded, original)
    XCTAssertEqual(decoded.body.payload, Data("{\"original\":\"exact challenge bytes\"}".utf8))
    let response = try SignedSignerResponse(body: SignerResponseBody(request: original,
      signerKey: SignerWire.hex(signer.publicKey.rawRepresentation), walletKey: wallet, result: .approved,
      expiresAt: 200, payload: Data("approved proof".utf8)), key: signer)
    XCTAssertEqual(try SignedSignerResponse.decode(response.encoded(), request: original,
      pinnedSigner: SignerWire.hex(signer.publicKey.rawRepresentation), now: 101), response)
    XCTAssertThrowsError(try response.verify(request: request(), pinnedSigner: SignerWire.hex(signer.publicKey.rawRepresentation), now: 101))
    XCTAssertThrowsError(try response.verify(request: original, pinnedSigner: SignerWire.hex(client.publicKey.rawRepresentation), now: 101))
  }
  func testClosedWireRejectsExtraFieldsDuplicateEscapedKeysAndUnknownOperations() throws {
    let original = try request()
    var raw = try XCTUnwrap(JSONSerialization.jsonObject(with: original.encoded()) as? [String: Any])
    raw["password"] = "not accepted"
    XCTAssertThrowsError(try SignedSignerRequest.decode(JSONSerialization.data(withJSONObject: raw), now: 101))
    raw.removeValue(forKey: "password")
    var body = raw["body"] as! [String: Any]
    var authority = body["service"] as! [String: Any]; authority["receiver"] = "https://route.example"
    body["service"] = authority; raw["body"] = body
    XCTAssertThrowsError(try SignedSignerRequest.decode(JSONSerialization.data(withJSONObject: raw), now: 101))
    let encoded = String(data: try original.encoded(), encoding: .utf8)!
    let duplicate = encoded.replacingOccurrences(of: "\"schema\":", with: "\"sc\\u0068ema\":\"ignored\",\"schema\":")
    XCTAssertThrowsError(try SignedSignerRequest.decode(Data(duplicate.utf8), now: 101))
    let changed = encoded.replacingOccurrences(of: "prepareServiceProof", with: "signBytes")
    XCTAssertThrowsError(try SignedSignerRequest.decode(Data(changed.utf8), now: 101))
  }
  func testExpiryBoundsAndSignedPayloadSubstitutionFailClosed() throws {
    let original = try request()
    XCTAssertThrowsError(try original.verify(now: 99)); XCTAssertThrowsError(try original.verify(now: 220))
    var raw = try XCTUnwrap(JSONSerialization.jsonObject(with: original.encoded()) as? [String: Any])
    var body = raw["body"] as! [String: Any]; body["payload"] = Data("changed".utf8).base64EncodedString(); raw["body"] = body
    XCTAssertThrowsError(try SignedSignerRequest.decode(JSONSerialization.data(withJSONObject: raw), now: 101))
    XCTAssertThrowsError(try SignerRequestBody(clientKey: SignerWire.hex(client.publicKey.rawRepresentation), expectedWallet: wallet,
      issuedAt: 100, expiresAt: 221, nonce: String(repeating: "c", count: 64), operation: .status))
    XCTAssertThrowsError(try SignerRequestBody(clientKey: SignerWire.hex(client.publicKey.rawRepresentation), expectedWallet: wallet,
      issuedAt: 100, expiresAt: 220, nonce: String(repeating: "c", count: 64), operation: .prepareServiceProof,
      service: service, proofKind: .operatorAccessV1, payload: Data(repeating: 0, count: 262_145)))
  }
  func testPolicyRejectsUnpairedRevokedWrongWalletAndUnapprovedService() throws {
    let original = try request(); try policy().authorize(original, now: 101)
    XCTAssertThrowsError(try policy(revoked: true).authorize(original, now: 101))
    XCTAssertThrowsError(try policy(walletKey: String(repeating: "d", count: 64)).authorize(original, now: 101))
    let empty = try SignerClientPolicy(clientKey: SignerWire.hex(client.publicKey.rawRepresentation), walletKey: wallet,
      operations: [.prepareServiceProof], services: [])
    XCTAssertThrowsError(try empty.authorize(original, now: 101))
    let unrelated = try SignerClientPolicy(clientKey: SignerWire.hex(signer.publicKey.rawRepresentation), walletKey: wallet,
      operations: [.prepareServiceProof], services: [service])
    XCTAssertThrowsError(try unrelated.authorize(original, now: 101))
  }
  func testJournalOneUseApprovalAndExactResultSurviveRestart() async throws {
    let store = try fixtureStore(), journal = try SignerConsentJournal(store: store)
    let original = try request(), policy = try policy(), digest = try original.digest
    _ = try await journal.register(original, policy: policy, verifiedSummary: Data("verified summary".utf8), now: 101)
    let ticket = try await journal.beginApproval(requestID: original.body.requestID, clientKey: original.body.clientKey,
      reviewedDigest: digest, policy: policy, now: 101)
    try await journal.complete(ticket, approvedProof: Data("exact original proof".utf8), policy: policy, now: 102)
    await rejects { try await journal.complete(ticket, approvedProof: Data("another proof".utf8), policy: policy, now: 103) }
    let restarted = try SignerConsentJournal(store: store)
    let recovered = try await restarted.entry(requestID: original.body.requestID, clientKey: original.body.clientKey)
    XCTAssertEqual(recovered.phase, .approved); XCTAssertEqual(recovered.approvedProof, Data("exact original proof".utf8))
    await rejects { try await restarted.beginApproval(requestID: original.body.requestID, clientKey: original.body.clientKey, reviewedDigest: digest, policy: policy, now: 104) }
  }
  func testCancelledOrInterruptedSigningCannotBeRepeated() async throws {
    let store = try fixtureStore(), journal = try SignerConsentJournal(store: store)
    let original = try request(), policy = try policy()
    _ = try await journal.register(original, policy: policy, verifiedSummary: Data("summary".utf8), now: 101)
    let ticket = try await journal.beginApproval(requestID: original.body.requestID, clientKey: original.body.clientKey,
      reviewedDigest: original.digest, policy: policy, now: 101)
    let restarted = try SignerConsentJournal(store: store)
    let recovered = try await restarted.entry(requestID: original.body.requestID, clientKey: original.body.clientKey)
    XCTAssertEqual(recovered.phase, .uncertain)
    await rejects { try await restarted.beginApproval(requestID: original.body.requestID, clientKey: original.body.clientKey,
      reviewedDigest: original.digest, policy: policy, now: 102) }
    try await restarted.invalidatePending()
    await rejects { try await journal.complete(ticket, approvedProof: Data("late".utf8), policy: policy, now: 102) }
  }
  func testChangedRequestIDAndRevokedPolicyCannotReuseReview() async throws {
    let store = try fixtureStore(), journal = try SignerConsentJournal(store: store)
    let original = try request(), policy = try policy()
    _ = try await journal.register(original, policy: policy, verifiedSummary: Data("summary".utf8), now: 101)
    let changed = try request(id: original.body.requestID, expectedWallet: String(repeating: "d", count: 64))
    await rejects { try await journal.register(changed, policy: self.policy(walletKey: String(repeating: "d", count: 64)), verifiedSummary: Data("changed".utf8), now: 101) }
    await rejects { try await journal.beginApproval(requestID: original.body.requestID, clientKey: original.body.clientKey,
      reviewedDigest: original.digest, policy: self.policy(revoked: true), now: 101) }
    try await journal.cancel(requestID: original.body.requestID, clientKey: original.body.clientKey)
    await rejects { try await journal.beginApproval(requestID: original.body.requestID, clientKey: original.body.clientKey,
      reviewedDigest: original.digest, policy: policy, now: 101) }
  }
  func testFailedDurableSaveDoesNotAcceptOrAdvanceConsent() async throws {
    let store = try fixtureStore(), journal = try SignerConsentJournal(store: store)
    let original = try request(), policy = try policy()
    store.failNextSave()
    await rejects { try await journal.register(original, policy: policy, verifiedSummary: Data("summary".utf8), now: 101) }
    await rejects { try await journal.entry(requestID: original.body.requestID, clientKey: original.body.clientKey) }
    _ = try await journal.register(original, policy: policy, verifiedSummary: Data("summary".utf8), now: 101)
    store.failNextSave()
    await rejects { try await journal.beginApproval(requestID: original.body.requestID, clientKey: original.body.clientKey,
      reviewedDigest: original.digest, policy: policy, now: 101) }
    let entry = try await journal.entry(requestID: original.body.requestID, clientKey: original.body.clientKey)
    XCTAssertEqual(entry.phase, .pending)
  }
  private func fixtureStore() throws -> JournalFixtureStore {
    let store = JournalFixtureStore(), policy = try policy()
    let peer = try SignerPeer(signingKey: policy.clientKey, agreementKey: String(repeating: "e", count: 64))
    var snapshot = SignerJournalSnapshot(); snapshot.revision = 1
    snapshot.pairings[policy.clientKey] = try SignerPairing(peer: peer, label: "Synthetic client", callbackScheme: "zenith-transfer-client", policy: policy)
    try store.save(snapshot, expectedRevision: 0); return store
  }
  private func rejects<T>(_ body: () async throws -> T, file: StaticString = #filePath, line: UInt = #line) async {
    do { _ = try await body(); XCTFail("Expected closed rejection", file: file, line: line) } catch { }
  }
}
private final class JournalFixtureStore: SignerJournalStore, @unchecked Sendable {
  private let lock = NSLock()
  private var snapshot: SignerJournalSnapshot?
  private var shouldFail = false
  func failNextSave() { lock.withLock { shouldFail = true } }
  func load() throws -> SignerJournalSnapshot? { lock.withLock { snapshot } }
  func save(_ next: SignerJournalSnapshot, expectedRevision: UInt64) throws {
    try lock.withLock {
      if shouldFail { shouldFail = false; throw SignerFailure.unavailable }
      guard (snapshot?.revision ?? 0) == expectedRevision, next.revision == expectedRevision + 1 else { throw SignerFailure.changedRequest }
      snapshot = next
    }
  }
}
