import CastaliaSignerProtocol
import CastaliaSignerStorage
import CryptoKit
import Foundation
import XCTest

final class SignerHostCoordinatorTests: XCTestCase {
  private let client = Curve25519.Signing.PrivateKey()
  private let signer = Curve25519.Signing.PrivateKey()
  private let wallet = String(repeating: "a", count: 64)
  private let service = try! SignerService(issuer: "devgraph-provider-example", audience: "devgraph", keyID: "read-v1", publicKey: String(repeating: "b", count: 64))
  private func request(_ operation: SignerOperation = .prepareServiceProof, original: String? = nil) throws -> SignedSignerRequest {
    try SignedSignerRequest(body: SignerRequestBody(clientKey: SignerWire.hex(client.publicKey.rawRepresentation),
      expectedWallet: wallet, issuedAt: 100, expiresAt: 200, nonce: String(repeating: "c", count: 64), operation: operation,
      service: operation == .prepareServiceProof ? service : nil, proofKind: operation == .prepareServiceProof ? .operatorAccessV1 : nil,
      originalRequestID: original, payload: operation == .prepareServiceProof ? Data("synthetic native challenge".utf8) : Data()), key: client)
  }
  private func fixture() async throws -> (SignerHostCoordinator, SignerConsentJournal, SyntheticRootEngine, SignerPairing, HostEventFixture) {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("signer-host-fixture-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    addTeardownBlock { try? FileManager.default.removeItem(at: directory) }
    let store = try EncryptedSignerJournal(directory: directory, key: SymmetricKey(size: .bits256))
    let journal = try SignerConsentJournal(store: store)
    let policy = try SignerClientPolicy(clientKey: SignerWire.hex(client.publicKey.rawRepresentation), walletKey: wallet,
      operations: Set(SignerOperation.allCases), services: [service])
    let pairing = try SignerPairing(peer: SignerPeer(signingKey: policy.clientKey, agreementKey: String(repeating: "e", count: 64)),
      label: "Synthetic Transfer", callbackScheme: "zenith-transfer-client", policy: policy)
    try await journal.pair(pairing, replacing: nil)
    let engine = SyntheticRootEngine(wallet: wallet), events = HostEventFixture()
    let host = SignerHostCoordinator(journal: journal, engine: engine, identity: signer, clock: { 101 }, event: { await events.record($0) })
    return (host, journal, engine, pairing, events)
  }
  private func exchange(_ request: SignedSignerRequest, _ host: SignerHostCoordinator) async throws -> SignedSignerResponse {
    let bytes = try await host.exchange(request.encoded())
    return try SignedSignerResponse.decode(bytes, request: request, pinnedSigner: SignerWire.hex(signer.publicKey.rawRepresentation), now: 101)
  }
  func testOnlySignerOwnedApprovalCanSignAndRecoveryReturnsOneOriginalProof() async throws {
    let (host, _, engine, _, events) = try await fixture(), original = try request()
    let pending = try await exchange(original, host); XCTAssertEqual(pending.body.result, .pending)
    let approval = try request(.requestServiceApproval, original: original.body.requestID)
    _ = try await exchange(approval, host)
    let countBefore = await engine.approved; XCTAssertEqual(countBefore, 0)
    let eventCount = await events.count; XCTAssertEqual(eventCount, 1)
    do { try await host.approve(requestID: original.body.requestID, clientKey: original.body.clientKey, reviewedDigest: String(repeating: "d", count: 64)); XCTFail("Changed review must fail") } catch {}
    try await host.approve(requestID: original.body.requestID, clientKey: original.body.clientKey, reviewedDigest: original.digest)
    let recovered = try await exchange(request(.recoverOriginalResult, original: original.body.requestID), host)
    XCTAssertEqual(recovered.body.result, .approved); XCTAssertEqual(recovered.body.payload, Data("one original synthetic proof".utf8))
    let duplicate = try await exchange(original, host); XCTAssertEqual(duplicate.body.payload, recovered.body.payload)
    do { try await host.approve(requestID: original.body.requestID, clientKey: original.body.clientKey, reviewedDigest: original.digest); XCTFail("Repeated approval must fail") } catch {}
    let approved = await engine.approved, prepared = await engine.prepared
    XCTAssertEqual(approved, 1); XCTAssertEqual(prepared, 1)
  }
  func testCancellationAndPairingRevocationCannotBeOverriddenByClient() async throws {
    let (host, journal, engine, pairing, _) = try await fixture(), original = try request()
    _ = try await exchange(original, host)
    _ = try await exchange(request(.cancel, original: original.body.requestID), host)
    do { try await host.approve(requestID: original.body.requestID, clientKey: original.body.clientKey, reviewedDigest: original.digest); XCTFail("Cancelled review must fail") } catch {}
    let next = try request(); _ = try await exchange(next, host)
    let revokedPolicy = try SignerClientPolicy(clientKey: pairing.policy.clientKey, walletKey: wallet,
      operations: pairing.policy.operations, services: pairing.policy.services, revoked: true)
    let revoked = try SignerPairing(peer: pairing.peer, label: pairing.label, callbackScheme: pairing.callbackScheme, policy: revokedPolicy)
    try await journal.pair(revoked, replacing: pairing)
    do { _ = try await exchange(next, host); XCTFail("Revoked pair must fail") } catch {}
    do { try await host.approve(requestID: next.body.requestID, clientKey: next.body.clientKey, reviewedDigest: next.digest); XCTFail("Revoked review must fail") } catch {}
    let approved = await engine.approved; XCTAssertEqual(approved, 0)
  }
  func testRemovedServiceCannotRecoverRetainedRootProof() async throws {
    let (host, journal, _, pairing, _) = try await fixture(), original = try request()
    _ = try await exchange(original, host)
    try await host.approve(requestID: original.body.requestID, clientKey: original.body.clientKey, reviewedDigest: original.digest)
    let reducedPolicy = try SignerClientPolicy(clientKey: pairing.policy.clientKey, walletKey: wallet,
      operations: pairing.policy.operations, services: [])
    let reduced = try SignerPairing(peer: pairing.peer, label: pairing.label, callbackScheme: pairing.callbackScheme, policy: reducedPolicy)
    try await journal.pair(reduced, replacing: pairing)
    do { _ = try await exchange(request(.recoverOriginalResult, original: original.body.requestID), host); XCTFail("Removed service must fail") } catch {}
  }
  func testLockInvalidatesReviewAndClientCannotSupplyAnApprovalOperation() async throws {
    let (host, _, engine, _, _) = try await fixture(), original = try request()
    _ = try await exchange(original, host); _ = try await exchange(request(.lock), host)
    do { try await host.approve(requestID: original.body.requestID, clientKey: original.body.clientKey, reviewedDigest: original.digest); XCTFail("Lock must cancel consent") } catch {}
    let count = await engine.approved; XCTAssertEqual(count, 0)
    let encoded = String(decoding: try original.encoded(), as: UTF8.self).replacingOccurrences(of: "prepareServiceProof", with: "approve")
    do { _ = try await host.exchange(Data(encoded.utf8)); XCTFail("No approval RPC exists") } catch {}
  }
}
private actor HostEventFixture {
  var count = 0
  func record(_ event: SignerHostEvent) { count += 1 }
}
private actor SyntheticRootEngine: SignerRootEngine {
  let wallet: String
  var approved = 0, prepared = 0
  var unlocked = true
  init(wallet: String) { self.wallet = wallet }
  func descriptor() throws -> SignerWalletDescriptor { try SignerWalletDescriptor(configured: true, unlocked: unlocked, publicKey: wallet) }
  func prepare(_ request: SignedSignerRequest, now: UInt64) throws -> SignerVerifiedReview {
    guard unlocked else { throw SignerFailure.interactionRequired }
    prepared += 1
    return try SignerVerifiedReview(requestDigest: request.digest, summary: Data("native-verified synthetic operation".utf8))
  }
  func approve(_ request: SignedSignerRequest, now: UInt64) throws -> Data {
    guard unlocked else { throw SignerFailure.interactionRequired }; approved += 1; return Data("one original synthetic proof".utf8)
  }
  func cancelPrepared() {}
  func lock() { unlocked = false }
}
