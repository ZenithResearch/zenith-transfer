import CastaliaCustody
import CastaliaSignerProtocol
import CryptoKit
import Foundation
import XCTest
import ZenithKit

final class NativeSignerEngineTests: XCTestCase {
  private let client = Curve25519.Signing.PrivateKey()
  private let now: UInt64 = 1_800_000_000
  private let receiver = "https://work.example"
  private var service: SignerService { try! SignerService(issuer: "example-issuer", audience: "devgraph", keyID: "key", publicKey: String(repeating: "12", count: 32)) }
  private func fixture(kind: SignerProofKind = .operatorAccessV1) async throws -> (WalletRepository, NativeSignerEngine, SignedSignerRequest, Data) {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("native-signer-engine-fixture-" + UUID().uuidString)
    addTeardownBlock { try? FileManager.default.removeItem(at: directory) }
    let repository = try WalletRepository(directory: directory)
    _ = try await repository.create(password: "disposable signer fixture password")
    let backup = try await repository.exportRecovery(password: "disposable signer backup password")
    _ = try await repository.verifyBackup(file: backup, password: "disposable signer backup password")
    let identityData = try await repository.graphAccessIdentityV2()
    let identity = try XCTUnwrap(JSONSerialization.jsonObject(with: identityData) as? [String: String])
    let wallet = try XCTUnwrap(identity["subject_public_key"]), installation = try XCTUnwrap(identity["installation_id"])
    let action: [String: Any] = kind == .operatorAccessV1 ? ["action": "approve", "action_id": String(repeating: "aa", count: 16),
      "selection": ["read": ["resources": ["Project/example"], "validity": ["mode": "until_revoked"]]]] :
      ["schema": "devgraph.access-request-action.v1", "action": "submit", "request_id": String(repeating: "ab", count: 16),
        "subject_public_key": wallet, "installation_id": installation, "intent": NSNull()]
    let details: [String: Any] = kind == .operatorAccessV1 ? ["action": action, "policy_revision": 7,
      "policy_digest_sha256": String(repeating: "bb", count: 32)] : action
    let challenge: [String: Any] = ["schema": "castalia.access-request-challenge.v1", "challenge_id": String(repeating: "cc", count: 16),
      "nonce": String(repeating: "A", count: 43), "issuer": service.issuer, "receiver": receiver,
      "subject_public_key": wallet, "installation_id": installation,
      "operation": kind == .operatorAccessV1 ? "access.decide" : "access.request", "issued_at": now, "expires_at": now + 120, "details": details]
    let bytes = try JSONSerialization.data(withJSONObject: challenge, options: [.sortedKeys, .withoutEscapingSlashes])
    let payload = try SignerServiceChallenge(receiver: receiver, challenge: bytes).encoded()
    let request = try SignedSignerRequest(body: SignerRequestBody(clientKey: SignerWire.hex(client.publicKey.rawRepresentation),
      expectedWallet: wallet, issuedAt: now, expiresAt: now + 120, nonce: String(repeating: "d", count: 64),
      operation: .prepareServiceProof, service: service, proofKind: kind, payload: payload), key: client)
    return (repository, NativeSignerEngine(repository: repository), request, bytes)
  }
  func testNativeOperatorConsentTokensStayInsideEngineAndProofRemainsCompatible() async throws {
    let (_, engine, request, original) = try await fixture()
    let review = try await engine.prepare(request, now: now)
    let disclosure = try JSONDecoder().decode(SignerProofDisclosure.self, from: review.summary)
    XCTAssertEqual(disclosure.wallet, request.body.expectedWallet); XCTAssertEqual(disclosure.operation, "access.decide")
    let details = try XCTUnwrap(JSONSerialization.jsonObject(with: disclosure.details) as? [String: Any])
    XCTAssertNotNil(details["action"]); XCTAssertNil(details["token"])
    let proof = try await engine.approve(request, now: now + 1)
    try verify(proof, challenge: original, wallet: XCTUnwrap(request.body.expectedWallet))
    do { _ = try await engine.approve(request, now: now + 2); XCTFail("Must not repeat native approval") } catch {}
  }
  func testNativeGraphRequestUsesOriginalProtocolBytesWithoutCommunityMembership() async throws {
    let (repository, engine, request, original) = try await fixture(kind: .graphAccessRequestV2)
    let state = try await repository.state(); XCTAssertFalse(state.membershipActive)
    let review = try await engine.prepare(request, now: now)
    let disclosure = try JSONDecoder().decode(SignerProofDisclosure.self, from: review.summary)
    XCTAssertEqual(disclosure.details, original)
    let proof = try await engine.approve(request, now: now + 1)
    try verify(proof, challenge: original, wallet: XCTUnwrap(request.body.expectedWallet))
  }
  func testLockCancelsNativeConsentAndNoUnimplementedProofFallbackExists() async throws {
    let (repository, engine, request, _) = try await fixture()
    _ = try await engine.prepare(request, now: now); await engine.lock()
    _ = try await repository.unlock(password: "disposable signer fixture password")
    do { _ = try await engine.approve(request, now: now + 1); XCTFail("Locked native consent must not revive") } catch {}
    let unsupported = try SignedSignerRequest(body: SignerRequestBody(clientKey: request.body.clientKey,
      expectedWallet: request.body.expectedWallet, issuedAt: now, expiresAt: now + 120, nonce: String(repeating: "e", count: 64),
      operation: .prepareServiceProof, service: service, proofKind: .membershipRequestV1, payload: request.body.payload), key: client)
    do { _ = try await engine.prepare(unsupported, now: now + 1); XCTFail("Unsupported proof must not fall back") } catch {}
  }
  private func verify(_ proof: Data, challenge: Data, wallet: String) throws {
    let object = try XCTUnwrap(JSONSerialization.jsonObject(with: proof) as? [String: Any])
    let actual = try JSONSerialization.data(withJSONObject: XCTUnwrap(object["challenge"]), options: [.sortedKeys, .withoutEscapingSlashes])
    XCTAssertEqual(actual, challenge)
    let encoded = try XCTUnwrap(object["signature"] as? String).replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
    let signature = try XCTUnwrap(Data(base64Encoded: encoded + String(repeating: "=", count: (4 - encoded.count % 4) % 4)))
    let key = try Curve25519.Signing.PublicKey(rawRepresentation: XCTUnwrap(SignerWire.bytes(wallet, count: 32)))
    XCTAssertTrue(key.isValidSignature(signature, for: Data("castalia/access-request-approval/v1\0".utf8) + challenge))
  }
}
