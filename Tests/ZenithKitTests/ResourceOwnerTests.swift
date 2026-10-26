@testable import CastaliaCustody
#if os(macOS)
import XCTest
@testable import ZenithKit

final class ResourceOwnerTests: XCTestCase {
  private func fixture() throws -> [String: Any] {
    let url = try XCTUnwrap(Bundle.module.url(forResource: "first-owner-bootstrap.vector", withExtension: "json"))
    return try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
  }
  private func encoded(_ value: Any) throws -> Data { try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys, .withoutEscapingSlashes]) }
  func testPackagedCoreSignsOwnerOnceAndLockInvalidatesReview() async throws {
    let directory=FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at:directory) }
    let repository=try WalletRepository(directory:directory)
    let wallet=try await repository.create(password:"synthetic local owner password")
    let backup=try await repository.exportRecovery(password:"synthetic backup password")
    _ = try await repository.verifyBackup(file:backup,password:"synthetic backup password")
    let state=try await repository.state()
    XCTAssertEqual(state.resourceOwnerProtocol,"zenith.resource-owner.v1")
    XCTAssertFalse(state.membershipActive)
    let vector=try fixture(), binding=try JSONDecoder().decode(ResourceOwnerBinding.self,from:encoded(vector["binding"]!))
    var raw=(vector["proof"] as! [String:Any])["challenge"] as! [String:Any]
    var grant=raw["admin_grant"] as! [String:Any]
    grant["holder_public_key"]=try XCTUnwrap(wallet.publicKey);raw["admin_grant"]=grant
    let now=UInt64(Date().timeIntervalSince1970)
    raw["issued_at"]=now;raw["expires_at"]=now+120
    let challenge=try ResourceOwnerChallenge.decode(encoded(raw),binding:binding,now:now)
    let consent=try await repository.prepareResourceOwner(challenge.encoded(),binding:binding,now:now)
    let proof=try await repository.approveResourceOwner(consent,now:now+1)
    try challenge.validateProof(proof)
    do { _ = try await repository.approveResourceOwner(consent,now:now+2);XCTFail("Owner signing token must be one shot") } catch { }
    let next=try await repository.prepareResourceOwner(challenge.encoded(),binding:binding,now:now+2)
    await repository.lock()
    _ = try await repository.unlock(password:"synthetic local owner password")
    do { _ = try await repository.approveResourceOwner(next,now:now+3);XCTFail("Lock must invalidate owner review") } catch { }
  }
  func testSharedPythonRustProofAndExactSelectedBinding() throws {
    let vector = try fixture(), proof = try XCTUnwrap(vector["proof"] as? [String: Any])
    let binding = try JSONDecoder().decode(ResourceOwnerBinding.self, from: encoded(vector["binding"]!))
    let c = try ResourceOwnerChallenge.decode(encoded(proof["challenge"]!), binding: binding, now: 101)
    XCTAssertEqual(c.binding.endpoint, "http://127.0.0.1:8080")
    XCTAssertEqual(c.adminGrant.operations, ["access.inbox", "access.review", "access.decide", "access.status"])
    XCTAssertFalse(c.adminGrant.onwardDelegation)
    try c.validateProof(encoded(proof))
    var changed = proof
    changed["signature"] = String(repeating: "0", count: 128)
    XCTAssertThrowsError(try c.validateProof(encoded(changed)))
  }
  func testTargetAuthorityAndExpiryMutationsAreRejected() throws {
    let vector = try fixture(), proof = try XCTUnwrap(vector["proof"] as? [String: Any])
    let binding = try JSONDecoder().decode(ResourceOwnerBinding.self, from: encoded(vector["binding"]!))
    let original = try XCTUnwrap(proof["challenge"] as? [String: Any])
    for now in [UInt64(99), 220, 9_007_199_254_740_992] {
      XCTAssertThrowsError(try ResourceOwnerChallenge.decode(encoded(original), binding: binding, now: now))
    }
    var changed = original, target = try XCTUnwrap(original["binding"] as? [String: Any])
    target["endpoint"] = "http://127.0.0.1:8181"; changed["binding"] = target
    XCTAssertThrowsError(try ResourceOwnerChallenge.decode(encoded(changed), binding: binding, now: 101))
    let mutations: [(String, Any)] = [("onward_delegation", true), ("operations", ["work.patch"]), ("extra_authority", true)]
    for (field, value) in mutations {
      changed = original; var grant = try XCTUnwrap(original["admin_grant"] as? [String: Any])
      grant[field] = value; changed["admin_grant"] = grant
      XCTAssertThrowsError(try ResourceOwnerChallenge.decode(encoded(changed), binding: binding, now: 101))
    }
    let raw = try XCTUnwrap(String(data: encoded(original), encoding: .utf8))
    XCTAssertThrowsError(try ResourceOwnerChallenge.decode(Data(raw.replacingOccurrences(of: "\"issued_at\":100", with: "\"issued_at\":100,\"issued_at\":101").utf8), binding: binding, now: 101))
    XCTAssertThrowsError(try ResourceOwnerChallenge.decode(Data(raw.replacingOccurrences(of: "\"issued_at\":100", with: "\"issued_at\":100.0").utf8), binding: binding, now: 101))
  }
  func testNativeReviewCannotChangeTheClaim() throws {
    let vector = try fixture(), proof = try XCTUnwrap(vector["proof"] as? [String: Any])
    let binding = try JSONDecoder().decode(ResourceOwnerBinding.self, from: encoded(vector["binding"]!))
    let c = try ResourceOwnerChallenge.decode(encoded(proof["challenge"]!), binding: binding, now: 101)
    var summary: [String: Any] = ["kind":"first_resource_administrator", "native_protocol":"zenith.resource-owner.v1", "binding":vector["binding"]!, "admin_grant":(proof["challenge"] as! [String:Any])["admin_grant"]!, "claim_id":c.claimID, "expires_at":c.expiresAt, "setup_authorization_consumed_on_activation":true]
    let review = try ResourceOwnerConsent.decode(encoded(["token":String(repeating:"f",count:32), "summary":summary]), challenge: c, lifecycle: 7)
    XCTAssertEqual(review.lifecycle, 7)
    summary["setup_authorization_consumed_on_activation"] = false
    XCTAssertThrowsError(try ResourceOwnerConsent.decode(encoded(["token":String(repeating:"f",count:32), "summary":summary]), challenge: c, lifecycle: 7))
  }
  func testLegacyCoreMetadataDoesNotAdvertiseOwnerSigning() throws {
    let state = try JSONDecoder().decode(WalletState.self, from: Data(#"{"configured":false,"unlocked":false,"revision":0,"public_key":null,"backup_verified":false,"membership_active":false}"#.utf8))
    XCTAssertNil(state.resourceOwnerProtocol)
  }
  func testInsecureOrNonCanonicalBindingsAreRejected() throws {
    let vector = try fixture()
    var raw = try XCTUnwrap(vector["binding"] as? [String: Any])
    for address in ["http://192.168.50.10:8080", "https://user:password@graph.example", "https://graph.example/path", "https://graph.example?x=1", "https://graph.example:0", "https://graph.example:443", "https://Graph.example", "https://graph example"] {
      raw["endpoint"] = address
      let binding = try JSONDecoder().decode(ResourceOwnerBinding.self, from: encoded(raw))
      XCTAssertThrowsError(try binding.validate(), address)
    }
  }
}
#endif
