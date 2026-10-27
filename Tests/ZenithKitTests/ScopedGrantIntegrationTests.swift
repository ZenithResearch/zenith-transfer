import CryptoKit
import Foundation
import XCTest
@testable import CastaliaCustody
@testable import ZenithKit

final class ScopedGrantIntegrationTests: XCTestCase {
  private func data(_ value: Any) throws -> Data {
    try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys, .withoutEscapingSlashes])
  }
  func testRealCoreKeepsLegacyGrantAndRoundTripsScopedGrant() async throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    let repository = try WalletRepository(directory: root)
    let password = "disposable scoped grant password"
    let created = try await repository.create(password: password)
    let backup = try await repository.exportRecovery(password: password)
    _ = try await repository.verifyBackup(file: backup, password: password)
    let key = Curve25519.Signing.PrivateKey()
    let pub = key.publicKey.rawRepresentation.map { String(format: "%02x", $0) }.joined()
    for version in ["v1", "v2"] {
      let service = "service:fixture-" + version
      let pin = HolderIssuerPin(issuer: "fixture", keyID: "key", publicKey: pub, service: service)
      var permission: [String: Any] = ["operation": "work.read", "resource": "work", "constraints": [:]]
      if version == "v1" { permission["scope"] = ["mode": "all"] }
      else { permission["roles"] = [["role": "target", "selector": ["schema": "secs.resource-selector.v1", "service": service, "kinds": ["Task"], "selection": ["mode": "all"]]]] }
      let claims: [String: Any] = ["schema": "secs.holder-grant." + version, "grant_id": String(repeating: "11", count: 16), "revision": String(repeating: "22", count: 32), "issuer": "fixture", "key_id": "key", "service": service, "holder_public_key": try XCTUnwrap(created.publicKey), "installation_id": NSNull(), "validity": ["schema": "castalia.grant-validity.v1", "mode": "until_revoked", "not_before": 100], "max_credential_lifetime_seconds": 600, "onward_delegation": false, "permissions": [permission]]
      let signed = Data(("secs.holder-grant." + version + "/signature\0").utf8) + (try data(claims))
      let signature = try key.signature(for: signed).map { String(format: "%02x", $0) }.joined()
      let review = try await repository.reviewHolderGrant(data(["claims": claims, "signature": signature]), pin: pin, now: 101)
      XCTAssertEqual(review.summary.permissions[0].roles != nil, version == "v2")
      try await repository.saveHolderGrant(review, now: 101)
      let credential = try await repository.deriveHolderCredential(service: service, permissions: nil, expires: 200, now: 102)
      let proof = try await repository.presentHolderCredential(service: service, credential: credential, call: data(["operation": "work.read", "resource": "work", "parameters": [:]]), now: 103)
      let envelope = try JSONSerialization.jsonObject(with: proof) as! [String: Any]
      XCTAssertEqual((envelope["proof"] as! [String: Any])["schema"] as? String, "secs.holder-presentation." + version)
    }
    let encrypted = try await repository.exportHolderGrantBackup()
    XCTAssertFalse(String(decoding: encrypted, as: UTF8.self).contains("service:fixture"))
    await repository.lock()
    _ = try await repository.unlock(password: password)
    let summaries = try await repository.holderGrantSummaries()
    XCTAssertEqual(summaries.count, 2)
    let preview = try await repository.prepareHolderGrantBackup(encrypted)
    _ = try await repository.commit(preview)
  }
}
