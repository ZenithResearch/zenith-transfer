import CryptoKit
import XCTest
@testable import ZenithKit

final class OperatorTests: XCTestCase {
  func testNativeOperatorDisclosureSignatureAndOneUse() async throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    let repo = try WalletRepository(directory: root)
    _ = try await repo.create(password: "disposable operator password")
    let backup = try await repo.exportRecovery(password: "disposable backup password")
    _ = try await repo.verifyBackup(file: backup, password: "disposable backup password")
    let state = try await repo.state()
    XCTAssertEqual(state.operatorAccessProtocol, "castalia.operator-access.v1")
    let identity = try JSONSerialization.jsonObject(with: await repo.graphAccessIdentityV2()) as! [String: String]
    let pin = try WorkAccessConfiguration(name:"Example", receiver:URL(string:"https://work.example")!,
      issuer:"example-issuer", keyID:"key", publicKey:String(repeating:"12",count:32)).authority
    let now = UInt64(Date().timeIntervalSince1970)
    let details: [String: Any] = ["action":["action":"approve","action_id":String(repeating:"aa",count:16),
      "selection":["read":["resources":["Project/example"],"validity":["mode":"until_revoked"]]]],
      "policy_revision":7,"policy_digest_sha256":String(repeating:"bb",count:32)]
    let challenge: [String: Any] = ["schema":"castalia.access-request-challenge.v1",
      "challenge_id":String(repeating:"cc",count:16),"nonce":String(repeating:"A",count:43),
      "issuer":pin.issuer,"receiver":pin.receiver,"subject_public_key":identity["subject_public_key"]!,
      "installation_id":identity["installation_id"]!,"operation":"access.decide","issued_at":now,"expires_at":now+120,"details":details]
    let encoded = try JSONSerialization.data(withJSONObject:challenge,options:[.sortedKeys,.withoutEscapingSlashes])
    let preview = try await repo.prepareOperatorAccess(encoded,pin:pin,now:now)
    XCTAssertEqual(preview.operation,"access.decide")
    XCTAssertEqual(try JSONSerialization.data(withJSONObject:JSONSerialization.jsonObject(with:preview.details),options:.sortedKeys),
      try JSONSerialization.data(withJSONObject:details,options:.sortedKeys))
    let approved = try JSONSerialization.jsonObject(with: await repo.approveOperatorAccess(preview,now:now+1)) as! [String:Any]
    let signature = approved["signature"] as! String
    let bytes = try XCTUnwrap(Data(base64Encoded:signature.replacingOccurrences(of:"-",with:"+").replacingOccurrences(of:"_",with:"/")+"=="))
    let key = identity["subject_public_key"]!
    let keyData = Data(stride(from:0,to:key.count,by:2).map { offset in
      UInt8(key.dropFirst(offset).prefix(2),radix:16)!
    })
    let owner = try Curve25519.Signing.PublicKey(rawRepresentation:keyData)
    XCTAssertTrue(owner.isValidSignature(bytes,for:Data("castalia/access-request-approval/v1\0".utf8)+encoded))
    do { _ = try await repo.approveOperatorAccess(preview,now:now+2); XCTFail("One use") } catch { }
    let pending = try await repo.prepareOperatorAccess(encoded,pin:pin,now:now+2)
    repo.invalidatePendingWork(); await repo.lock()
    _ = try await repo.unlock(password:"disposable operator password")
    do { _ = try await repo.approveOperatorAccess(pending,now:now+3); XCTFail("Lock invalidates") } catch { }
  }
  func testUnknownJournalSurvivesRestartAndCannotChangeOriginalAction() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at:root) }
    let origin = "https://work.example"
    let journal = try OperatorJournal(directory:root,origin:origin)
    var value: [String:Any] = ["schema":"devgraph.operator-pending.v1","origin":origin,
      "identity":["subject_public_key":String(repeating:"11",count:32),"installation_id":String(repeating:"22",count:16)],
      "action":["schema":"devgraph.access-operator-action.v7","action":"approve","action_id":String(repeating:"33",count:16)],
      "assignment_digest":String(repeating:"44",count:32),"dispatched":false]
    func data(_ v:[String:Any]) throws -> Data { try JSONSerialization.data(withJSONObject:v,options:.sortedKeys) }
    try journal.save(data(value)); value["dispatched"] = true
    let original = try data(value); try journal.save(original)
    let reopened = try OperatorJournal(directory:root,origin:origin)
    XCTAssertEqual(try reopened.load(),original)
    var changed = value; changed["action"] = ["schema":"devgraph.access-operator-action.v7","action":"approve","action_id":String(repeating:"55",count:16)]
    XCTAssertThrowsError(try reopened.save(data(changed)))
    changed=value;changed["dispatched"]=false
    XCTAssertThrowsError(try reopened.save(data(changed)))
    changed=value;changed["signature"]="must-not-persist"
    XCTAssertThrowsError(try reopened.save(data(changed)))
    XCTAssertThrowsError(try reopened.clear(matching:data(changed)))
    XCTAssertEqual(try reopened.load(),original)
    try reopened.clear(matching:original); XCTAssertNil(try reopened.load())
  }
}
