import Foundation
import XCTest
@testable import ZenithKit

final class WalletBackgroundTests:XCTestCase {
  func testBackgroundInvalidatesConsentButRetainsUnlockAndCanSignFreshProofWithoutPassword() async throws {
    let directory=FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at:directory) }
    let repository=try WalletRepository(directory:directory)
    let created=try await repository.create(password:"disposable background wallet password")
    let recovery=try await repository.exportRecovery(password:"disposable background backup password")
    _ = try await repository.verifyBackup(file:recovery,password:"disposable background backup password")
    let identity=try JSONSerialization.jsonObject(with:await repository.graphAccessIdentityV2()) as! [String:String]
    let pin=try WorkAccessConfiguration(name:"Background fixture",receiver:URL(string:"https://work.example")!,issuer:"background-fixture",keyID:"fixture",publicKey:String(repeating:"12",count:32)).authority
    let now=UInt64(Date().timeIntervalSince1970)
    func challenge() throws -> Data {
      try JSONSerialization.data(withJSONObject:["schema":"castalia.access-request-challenge.v1",
        "challenge_id":UUID().uuidString.replacingOccurrences(of:"-",with:"").lowercased(),
        "nonce":String(repeating:"A",count:43),"issuer":pin.issuer,"receiver":pin.receiver,
        "subject_public_key":identity["subject_public_key"]!,"installation_id":identity["installation_id"]!,
        "operation":"access.request","issued_at":now,"expires_at":now+120,
        "details":["action":["action":"submit"]]])
    }
    let oldTicket=repository.lifecycleTicket()
    let old=try await repository.prepareGraphAccessRequestV2(challenge(),pin:pin,now:now)
    let pause=repository.pauseForBackground()
    XCTAssertThrowsError(try repository.checkLifecycle(oldTicket))
    await pause.value
    let retained=try await repository.state()
    XCTAssertTrue(retained.unlocked)
    XCTAssertEqual(retained.publicKey,created.publicKey)
    do {
      _ = try await repository.approveGraphAccessRequestV2(old,now:now,ticket:oldTicket)
      XCTFail("A background-invalidated approval must not sign")
    } catch { }
    // No unlock call or password between backgrounding and this fresh approval.
    let ticket=repository.lifecycleTicket()
    let fresh=try await repository.prepareGraphAccessRequestV2(challenge(),pin:pin,now:now)
    let proof=try await repository.approveGraphAccessRequestV2(fresh,now:now,ticket:ticket)
    let signed=try JSONSerialization.jsonObject(with:proof) as! [String:Any]
    XCTAssertNotNil(signed["signature"])
    await repository.lock()
    let locked=try await repository.state()
    XCTAssertFalse(locked.unlocked)
    let relaunched=try WalletRepository(directory:directory)
    let afterLaunch=try await relaunched.state()
    XCTAssertFalse(afterLaunch.unlocked,"No unlocked state or key persists across process lifetime")
  }
}
