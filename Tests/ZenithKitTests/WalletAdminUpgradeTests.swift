#if os(macOS)
import XCTest
@testable import ZenithKit

final class WalletAdminUpgradeTests: XCTestCase {
  private let identity = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
  private func resource(_ endpoint: String = "http://127.0.0.1:8080") throws -> LocalResource {
    try LocalResource.decode(JSONSerialization.data(withJSONObject: ["schema":"zenith.local-resource.v1", "resource_id":identity, "kind":"devgraph", "name":"My actual graph", "endpoint":endpoint, "connection":NSNull(), "updated_at":1]))
  }
  func testUpgradeKeepsSelectedGraphAndMakesAnExplicitLocalAdminConnection() throws {
    let selected = try resource("http://127.0.0.1:8181")
    let target = OwnerRegistrationTarget(resource:selected)
    let data = try JSONSerialization.data(withJSONObject:["schema":"devgraph.wallet-admin-upgrade-proposal.v1", "resource_id":identity, "source_endpoint":selected.endpoint, "wallet_endpoint":"https://127.0.0.1:19231", "local_only":true, "authority_changed":false])
    let proposal = try WalletAdminUpgradeProposal.decode(data,target:target)
    let inspection = OwnerSetupInspection(resource:selected,registrationSHA256:String(repeating:"a",count:64),configurationSHA256:String(repeating:"b",count:64),healthy:true)
    let plan = try OwnerSetupPlan.walletAdminUpgrade(resource:selected,inspection:inspection,ownerPublicKey:String(repeating:"c",count:64),proposal:proposal,now:100)
    XCTAssertEqual(plan.schema,"zenith.devgraph-owner-setup.v3")
    XCTAssertEqual(plan.localEndpoint,selected.endpoint)
    XCTAssertEqual(plan.walletEndpoint,"https://127.0.0.1:19231")
    XCTAssertEqual(plan.resourceID,selected.id)
    XCTAssertNil(plan.notAfter)
    XCTAssertEqual(plan.writeOperations,OwnerPermissionPreset.allOperations)
    try target.check(plan)
    XCTAssertEqual(try OwnerSetupPlan.decode(plan.encoded()),plan)
    XCTAssertThrowsError(try OwnerRegistrationTarget(resource:resource()).check(plan))
  }
  func testProposalCannotSubstituteAnotherGraphOrExposeTheNetwork() throws {
    let target = OwnerRegistrationTarget(resource:try resource())
    var raw: [String:Any] = ["schema":"devgraph.wallet-admin-upgrade-proposal.v1", "resource_id":identity, "source_endpoint":target.endpoint, "wallet_endpoint":"https://127.0.0.1:19231", "local_only":true, "authority_changed":false]
    for field in ["resource_id","source_endpoint","wallet_endpoint","local_only","authority_changed"] {
      var bad=raw
      bad[field] = ["resource_id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "source_endpoint":"http://127.0.0.1:8081", "wallet_endpoint":"https://192.168.50.10:19231", "local_only":false,"authority_changed":true][field]!
      XCTAssertThrowsError(try WalletAdminUpgradeProposal.decode(JSONSerialization.data(withJSONObject:bad),target:target))
    }
    raw["extra_authority"]=true
    XCTAssertThrowsError(try WalletAdminUpgradeProposal.decode(JSONSerialization.data(withJSONObject:raw),target:target))
  }
  func testLocalPinIsMandatoryAndCannotBeUsedForAnotherOrigin() throws {
    let raw: [String:Any] = ["name":"My actual graph", "receiver":"https://127.0.0.1:19231", "issuer":"my-graph", "authority":["issuer":"my-graph","key_id":"my-key","public_key":String(repeating:"a",count:64),"receiver":"https://127.0.0.1:19231","audience":"devgraph"], "network":"local", "tls_certificate_sha256":String(repeating:"b",count:64)]
    let configuration=try WorkServerSettings.decode(JSONSerialization.data(withJSONObject:raw))
    XCTAssertEqual(configuration.network?.rawValue,"local")
    let trust=try LANServerTrust(configuration:configuration)
    XCTAssertTrue(trust.permits(URL(string:"https://127.0.0.1:19231/devgraph/access-operator/v1/challenges")!))
    XCTAssertFalse(trust.permits(URL(string:"https://127.0.0.1:19232")!))
    for receiver in ["https://192.168.50.10:19231","https://localhost:19231"] {
      var bad=raw; var authority=raw["authority"] as! [String:String]
      authority["receiver"]=receiver;bad["authority"]=authority;bad["receiver"]=receiver
      XCTAssertThrowsError(try WorkServerSettings.decode(JSONSerialization.data(withJSONObject:bad)))
    }
    var missing=raw;missing.removeValue(forKey:"tls_certificate_sha256")
    XCTAssertThrowsError(try WorkServerSettings.decode(JSONSerialization.data(withJSONObject:missing)))
  }
}
#endif
