#if os(macOS)
import Foundation
import XCTest
@testable import ZenithKit

final class ServicePublicationTests:XCTestCase {
  private func snapshot(_ config:String="{}",dns:String="host.example.ts.net.") throws -> PublicationSnapshot {
    let status=try JSONSerialization.data(withJSONObject:["BackendState":"Running","Self":["Online":true,"DNSName":dns]])
    return try PublicationSnapshot.decode(status:status,serve:Data(config.utf8))
  }
  private func service(_ id:String="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",endpoint:String="https://127.0.0.1:20643",privateAPI:Bool=false) throws -> LocalService {
    let configuration=try WorkAccessConfiguration(name:"Actual graph",receiver:URL(string:endpoint)!,issuer:"issuer",keyID:"key",publicKey:String(repeating:"12",count:32),network:.local,tlsCertificateSHA256:String(repeating:"34",count:32))
    return LocalService(instance_id:id,resource_id:"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",interface:privateAPI ? .privateAPI:.walletAPI,name:"Actual graph",endpoint:endpoint,connection:privateAPI ? nil:configuration,updated_at:1)
  }
  func testPrivateAndPublicAreIndependentAndUseDistinctPorts() throws {
    let s=try snapshot(),local=try service()
    let both=try ServicePublicationReview.prepare(service:local,snapshot:s,tailnet:true,privatePort:10444,funnel:true,publicPort:443)
    XCTAssertEqual(both.tailnetURL,"https://host.example.ts.net:10444")
    XCTAssertEqual(both.funnelURL,"https://host.example.ts.net:443")
    XCTAssertFalse(both.authorityChanged)
    XCTAssertFalse(both.blockers.isEmpty,"No owner configuration adapter is implied by discovery")
    for (tailnet,funnel) in [(true,false),(false,true)] {
      let r=try ServicePublicationReview.prepare(service:local,snapshot:s,tailnet:tailnet,privatePort:10444,funnel:funnel,publicPort:443)
      XCTAssertEqual(r.tailnetURL != nil,tailnet);XCTAssertEqual(r.funnelURL != nil,funnel)
    }
    XCTAssertThrowsError(try ServicePublicationReview.prepare(service:local,snapshot:s,tailnet:true,privatePort:443,funnel:true,publicPort:443))
    XCTAssertThrowsError(try ServicePublicationReview.prepare(service:local,snapshot:s,tailnet:false,privatePort:10444,funnel:false,publicPort:443))
  }
  func testAnyExistingPathReservesWholePortAndAllPublicPortsCanConflict() throws {
    let s=try snapshot(#"{"TCP":{"443":{"HTTPS":true},"8443":{"HTTPS":true},"10000":{"HTTPS":true}},"Web":{"host.example.ts.net:8443":{"Handlers":{"/private":{"Proxy":"http://127.0.0.1:8008"}}}},"AllowFunnel":{"host.example.ts.net:443":true}}"#)
    XCTAssertEqual(s.occupiedPorts,[443,8443,10000]);XCTAssertEqual(s.publicPorts,[443])
    for port in [443,8443,10000] {
      let r=try ServicePublicationReview.prepare(service:service(),snapshot:s,tailnet:false,privatePort:10444,funnel:true,publicPort:port)
      XCTAssertTrue(r.blockers.contains(where:{$0.contains("already in use")}))
    }
  }
  func testChangedConfigAndDifferentServicesHaveDifferentReviewBindings() throws {
    let a=try snapshot(),b=try snapshot(#"{"TCP":{"443":{"HTTPS":true}}}"#)
    XCTAssertNotEqual(a.revision,b.revision)
    let one=try ServicePublicationReview.prepare(service:service(),snapshot:a,tailnet:true,privatePort:10444,funnel:false,publicPort:443)
    let two=try ServicePublicationReview.prepare(service:service("cccccccc-cccc-4ccc-8ccc-cccccccccccc"),snapshot:a,tailnet:true,privatePort:10444,funnel:false,publicPort:443)
    XCTAssertNotEqual(one.serviceSHA256,two.serviceSHA256)
    XCTAssertEqual(try JSONDecoder().decode(ServicePublicationReview.self,from:JSONEncoder().encode(one)),one)
  }
  func testMalformedSnapshotOrUntrustedHostRejected() throws {
    XCTAssertThrowsError(try snapshot(dns:"host.evil.test"))
    XCTAssertThrowsError(try snapshot(dns:"host..ts.net"))
    XCTAssertThrowsError(try snapshot(#"{"TCP":{"443":{},"443":{}}}"#))
    XCTAssertThrowsError(try snapshot(#"{"AllowFunnel":{"other.example.ts.net:443":true}}"#))
    XCTAssertThrowsError(try snapshot(#"{"TCP":{"0443":{}}}"#))
    XCTAssertThrowsError(try snapshot(#"{"TCP":[]}"#))
    XCTAssertThrowsError(try PublicationSnapshot.decode(status:Data(repeating:65,count:1_048_577),serve:Data("{}".utf8)))
  }
  func testRemoteTargetAndUnsupportedPortsRejectedBeforeProposal() throws {
    var remote=try service();remote=LocalService(instance_id:remote.id,resource_id:remote.resource_id,interface:remote.interface,name:remote.name,endpoint:"https://other-host.example:20643",connection:remote.connection,updated_at:1)
    XCTAssertThrowsError(try ServicePublicationReview.prepare(service:remote,snapshot:snapshot(),tailnet:true,privatePort:10444,funnel:false,publicPort:443))
    XCTAssertThrowsError(try ServicePublicationReview.prepare(service:service(),snapshot:snapshot(),tailnet:true,privatePort:65536,funnel:false,publicPort:443))
    XCTAssertThrowsError(try ServicePublicationReview.prepare(service:service(),snapshot:snapshot(),tailnet:false,privatePort:10444,funnel:true,publicPort:9443))
  }
  func testPrivateAPIIsNeverImplicitlyPublicSafe() throws {
    let r=try ServicePublicationReview.prepare(service:service(privateAPI:true),snapshot:snapshot(),tailnet:true,privatePort:10444,funnel:true,publicPort:443)
    XCTAssertTrue(r.blockers.contains(where:{$0.contains("private API")}))
  }
  func testGraphicalAppAlwaysInvokesTailscaleInCLIMode() {
    let inherited = ["HOME":"/fixture/user", "PATH":"/usr/bin:/bin", "TAILSCALE_BE_CLI":"0"]
    let command = TailscalePublicationInspector.commandEnvironment(inherited)
    XCTAssertEqual(command["TAILSCALE_BE_CLI"], "1")
    XCTAssertEqual(command["HOME"], inherited["HOME"])
    XCTAssertEqual(command["PATH"], inherited["PATH"])
    XCTAssertNil(command["TERM"], "CLI mode must not require a simulated terminal")
    XCTAssertEqual(inherited["TAILSCALE_BE_CLI"], "0", "Only the child environment changes")
  }
  func testInstalledReadOnlyInspectionWhenRequested() async throws {
    guard ProcessInfo.processInfo.environment["TRANSFER_TAILSCALE_INSPECT"] == "1" else {
      throw XCTSkip("No installed Tailscale inspection requested")
    }
    let s=try await TailscalePublicationInspector.inspect()
    XCTAssertTrue(s.dnsName.hasSuffix(".ts.net"))
    XCTAssertEqual(s.revision.count,64)
    XCTAssertTrue(s.publicPorts.isSubset(of:s.occupiedPorts))
  }
}
#endif
