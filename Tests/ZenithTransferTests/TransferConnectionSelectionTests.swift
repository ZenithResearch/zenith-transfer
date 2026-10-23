#if os(macOS)
import Foundation
import XCTest
@testable import ZenithKit
@testable import ZenithTransfer

final class TransferConnectionSelectionTests: XCTestCase {
  private func saved(_ host: String, key: String = "12") throws -> RegisteredResource {
    try RegisteredResource(configuration: WorkAccessConfiguration(name: host,
      receiver: URL(string: "https://" + host)!, issuer: "issuer-" + host,
      keyID: "key-" + host, publicKey: String(repeating: key, count: 32)))
  }
  func testSeveralLocalAndSavedConnectionsResolveOnlyTheExplicitSelection() throws {
    let a = LocalResource(resource_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", name: "Graph A",
      endpoint: "http://127.0.0.1:8181", connection: nil, updated_at: 1)
    let b = LocalResource(resource_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", name: "Graph B",
      endpoint: "http://127.0.0.1:8282", connection: nil, updated_at: 1)
    let first = try saved("graph-a.example"), second = try saved("graph-b.example", key: "34")
    for local in [a, b] {
      let selection = TransferConnectionSelection.local(local.id)
      XCTAssertEqual(selection.localResource(in: [b, a]), local)
      XCTAssertNil(selection.savedResource(in: [first, second]))
      XCTAssertNil(selection.accessResource(in:[],health:[:]))
    }
    for resource in [first, second] {
      let selection = TransferConnectionSelection.saved(resource.id)
      XCTAssertEqual(selection.savedResource(in: [second, first]), resource)
      XCTAssertNil(selection.localResource(in: [a, b]))
      XCTAssertEqual(TransferConnectionScreen.access(resource).endpoint, resource.id)
    }
    XCTAssertNil(TransferConnectionSelection.local(a.id).localResource(in: [b]))
    XCTAssertNil(TransferConnectionSelection.saved(first.id).savedResource(in: [second]))
    XCTAssertNil(TransferConnectionSelection.local(a.id).localResource(in: [a, a]))
    XCTAssertNil(TransferConnectionSelection.saved(first.id).savedResource(in: [first, first]))
  }
  func testServiceSelectionNeverFallsBackToAnotherInterfaceOrGraph() throws {
    let graph="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    let config=try saved("graph-a.example").configuration
    let one=LocalService(instance_id:try LocalService.instanceID(resourceID:graph,interface:.walletAPI,endpoint:config.origin),resource_id:graph,interface:.walletAPI,name:config.name,endpoint:config.origin,connection:config,updated_at:1)
    let privateAPI=LocalService(instance_id:try LocalService.instanceID(resourceID:graph,interface:.privateAPI,endpoint:"http://127.0.0.1:8080"),resource_id:graph,interface:.privateAPI,name:config.name,endpoint:"http://127.0.0.1:8080",connection:nil,updated_at:1)
    let health=["service:"+one.id:LocalServiceHealth(reached:true,walletAdministration:true),"service:"+privateAPI.id:LocalServiceHealth(reached:true,walletAdministration:false)]
    let selection=TransferConnectionSelection.service(one.id)
    XCTAssertEqual(selection.service(in:[privateAPI,one]),one)
    XCTAssertEqual(selection.accessResource(in:[privateAPI,one],health:health)?.id,one.endpoint)
    XCTAssertNil(selection.accessResource(in:[privateAPI],health:health))
    XCTAssertNil(selection.accessResource(in:[one],health:[:]))
    XCTAssertNil(selection.service(in:[one,one]))
    XCTAssertNil(TransferConnectionSelection.service(privateAPI.id).accessResource(in:[privateAPI,one],health:health))
    XCTAssertNil(TransferConnectionSelection.local(graph).accessResource(in:[one],health:health))
    XCTAssertNil(selection.savedResource(in:[try RegisteredResource(configuration:config)]))
    XCTAssertEqual(TransferConnectionScreen.access(try XCTUnwrap(selection.accessResource(in:[one],health:health))).endpoint,one.endpoint)
  }
  func testSecondScreenCapturesTargetAndPinChangesInvalidateViewIdentity() throws {
    let a = try saved("graph-a.example"), b = try saved("graph-b.example", key: "34")
    let oldScreen = TransferConnectionScreen.access(a)
    let secondScreen = TransferConnectionScreen.access(b)
    XCTAssertNotEqual(oldScreen.id, secondScreen.id)
    XCTAssertEqual(oldScreen.endpoint, a.id)
    XCTAssertEqual(secondScreen.endpoint, b.id)
    let updatedA = try saved("graph-a.example", key: "56")
    XCTAssertEqual(a.id, updatedA.id)
    XCTAssertNotEqual(oldScreen.id, TransferConnectionScreen.access(updatedA).id,
      "A new verification pin must not reuse the old StateObject/client")
    XCTAssertEqual(oldScreen.endpoint, a.id, "A retained screen is not retargeted by refresh or another selection")
  }
}
#endif
