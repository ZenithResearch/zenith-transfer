#if os(macOS)
import Foundation
import XCTest
@testable import ZenithKit

final class LocalServiceDiscoveryTests: XCTestCase {
  private struct Vector: Decodable { let name:String;let accepted:Bool;let raw:String }
  private func vectors() throws -> [Vector] {
    struct Document:Decodable { let cases:[Vector] }
    let url=try XCTUnwrap(Bundle.module.url(forResource:"zenith-local-service-v1",withExtension:"json"))
    return try JSONDecoder().decode(Document.self,from:Data(contentsOf:url)).cases
  }
  private func service(_ name:String="wallet-one") throws -> LocalService {
    try LocalService.decode(Data(try XCTUnwrap(vectors().first { $0.name==name }).raw.utf8))
  }
  func testSharedVectorsAndStableDistinctInstances() throws {
    for vector in try vectors() {
      if vector.accepted { XCTAssertNoThrow(try LocalService.decode(Data(vector.raw.utf8)),vector.name) }
      else { XCTAssertThrowsError(try LocalService.decode(Data(vector.raw.utf8)),vector.name) }
    }
    let a=try service("private"),b=try service(),c=try service("wallet-two")
    XCTAssertEqual(a.resource_id,b.resource_id);XCTAssertEqual(b.resource_id,c.resource_id)
    XCTAssertEqual(Set([a.id,b.id,c.id]).count,3)
  }
  func testRegistryRetainsEveryInterfaceAndRejectsLinkedOrUnsafeRecords() throws {
    let home=FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at:home) }
    XCTAssertTrue(LocalServiceDiscovery.scan(home:home).services.isEmpty)
    let directory=LocalServiceDiscovery.directory(home:home)
    try FileManager.default.createDirectory(at:directory,withIntermediateDirectories:true,attributes:[.posixPermissions:0o700])
    // Intermediate paths also need private permissions.
    for relative in [".zenith",".zenith/services",".zenith/services/v1"] {
      try FileManager.default.setAttributes([.posixPermissions:0o700],ofItemAtPath:home.appendingPathComponent(relative).path)
    }
    for vector in try vectors().filter({ $0.accepted }) {
      let value=try LocalService.decode(Data(vector.raw.utf8)),file=directory.appendingPathComponent(value.id+".json")
      try Data(vector.raw.utf8).write(to:file);try FileManager.default.setAttributes([.posixPermissions:0o600],ofItemAtPath:file.path)
    }
    XCTAssertEqual(LocalServiceDiscovery.scan(home:home).services.count,3)
    let value=try service(),file=directory.appendingPathComponent(value.id+".json")
    let outside=home.appendingPathComponent("outside.json");try Data(contentsOf:file).write(to:outside)
    try FileManager.default.removeItem(at:file);try FileManager.default.createSymbolicLink(at:file,withDestinationURL:outside)
    let after=LocalServiceDiscovery.scan(home:home)
    XCTAssertEqual(after.services.count,2);XCTAssertEqual(after.rejected,1)
  }
  func testWalletDiscoveryBindsLiveIdentityAndProfileToSelectedInstance() async throws {
    let selected=try service(),other=try service("wallet-two"),config=try XCTUnwrap(selected.connection)
    let health:[String:Any]=["live":true,"mode":"owner-local-wallet-administration","resource_id":selected.resource_id,"instance_id":selected.id]
    let live=try JSONSerialization.data(withJSONObject:health),profile=try JSONEncoder().encode(config)
    let result=await LocalServiceProbe.check(endpoint:selected.endpoint,connection:config,resourceID:selected.resource_id,instanceID:selected.id) { origin,path in
      XCTAssertEqual(origin.absoluteString,selected.endpoint)
      return path == "/live" ? live : profile
    }
    XCTAssertTrue(result.reached);XCTAssertTrue(result.walletAdministration)
    let wrong=await LocalServiceProbe.check(endpoint:other.endpoint,connection:other.connection,resourceID:other.resource_id,instanceID:other.id) { _,path in path == "/live" ? live : profile }
    XCTAssertFalse(wrong.reached);XCTAssertFalse(wrong.walletAdministration)
    let profileDrift=await LocalServiceProbe.check(endpoint:selected.endpoint,connection:config,resourceID:selected.resource_id,instanceID:selected.id) { _,path in path == "/live" ? live : try JSONEncoder().encode(other.connection!) }
    XCTAssertFalse(profileDrift.walletAdministration)
    let offline=await LocalServiceProbe.check(endpoint:selected.endpoint,connection:config) { _,_ in throw URLError(.cannotConnectToHost) }
    XCTAssertFalse(offline.reached)
    let legacy=await LocalServiceProbe.check(endpoint:"http://127.0.0.1:8080",connection:nil) { origin,path in
      XCTAssertEqual(origin.absoluteString,"http://127.0.0.1:8080");XCTAssertEqual(path,"/live")
      return Data(#"{"live":true}"#.utf8)
    }
    XCTAssertTrue(legacy.reached);XCTAssertFalse(legacy.walletAdministration)
  }
  func testReadOnlyListenerCannotMasqueradeAsWalletAdministration() async throws {
    let selected=try service()
    let result=await LocalServiceProbe.check(endpoint:selected.endpoint,connection:selected.connection) { _,path in
      XCTAssertEqual(path,"/live")
      return Data(#"{"live":true,"mode":"lan-read"}"#.utf8)
    }
    XCTAssertTrue(result.reached);XCTAssertFalse(result.walletAdministration)
  }
  func testUnclaimedServiceIsDiscoverableButCannotManageGrants() async throws {
    let selected=try service(),config=try XCTUnwrap(selected.connection)
    let raw=try JSONSerialization.data(withJSONObject:["live":true,"mode":"owner-local-wallet-unclaimed","resource_id":selected.resource_id,"instance_id":selected.id,"owner_registered":false,"administration_enabled":false])
    let profile=try JSONEncoder().encode(config)
    let result=await LocalServiceProbe.check(endpoint:selected.endpoint,connection:config,resourceID:selected.resource_id,instanceID:selected.id) { _,path in path == "/live" ? raw : profile }
    XCTAssertTrue(result.reached);XCTAssertTrue(result.ownerRegistrationRequired)
    XCTAssertFalse(result.walletAdministration)
    XCTAssertEqual(result.label,"Running · Owner registration required")
  }
  func testPrivateAPIProbeSendsOnlyUnauthenticatedFixedMetadataGET() async throws {
    let configuration=URLSessionConfiguration.ephemeral;configuration.protocolClasses=[ServiceMetadataURLProtocol.self]
    let transport=PrivateTransport(configuration:configuration)
    _ = try await transport.publicServiceMetadata(at:URL(string:"http://127.0.0.1:8080")!,path:"/live")
    for path in ["/query","/devgraph/access-operator/v1/actions","/.well-known/devgraph-connection.json"] {
      do { _ = try await transport.publicServiceMetadata(at:URL(string:"http://127.0.0.1:8080")!,path:path);XCTFail("HTTP discovery must never become a general request API") } catch { }
    }
    do { _ = try await transport.publicServiceMetadata(at:URL(string:"http://192.168.50.10:8080")!,path:"/live");XCTFail("No plaintext LAN probe") } catch { }
  }
}

private final class ServiceMetadataURLProtocol:URLProtocol {
  override class func canInit(with request:URLRequest)->Bool { true }
  override class func canonicalRequest(for request:URLRequest)->URLRequest { request }
  override func startLoading() {
    XCTAssertEqual(request.url?.absoluteString,"http://127.0.0.1:8080/live")
    XCTAssertEqual(request.httpMethod,"GET");XCTAssertNil(request.httpBody)
    XCTAssertNil(request.value(forHTTPHeaderField:"Authorization"));XCTAssertNil(request.value(forHTTPHeaderField:"Cookie"))
    let response=HTTPURLResponse(url:request.url!,statusCode:200,httpVersion:"HTTP/1.1",headerFields:["Content-Type":"application/json"])!
    client?.urlProtocol(self,didReceive:response,cacheStoragePolicy:.notAllowed)
    client?.urlProtocol(self,didLoad:Data(#"{"live":true}"#.utf8));client?.urlProtocolDidFinishLoading(self)
  }
  override func stopLoading() {}
}
#endif
