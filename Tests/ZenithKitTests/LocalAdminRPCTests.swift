#if os(macOS)
import Foundation
import XCTest
@testable import ZenithKit

final class LocalAdminRPCTests: XCTestCase {
  private func service() throws -> LocalService {
    struct Vector: Decodable { let name: String; let raw: String }
    struct Vectors: Decodable { let cases: [Vector] }
    let url = try XCTUnwrap(Bundle.module.url(forResource: "zenith-local-service-v1", withExtension: "json"))
    let vector = try XCTUnwrap(JSONDecoder().decode(Vectors.self, from: Data(contentsOf: url)).cases.first { $0.name == "wallet-one" })
    return try LocalService.decode(Data(vector.raw.utf8))
  }
  private func configuration(_ service: LocalService) throws -> [String:Any] {
    ["schema":"secs.local-admin-config.v1","resource_id":service.resource_id,"instance_id":service.id,
      "receiver":service.endpoint,"issuer":service.connection!.issuer,"profile_sha256":try LocalAdminRPC.profileDigest(service.connection!),
      "rpc_binary_sha256":String(repeating:"a",count:64),"python":"/fixed/python","python_sha256":String(repeating:"b",count:64),
      "source":"/fixed/source","runtime":"/fixed/runtime","data_root":"/fixed/data","name":"Fixture","source_files":[:]]
  }
  func testExactServiceAndProfileBoundWithoutChangingPortableHTTPSSettings() throws {
    let service = try service(), config = try configuration(service)
    let value = try LocalAdminRPC.decode(JSONSerialization.data(withJSONObject: config), service: service, home: FileManager.default.homeDirectoryForCurrentUser)
    XCTAssertEqual(value.instanceID, service.id)
    XCTAssertEqual(value.receiver, service.endpoint)
    for key in ["resource_id","instance_id","receiver","issuer","profile_sha256","rpc_binary_sha256"] {
      var changed = config; changed[key] = "changed"
      XCTAssertThrowsError(try LocalAdminRPC.decode(JSONSerialization.data(withJSONObject: changed), service: service, home: FileManager.default.homeDirectoryForCurrentUser),key)
    }
    var changed = config; changed["credential"] = "forbidden"
    XCTAssertThrowsError(try LocalAdminRPC.decode(JSONSerialization.data(withJSONObject: changed), service: service, home: FileManager.default.homeDirectoryForCurrentUser))
  }
  func testCommandAndOriginalResponseCorrelationAreClosed() throws {
    let service = try service()
    let rpc = try LocalAdminRPC.decode(JSONSerialization.data(withJSONObject: configuration(service)), service: service, home: FileManager.default.homeDirectoryForCurrentUser)
    let id = UUID().uuidString.lowercased()
    let bytes = try rpc.envelope(operation: "inspect", body: Data("{}".utf8), requestID: id)
    let raw = try XCTUnwrap(JSONSerialization.jsonObject(with:bytes) as? [String:Any])
    XCTAssertEqual(raw["instance_id"] as? String,service.id);XCTAssertEqual(raw["request_id"] as? String,id)
    XCTAssertThrowsError(try rpc.envelope(operation:"shell",body:Data("{}".utf8),requestID:id))
    XCTAssertThrowsError(try rpc.envelope(operation:"challenge",body:Data("{\"a\":1,\"a\":2}".utf8),requestID:id))
    var result:[String:Any] = ["schema":"secs.local-admin-response.v1","request_id":id,"resource_id":service.resource_id,
      "instance_id":service.id,"receiver":service.endpoint,"status":200,"body":["safe":true]]
    XCTAssertEqual(try rpc.response(JSONSerialization.data(withJSONObject:result),requestID:id).status,200)
    for key in ["request_id","resource_id","instance_id","receiver"] {
      var altered = result;altered[key]="changed"
      XCTAssertThrowsError(try rpc.response(JSONSerialization.data(withJSONObject:altered),requestID:id),key)
    }
    result["status"]=302
    XCTAssertThrowsError(try rpc.response(JSONSerialization.data(withJSONObject:result),requestID:id))
  }
  func testInstalledLocalRPCWhenExplicitlySelected() async throws {
    guard let instance = ProcessInfo.processInfo.environment["LOCAL_ADMIN_RPC_INSTANCE"] else {
      throw XCTSkip("No explicitly selected installed local RPC service")
    }
    let service = try XCTUnwrap(LocalServiceDiscovery.scan().services.first { $0.id == instance })
    let rpc = try LocalAdminRPC.discover(configuration: try XCTUnwrap(service.connection))
    let result = try await rpc.call(operation: "inspect", body: Data("{}".utf8))
    XCTAssertEqual(result.status, 200)
    let raw = try XCTUnwrap(JSONSerialization.jsonObject(with: result.data) as? [String:Any])
    XCTAssertEqual(raw["transport"] as? String, "local-secs-rpc")
    XCTAssertEqual(raw["owner_registered"] as? Bool, true)
    XCTAssertEqual(raw["https_hosted_by_transfer"] as? Bool, false)
    XCTAssertEqual(raw["service_configuration"] as? Bool, false)
  }
  func testMissingLocalRPCDoesNotBecomeRemoteAdministration() throws {
    let service = try service()
    let home = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    XCTAssertThrowsError(try LocalAdminRPC.discover(configuration:service.connection!,home:home))
  }
}
#endif
