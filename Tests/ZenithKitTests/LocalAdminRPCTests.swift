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
  func testHierarchicalReviewAndProofFitTheNativeRPCDepthBudget() throws {
    let service = try service()
    let rpc = try LocalAdminRPC.decode(JSONSerialization.data(withJSONObject: configuration(service)), service: service,
      home: FileManager.default.homeDirectoryForCurrentUser)
    let path: [String: Any] = ["schema": "devgraph.resource-path.v1", "path": ["Arena/fixture"]]
    let grant: [String: Any] = ["schema": "devgraph.path-read-grant.v1", "scope": "devgraph.work.read",
      "operations": ["list", "get"], "relationship_types": [], "work_kinds": ["Task"],
      "include_archived": false, "resource_paths": [path]]
    let draft: [String: Any] = ["schema": "devgraph.access-draft.v5", "issuer": service.connection!.issuer,
      "receiver": service.endpoint, "read_grants": [grant], "lifetime_seconds": 300,
      "validity": ["schema": "castalia.grant-validity.v1", "mode": "until_revoked", "not_before": 1]]
    let action: [String: Any] = ["schema": "devgraph.access-operator-action.v6", "action": "review",
      "action_id": String(repeating: "a", count: 32), "selection": ["read": draft]]
    let request: [String: Any] = ["subject_public_key": String(repeating: "b", count: 64),
      "installation_id": String(repeating: "c", count: 32), "action": action]
    let proof: [String: Any] = ["challenge": ["details": ["action": action]], "signature": "synthetic-unused"]
    for (operation, body) in [("challenge", request), ("execute", proof)] {
      let encoded = try JSONSerialization.data(withJSONObject: body)
      XCTAssertNoThrow(try rpc.envelope(operation: operation, body: encoded, requestID: UUID().uuidString.lowercased()), operation)
    }
    var tooDeep: Any = "leaf"
    for _ in 0..<17 { tooDeep = ["child": tooDeep] }
    XCTAssertThrowsError(try rpc.envelope(operation: "challenge",
      body: JSONSerialization.data(withJSONObject: tooDeep), requestID: UUID().uuidString.lowercased()))
    XCTAssertThrowsError(try rpc.envelope(operation: "challenge",
      body: JSONSerialization.data(withJSONObject: ["text": String(repeating: "a", count: 524_288)]),
      requestID: UUID().uuidString.lowercased()))
  }
  func testLargeOperatorEnvelopeFitsWithoutWeakeningTheOverallBound() throws {
    let service = try service()
    let rpc = try LocalAdminRPC.decode(JSONSerialization.data(withJSONObject: configuration(service)), service: service,
      home: FileManager.default.homeDirectoryForCurrentUser)
    let body = try JSONSerialization.data(withJSONObject: ["challenge": ["details": ["selection": String(repeating: "s", count: 131_072)]]])
    XCTAssertGreaterThan(body.count, 65_536)
    let encoded = try rpc.envelope(operation: "execute", body: body, requestID: UUID().uuidString.lowercased())
    let value = try XCTUnwrap(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
    XCTAssertEqual(try JSONSerialization.data(withJSONObject: value["body"]!, options: [.sortedKeys]),
      try JSONSerialization.data(withJSONObject: JSONSerialization.jsonObject(with: body), options: [.sortedKeys]))
  }
  private func secondary(_ network: WorkNetwork?, endpoint: String) throws -> LocalService {
    let original = try service()
    let profile = try WorkAccessConfiguration(name: "Fixture endpoint", receiver: XCTUnwrap(URL(string: endpoint)),
      issuer: "fixture-secondary", keyID: "fixture-read", publicKey: String(repeating: "12", count: 32), network: network,
      tlsCertificateSHA256: network == .lan ? String(repeating: "34", count: 32) : nil)
    return LocalService(instance_id: try LocalService.instanceID(resourceID: original.resource_id, interface: .walletAPI, endpoint: endpoint),
      resource_id: original.resource_id, interface: .walletAPI, name: profile.name, endpoint: endpoint, connection: profile, updated_at: 1)
  }
  private func v3(_ service: LocalService) throws -> [String: Any] {
    var raw = try configuration(service)
    raw["schema"] = "secs.local-admin-config.v3"
    raw["source_files"] = ["devgraph/ops/local_admin_rpc.py": String(repeating: "c", count: 64)]
    return raw
  }
  func testV3RegisteredEndpointIsIndependentOfNetworkAndLegacyContractsStayRestricted() throws {
    let cases: [(WorkNetwork?, String)] = [
      (.tailscale, "https://graph.example.ts.net:9443"),
      (.lan, "https://192.168.50.10:19443"),
      (nil, "https://graph.example")
    ]
    for (network, endpoint) in cases {
      let selected = try secondary(network, endpoint: endpoint)
      let config = try v3(selected)
      let rpc = try LocalAdminRPC.decode(JSONSerialization.data(withJSONObject: config), service: selected, home: FileManager.default.homeDirectoryForCurrentUser)
      XCTAssertEqual(rpc.receiver, endpoint)
      XCTAssertEqual(rpc.instanceID, selected.id)
      XCTAssertEqual(selected.connection?.network, network, "RPC must not relabel the HTTPS profile")
      var legacy = config; legacy["schema"] = "secs.local-admin-config.v1"
      XCTAssertThrowsError(try LocalAdminRPC.decode(JSONSerialization.data(withJSONObject: legacy), service: selected, home: FileManager.default.homeDirectoryForCurrentUser))
      legacy["schema"] = "secs.local-admin-config.v2"
      if network == .lan {
        XCTAssertNoThrow(try LocalAdminRPC.decode(JSONSerialization.data(withJSONObject: legacy), service: selected, home: FileManager.default.homeDirectoryForCurrentUser))
      } else {
        XCTAssertThrowsError(try LocalAdminRPC.decode(JSONSerialization.data(withJSONObject: legacy), service: selected, home: FileManager.default.homeDirectoryForCurrentUser))
      }
      for field in ["resource_id", "instance_id", "receiver", "issuer", "profile_sha256"] {
        var changed = config; changed[field] = "another-binding"
        XCTAssertThrowsError(try LocalAdminRPC.decode(JSONSerialization.data(withJSONObject: changed), service: selected, home: FileManager.default.homeDirectoryForCurrentUser))
      }
      for manifest in [[:], ["../local_admin_rpc.py": String(repeating: "c", count: 64)],
        ["devgraph/ops/local_admin_rpc.py": "bad-hash"]] {
        var changed = config; changed["source_files"] = manifest
        XCTAssertThrowsError(try LocalAdminRPC.decode(JSONSerialization.data(withJSONObject: changed), service: selected, home: FileManager.default.homeDirectoryForCurrentUser))
      }
    }
  }
  func testCurrentSecondaryRegistryAndPrivateConfigAreRecheckedBeforeDispatch() throws {
    let home = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: home) }
    let selected = try secondary(.tailscale, endpoint: "https://graph.example.ts.net:9443")
    for dir in [home, home.appendingPathComponent(".zenith"), home.appendingPathComponent(".zenith/services"),
      home.appendingPathComponent(".zenith/services/v1"), home.appendingPathComponent(".zenith/rpc"), home.appendingPathComponent(".zenith/rpc/v1")] {
      try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    }
    let registry: [String: Any] = ["schema": "zenith.local-service.v1", "resource_id": selected.resource_id,
      "instance_id": selected.id, "interface": "wallet-api", "kind": "devgraph", "name": selected.name,
      "endpoint": selected.endpoint, "connection": try JSONSerialization.jsonObject(with: JSONEncoder().encode(selected.connection!)), "updated_at": 1]
    let serviceFile = home.appendingPathComponent(".zenith/services/v1/\(selected.id).json")
    let configFile = home.appendingPathComponent(".zenith/rpc/v1/\(selected.id).json")
    func save(_ raw: [String: Any], to file: URL) throws {
      try JSONSerialization.data(withJSONObject: raw).write(to: file, options: .atomic)
      try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
    }
    try save(registry, to: serviceFile)
    var config = try v3(selected); try save(config, to: configFile)
    XCTAssertTrue(LocalAdminRPC.hasRegisteredService(configuration: selected.connection!, home: home))
    let rpc = try LocalAdminRPC.discover(configuration: selected.connection!, home: home)
    XCTAssertNoThrow(try rpc.checkCurrentRegistration())
    config["runtime"] = "/fixed/changed-runtime"; try save(config, to: configFile)
    XCTAssertThrowsError(try rpc.checkCurrentRegistration(), "The complete protected config is pinned, not just the portable profile")
    config = try v3(selected); try save(config, to: configFile)
    try FileManager.default.removeItem(at: configFile)
    XCTAssertTrue(LocalAdminRPC.hasRegisteredService(configuration: selected.connection!, home: home), "A missing RPC binding must not turn a locally registered endpoint into remote administration")
    XCTAssertThrowsError(try rpc.checkCurrentRegistration())
    try save(config, to: configFile)
    try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: configFile.path)
    XCTAssertThrowsError(try LocalAdminRPC.discover(configuration: selected.connection!, home: home))
  }
}
#endif
