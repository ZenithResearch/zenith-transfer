#if os(macOS)
import Foundation
import XCTest
@testable import ZenithKit

final class OwnerSetupTests: XCTestCase {
  private struct Vector: Decodable { let name: String; let accepted: Bool; let raw: String; let digest: String? }
  private func vectors() throws -> [Vector] {
    struct Document: Decodable { let cases: [Vector] }
    return try JSONDecoder().decode(Document.self, from: Data(contentsOf: XCTUnwrap(Bundle.module.url(forResource: "owner-setup-v1", withExtension: "json")))).cases
  }
  private func plan() throws -> OwnerSetupPlan {
    let raw = try XCTUnwrap(vectors().first { $0.name == "global-standing-manager" }).raw
    return try OwnerSetupPlan.decode(Data(raw.utf8))
  }
  func testSharedProducerConsumerVectorsAndCanonicalDigest() throws {
    for vector in try vectors() {
      if vector.accepted {
        let value = try OwnerSetupPlan.decode(Data(vector.raw.utf8))
        XCTAssertNoThrow(try value.validate(), vector.name)
        XCTAssertEqual(value.digest, vector.digest, vector.name)
      } else {
        XCTAssertThrowsError(try { let value = try OwnerSetupPlan.decode(Data(vector.raw.utf8)); try value.validate() }(), vector.name)
      }
    }
  }
  func testSelectingAContainerCoversDescendantsButNotSiblings() throws {
    let a = try OwnerScopeNode(kind: "Arena", resourceID: "area-a", title: "A", path: ["Arena/area-a"])
    let child = try OwnerScopeNode(kind: "Project", resourceID: "project-a", title: "Child", path: ["Arena/area-a", "Initiative/initiative-a", "Project/project-a"])
    let sibling = try OwnerScopeNode(kind: "Arena", resourceID: "area-b", title: "B", path: ["Arena/area-b"])
    XCTAssertEqual(OwnerSetupPlan.normalized([a, child, sibling, a]), [a,sibling])
    XCTAssertEqual(OwnerSetupPlan.normalized([child]), [child])
    XCTAssertThrowsError(try OwnerScopeNode(kind: "Project", resourceID: "project-a", title: "Wrong", path: ["Arena/area-a", "Project/project-a"]))
    XCTAssertThrowsError(try OwnerScopeNode(kind: "Task", resourceID: "task-a", title: "Wrong", path: ["Task/task-a"]))
  }
  func testLocalHTTPSSetupDoesNotExposePrivateAPIOrAcceptForeignURLs() {
    for value in ["https://127.0.0.1:18443", "https://192.168.50.10:18443", "https://10.0.0.7:18443", "https://172.16.0.2:18443"] {
      XCTAssertTrue(OwnerSetupPlan.localWalletAddress(value),value)
    }
    for value in ["http://192.168.50.10:18443", "https://public.example:18443", "https://8.8.8.8:18443", "https://192.168.50.10:8080", "https://127.0.0.1:7687", "https://127.0.0.1:443", "https://127.0.0.1:18443/path", "https://user:password@127.0.0.1:18443", "https://127.0.0.1:18443?token=none"] {
      XCTAssertFalse(OwnerSetupPlan.localWalletAddress(value),value)
    }
  }
  func testSavingReviewedPlanIsPrivateAndVersionCheckedAndCreatesNoConnection() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    let store = try OwnerSetupStore(directory: root)
    let otherInstance = try OwnerSetupStore(directory: root)
    let value = try plan()
    XCTAssertNil(try store.load(resourceID: value.resourceID))
    try store.save(value,replacing:nil)
    XCTAssertEqual(try otherInstance.load(resourceID: value.resourceID),value)
    XCTAssertThrowsError(try otherInstance.save(value,replacing:nil))
    XCTAssertEqual(try store.load(resourceID: value.resourceID)?.status,"prepared_not_applied")
    XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: root.path),[value.resourceID+".json"])
    let mode = try XCTUnwrap(FileManager.default.attributesOfItem(atPath: root.appendingPathComponent(value.resourceID+".json").path)[.posixPermissions] as? NSNumber)
    XCTAssertEqual(mode.intValue,0o600)
  }
  func testUnsafeDraftLocationsAndLinkedFilesAreRejected() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: root,withIntermediateDirectories:true,attributes:[.posixPermissions:0o700])
    defer { try? FileManager.default.removeItem(at: root) }
    let target = root.appendingPathComponent("target")
    _ = try OwnerSetupStore(directory: target)
    let link = root.appendingPathComponent("linked")
    try FileManager.default.createSymbolicLink(at: link, withDestinationURL: target)
    XCTAssertThrowsError(try OwnerSetupStore(directory: link))
    let store = try OwnerSetupStore(directory: target), value = try plan()
    let outside = root.appendingPathComponent("outside.json"); try value.encoded().write(to: outside)
    try FileManager.default.setAttributes([.posixPermissions:0o600],ofItemAtPath:outside.path)
    try FileManager.default.createSymbolicLink(at: target.appendingPathComponent(value.resourceID+".json"), withDestinationURL: outside)
    XCTAssertThrowsError(try store.load(resourceID: value.resourceID))
    XCTAssertTrue(FileManager.default.fileExists(atPath: outside.path))
  }
  func testOwnerBootstrapDefaultsToAdministrationWithoutAMemberSelection() throws {
    let resource = LocalResource(resource_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", name: "DevGraph on this Mac",
      endpoint: "http://127.0.0.1:8080", connection: nil, updated_at: 1)
    let inspection = OwnerSetupInspection(resource: resource, registrationSHA256: String(repeating: "a", count: 64),
      configurationSHA256: String(repeating: "b", count: 64), healthy: true)
    let plan = try OwnerSetupPlan.ownerBootstrap(resource: resource, inspection: inspection,
      ownerPublicKey: String(repeating: "c", count: 64), walletEndpoint: "https://192.168.50.10:18443", now: 100)
    XCTAssertEqual(plan.scopeMode, "global"); XCTAssertTrue(plan.paths.isEmpty)
    XCTAssertEqual(plan.writeOperations, OwnerPermissionPreset.allOperations)
    XCTAssertEqual(plan.effectiveReads, CredentialPresetRevision.allReads)
    XCTAssertNil(plan.notAfter); XCTAssertNil(plan.presetSnapshot)
    XCTAssertEqual(plan.status, "prepared_not_applied"); XCTAssertFalse(plan.publishHierarchy)
    XCTAssertEqual(try OwnerSetupPlan.decode(plan.encoded()), plan)
    let stopped = OwnerSetupInspection(resource: resource, registrationSHA256: inspection.registrationSHA256,
      configurationSHA256: inspection.configurationSHA256, healthy: false)
    XCTAssertThrowsError(try OwnerSetupPlan.ownerBootstrap(resource: resource, inspection: stopped,
      ownerPublicKey: plan.ownerPublicKey, walletEndpoint: plan.walletEndpoint, now: 100))
    let other = LocalResource(resource_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", name: resource.name,
      endpoint: resource.endpoint, connection: nil, updated_at: 1)
    XCTAssertThrowsError(try OwnerSetupPlan.ownerBootstrap(resource: other, inspection: inspection,
      ownerPublicKey: plan.ownerPublicKey, walletEndpoint: plan.walletEndpoint, now: 100))
  }
  func testOwnerRegistrationCannotRedirectTheSelectedConnection() throws {
    let resource = LocalResource(resource_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", name: "DevGraph on this Mac",
      endpoint: "http://127.0.0.1:8080", connection: nil, updated_at: 1)
    let target = OwnerRegistrationTarget(resource: resource)
    XCTAssertEqual(target.resourceID, resource.id)
    XCTAssertEqual(target.endpoint, resource.endpoint)
    XCTAssertTrue(target.needsInstalledWalletSupport)
    let inspection = OwnerSetupInspection(resource: resource, registrationSHA256: String(repeating: "a", count: 64),
      configurationSHA256: String(repeating: "b", count: 64), healthy: true)
    for address in ["https://192.168.50.10:18443", "https://192.168.50.10:19443", "https://127.0.0.1:18443"] {
      let separateListener = try OwnerSetupPlan.ownerBootstrap(resource: resource, inspection: inspection,
        ownerPublicKey: String(repeating: "c", count: 64), walletEndpoint: address, now: 100)
      XCTAssertThrowsError(try target.check(separateListener), address)
      // Historical plans remain readable as evidence, without being reused for
      // registration against a different selected connection.
      XCTAssertEqual(try OwnerSetupPlan.decode(separateListener.encoded()), separateListener)
    }
  }
  func testInspectionChecksTheSelectedServerAgainstTheCLIsActualEndpoint() throws {
    for port in [8181, 8282] {
      let endpoint = "http://127.0.0.1:\(port)"
      let row: [String: Any] = ["schema": "zenith.local-resource.v1",
        "resource_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "kind": "devgraph",
        "name": "Selected graph", "endpoint": endpoint, "connection": NSNull(), "updated_at": 1]
      let registration = try JSONSerialization.data(withJSONObject: row)
      let selected = try LocalResource.decode(registration)
      let status = try JSONSerialization.data(withJSONObject: ["healthy": true, "api": ["api": ["base_url": endpoint]]])
      XCTAssertEqual(try OwnerSetupInspector.verifiedInspection(selected, registration: registration,
        configuration: Data("{}".utf8), status: status).resource.endpoint, endpoint)
      let wrong = try JSONSerialization.data(withJSONObject: ["healthy": true, "api": ["api": ["base_url": "http://127.0.0.1:8080"]]])
      XCTAssertThrowsError(try OwnerSetupInspector.verifiedInspection(selected, registration: registration,
        configuration: Data("{}".utf8), status: wrong))
    }
  }
  func testOptionalReadOnlyInstalledDiscovery() async throws {
    guard ProcessInfo.processInfo.environment["ZENITH_OWNER_SETUP_READONLY_SMOKE"] == "1" else { throw XCTSkip("explicit read-only installed DevGraph check") }
    let scan = LocalResourceDiscovery.scan()
    let local = try XCTUnwrap(scan.resources.first { $0.endpoint == "http://127.0.0.1:8080" })
    let service = OwnerSetupInspector()
    let value = try await service.inspect(local)
    XCTAssertTrue(value.healthy); XCTAssertEqual(value.resource.id,local.id)
    let page = try await service.page(parent:nil)
    XCTAssertFalse(page.nodes.isEmpty)
    XCTAssertTrue(page.nodes.allSatisfy { $0.kind == "Arena" })
    if let root = page.nodes.first {
      let children = try await service.page(parent:root)
      XCTAssertTrue(children.nodes.allSatisfy { $0.path.first == root.id && $0.kind == "Initiative" })
    }
  }
}
#endif
