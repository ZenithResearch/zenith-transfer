#if os(macOS)
import Foundation
import XCTest
@testable import ZenithKit

final class CredentialPresetTests: XCTestCase {
  func testSharedV2PlansKeepExactRecipesAndGranularReads() throws {
    struct Case: Decodable { let name: String; let accepted: Bool; let raw: String; let digest: String? }
    struct Document: Decodable { let cases: [Case] }
    let file = try XCTUnwrap(Bundle.module.url(forResource: "owner-setup-v2", withExtension: "json"))
    for c in try JSONDecoder().decode(Document.self, from: Data(contentsOf: file)).cases {
      if c.accepted {
        let plan = try OwnerSetupPlan.decode(Data(c.raw.utf8))
        XCTAssertEqual(plan.digest, c.digest, c.name)
        if let snapshot = plan.presetSnapshot {
          XCTAssertEqual(snapshot.writeOperations, plan.writeOperations)
          XCTAssertEqual(snapshot.readOperations, plan.effectiveReads)
        }
      } else { XCTAssertThrowsError(try OwnerSetupPlan.decode(Data(c.raw.utf8)), c.name) }
    }
  }
  private func revision(_ number: UInt64, writes: [String] = ["patch"], archived: Bool = false) throws -> CredentialPresetRevision {
    try CredentialPresetRevision(presetID: "custom-9cf2dc48-a634-4c38-831d-2de8ef92fbb7", revision: number,
      name: "Maintainer", readOperations: ["list", "get"], writeOperations: writes, archived: archived)
  }
  func testPresetEditsRetainHistoryAndRejectStaleWriters() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    let store = try CredentialPresetStore(directory: root), another = try CredentialPresetStore(directory: root)
    let first = try revision(1), second = try revision(2, writes: ["patch", "progress.set"])
    try store.append(first, replacing: nil)
    let pinned = try CredentialPresetRevision.decode(first.encoded())
    try another.append(second, replacing: first)
    XCTAssertThrowsError(try store.append(second, replacing: first))
    XCTAssertEqual(try store.history(first.presetID), [first, second])
    XCTAssertEqual(pinned.writeOperations, ["patch"])
    XCTAssertNotEqual(first.digest, second.digest)
    let archived = try revision(3, archived: true)
    try store.append(archived, replacing: second)
    XCTAssertEqual(try another.latest(), [archived])
    XCTAssertEqual(try store.history(first.presetID).first, first)
    let file = root.appendingPathComponent(first.presetID + ".json")
    XCTAssertEqual((try FileManager.default.attributesOfItem(atPath: file.path)[.posixPermissions] as? NSNumber)?.intValue, 0o600)
    XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: root.path), [first.presetID + ".json"])
  }
  func testWorkReadsCannotEncodeArenaOrOwnerAuthority() throws {
    // Presentation changes must not widen the existing credential contract.
    XCTAssertEqual(WorkReadPermission.allCases.map(\.rawValue), CredentialPresetRevision.allReads)
    for operation in ["arena.list", "arena.get", "read.arenas", "owner", "access.admin"] {
      XCTAssertNil(WorkReadPermission(rawValue: operation))
      XCTAssertThrowsError(try CredentialPresetRevision(presetID: "invalid-reads", revision: 1,
        name: "Unsupported", readOperations: [operation], writeOperations: []))
    }
    let reads = try CredentialPresetRevision(presetID: "work-reader", revision: 1,
      name: "Work reader", readOperations: ["list", "get", "relationships"], writeOperations: [])
    XCTAssertEqual(try CredentialPresetRevision.decode(reads.encoded()).readOperations, CredentialPresetRevision.allReads)
  }
  func testUnsafeStorageAndLinkedHistoryAreRefused() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    let store = try CredentialPresetStore(directory: root), value = try revision(1)
    try store.append(value, replacing: nil)
    let file = root.appendingPathComponent(value.presetID + ".json"), link = root.appendingPathComponent("outside")
    try FileManager.default.moveItem(at: file, to: link)
    try FileManager.default.createSymbolicLink(at: file, withDestinationURL: link)
    XCTAssertThrowsError(try store.history(value.presetID))
    XCTAssertThrowsError(try store.append(try revision(2), replacing: value))
    XCTAssertTrue(FileManager.default.fileExists(atPath: link.path))
    try FileManager.default.setAttributes([.posixPermissions:0o755], ofItemAtPath:root.path)
    XCTAssertThrowsError(try CredentialPresetStore(directory:root))
  }
  func testSeatReferencesAreMetadataAndBuiltinsAreFixed() throws {
    let seat = try PresetSeatAssociation(seatClassIRI: PresetSeatAssociation.sharedSeatClassIRI, seatTypeIRI: "urn:example:Contributor", label: "Contributor")
    let plain = try revision(1)
    let linked = try CredentialPresetRevision(presetID: plain.presetID, revision: 1, name: plain.name,
      readOperations: plain.readOperations, writeOperations: plain.writeOperations, seat: seat)
    XCTAssertEqual(linked.writeOperations, plain.writeOperations)
    XCTAssertNotEqual(linked.digest, plain.digest)
    XCTAssertThrowsError(try PresetSeatAssociation(seatClassIRI:"javascript:alert(1)",seatTypeIRI:"urn:example:Type",label:"Unsafe"))
    XCTAssertThrowsError(try PresetSeatAssociation(seatClassIRI:"urn:other:Seat",seatTypeIRI:"urn:example:Type",label:"Other"))
    XCTAssertThrowsError(try CredentialPresetRevision(presetID:plain.presetID,revision:1,name:String(repeating:"e\u{301}",count:50),readOperations:["get"],writeOperations:[]))
    XCTAssertEqual(CredentialPresetRevision.builtins.map(\.writeOperations), [[], OwnerPermissionPreset.contributor.operations, OwnerPermissionPreset.projectManager.operations])
    let raw = String(decoding: try plain.encoded(), as: UTF8.self)
    XCTAssertThrowsError(try CredentialPresetRevision.decode(Data((String(raw.dropLast()) + ",\"revision\":2}").utf8)))
    XCTAssertThrowsError(try CredentialPresetRevision(presetID:plain.presetID,revision:1,name:"Bad",readOperations:["get"],writeOperations:["access.admin"]))
  }
}
#endif
