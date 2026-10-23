import XCTest

@testable import ZenithKit

final class StorageTests: XCTestCase {
  func testCompareAndSwapAcrossConnectionsPreservesCommittedData() throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: directory) }
    let a = try SnapshotStore(directory: directory)
    let b = try SnapshotStore(directory: directory)
    XCTAssertNil(try a.read())
    try a.commit(snapshot: "encrypted-one", expectedRevision: 0, revision: 1)
    XCTAssertThrowsError(try b.commit(snapshot: "stale-data", expectedRevision: 0, revision: 1))
    XCTAssertEqual(try b.read()?.snapshot, "encrypted-one")
    try b.commit(snapshot: "encrypted-two", expectedRevision: 1, revision: 2)
    XCTAssertEqual(try a.read()?.revision, 2)
    XCTAssertThrowsError(try a.commit(snapshot: "skipped", expectedRevision: 2, revision: 4))
    XCTAssertEqual(try a.read()?.snapshot, "encrypted-two")
  }
}
