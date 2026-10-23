import XCTest
@testable import ZenithKit

final class WorkServerInboxTests: XCTestCase {
  func testDiscoveryOnlyOffersValidatedPublicProfilesNewestFirst() throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    func profile(_ name: String) throws -> Data {
      try JSONEncoder().encode(WorkAccessConfiguration(name: name, receiver: URL(string: "https://work.example")!,
        issuer: "example", keyID: "test", publicKey: String(repeating: "12", count: 32)))
    }
    let old = directory.appendingPathComponent("old.json")
    let new = directory.appendingPathComponent("new.json")
    try profile("Old").write(to: old)
    try profile("New").write(to: new)
    try FileManager.default.setAttributes([.modificationDate: Date(timeIntervalSince1970: 100)], ofItemAtPath: old.path)
    try Data("{\"password\":\"not-a-profile\"}".utf8).write(to: directory.appendingPathComponent("custody.json"))
    try Data(repeating: 65, count: 16_385).write(to: directory.appendingPathComponent("huge.json"))
    try profile("Hidden").write(to: directory.appendingPathComponent(".hidden.json"))
    try FileManager.default.createSymbolicLink(at: directory.appendingPathComponent("linked.json"), withDestinationURL: old)
    let entries = try WorkServerInbox.profiles(in: directory)
    XCTAssertEqual(entries.map(\.configuration.name), ["New", "Old"])
    XCTAssertEqual(try entries[0].selectedConfiguration().name, "New")
    try profile("Changed").write(to: new)
    XCTAssertThrowsError(try entries[0].selectedConfiguration())
    try FileManager.default.removeItem(at: old)
    XCTAssertThrowsError(try entries[1].selectedConfiguration())
  }
  func testEmptyInboxDoesNotInventServer() throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    XCTAssertTrue(try WorkServerInbox.profiles(in: directory).isEmpty)
  }
}
