import XCTest
import Darwin
@testable import ZenithKit

final class NetworkConnectionFilesTests: XCTestCase {
  let key = "tskey-auth-0123456789ABCDEF-0123456789abcdef0123456789abcdef"
  func testSavedFilesAreReviewedWithoutMutatingConnectionsAndRevalidatedOnUse() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    let directory = try NetworkConnectionFiles.directory(applicationDirectory: root)
    let auth = directory.appendingPathComponent("network.tailscale-key")
    try NetworkConnectionFiles.saveEnrollmentKey(key, to: auth)
    let config = try WorkAccessConfiguration(name: "My graph", receiver: URL(string: "https://graph.example")!, issuer: "example", keyID: "test", publicKey: String(repeating: "12", count: 32))
    let graph = directory.appendingPathComponent("graph.json")
    try NetworkConnectionFiles.saveConfiguration(config, to: graph)
    let entries = try NetworkConnectionFiles.scan(directory)
    XCTAssertEqual(entries.count, 2)
    let network = try XCTUnwrap(entries.first { $0.kind == .tailscale })
    XCTAssertNil(network.configuration)
    XCTAssertEqual(try network.selectedEnrollmentKey(), key)
    XCTAssertThrowsError(try network.selectedConfiguration())
    let service = try XCTUnwrap(entries.first { $0.kind == .devgraph })
    XCTAssertEqual(try service.selectedConfiguration(), config)
    XCTAssertThrowsError(try service.selectedEnrollmentKey())
    try Data((key + "x").utf8).write(to: auth)
    XCTAssertThrowsError(try network.selectedEnrollmentKey())
    XCTAssertThrowsError(try NetworkConnectionFiles.saveEnrollmentKey(key, to: auth))
    XCTAssertEqual((try FileManager.default.attributesOfItem(atPath: graph.path)[.posixPermissions] as? NSNumber)?.intValue, 0o600)
  }
  func testFilesRejectLinksPipesOversizeWrongKindsAndDuplicateFields() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    let directory = try NetworkConnectionFiles.directory(applicationDirectory: root)
    let auth = directory.appendingPathComponent("network.txt")
    try NetworkConnectionFiles.saveEnrollmentKey(key, to: auth)
    let link = directory.appendingPathComponent("linked.txt")
    try FileManager.default.createSymbolicLink(at: link, withDestinationURL: auth)
    XCTAssertThrowsError(try ConnectionFileReview.read(link, as: .tailscale))
    let pipe = directory.appendingPathComponent("pipe.txt"); XCTAssertEqual(mkfifo(pipe.path, 0o600), 0)
    XCTAssertThrowsError(try ConnectionFileReview.read(pipe, as: .tailscale))
    let huge = directory.appendingPathComponent("huge.txt"); try Data(repeating: 65, count: 1025).write(to: huge)
    XCTAssertThrowsError(try ConnectionFileReview.read(huge, as: .tailscale))
    XCTAssertThrowsError(try ConnectionFileReview.read(auth, as: .devgraph))
    let json = directory.appendingPathComponent("duplicate.json")
    try Data(#"{"name":"a","name":"b"}"#.utf8).write(to: json)
    XCTAssertThrowsError(try ConnectionFileReview.read(json, as: .devgraph))
    XCTAssertEqual(try NetworkConnectionFiles.scan(directory).count, 1)
  }
  func testNewUserHasEmptyInboxAndSecretsAreNeverAcceptedAsPublicProfiles() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    let directory = try NetworkConnectionFiles.directory(applicationDirectory: root)
    XCTAssertTrue(try NetworkConnectionFiles.scan(directory).isEmpty)
    let file = directory.appendingPathComponent("not-a-connection.json")
    try Data(#"{"auth_key":"tskey-auth-secret","receiver":"https://graph.example"}"#.utf8).write(to: file)
    XCTAssertTrue(try NetworkConnectionFiles.scan(directory).isEmpty)
    XCTAssertThrowsError(try NetworkConnectionFiles.saveEnrollmentKey("tskey-api-wrong-token", to: directory.appendingPathComponent("api.txt")))
  }
}
