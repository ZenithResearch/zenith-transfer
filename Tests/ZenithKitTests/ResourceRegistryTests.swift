import XCTest
@testable import ZenithKit

final class ResourceRegistryTests: XCTestCase {
  private func resource(_ origin: String = "https://work.example", name: String = "Work", key: String = "12") throws -> RegisteredResource {
    try RegisteredResource(configuration: WorkAccessConfiguration(name: name,
      receiver: URL(string: origin)!, issuer: "example-issuer", keyID: "example-key",
      publicKey: String(repeating: key, count: 32)))
  }
  private func temporary() -> URL {
    FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
  }
  func testRegistryPersistsMultipleResourcesWithoutGrantOrPrivateFields() throws {
    let root = temporary(); defer { try? FileManager.default.removeItem(at: root) }
    let registry = try ResourceRegistry(directory: root)
    let one = try resource(), two = try resource("https://other.example:8443", name: "Other")
    XCTAssertEqual(try registry.load(), [])
    try registry.save(one, replacing: nil); try registry.save(two, replacing: nil)
    XCTAssertEqual(try ResourceRegistry(directory: root).load(), [two, one])
    XCTAssertEqual(one.inboxURL.absoluteString, "https://work.example/monitor/access/")
    let files = try FileManager.default.contentsOfDirectory(at: root, includingPropertiesForKeys: nil)
    for file in files {
      let data = try Data(contentsOf: file)
      XCTAssertNoThrow(try WorkServerSettings.decode(data))
      XCTAssertEqual((try FileManager.default.attributesOfItem(atPath: file.path)[.posixPermissions] as? NSNumber)?.intValue, 0o600)
    }
  }
  func testStaleIssuerReplacementAndRemovalAreRejectedAcrossInstances() throws {
    let root = temporary(); defer { try? FileManager.default.removeItem(at: root) }
    let first = try ResourceRegistry(directory: root), second = try ResourceRegistry(directory: root)
    let original = try resource(), changed = try resource(name: "New issuer", key: "34")
    try first.save(original, replacing: nil)
    XCTAssertThrowsError(try second.save(changed, replacing: nil))
    try second.save(changed, replacing: original)
    XCTAssertThrowsError(try first.save(original, replacing: original))
    XCTAssertThrowsError(try first.save(nil, replacing: original))
    XCTAssertEqual(try first.load(), [changed])
    try first.save(nil, replacing: changed)
    XCTAssertEqual(try first.load(), [])
    XCTAssertThrowsError(try first.save(try resource("https://different.example"), replacing: original))
  }
  func testMalformedSecretAndLinkRecordsFailClosedWithoutOverwriting() throws {
    let root = temporary(); defer { try? FileManager.default.removeItem(at: root) }
    let registry = try ResourceRegistry(directory: root), original = try resource()
    try registry.save(original, replacing: nil)
    let file = try XCTUnwrap(FileManager.default.contentsOfDirectory(at: root, includingPropertiesForKeys: nil).first)
    var value = try JSONSerialization.jsonObject(with: Data(contentsOf: file)) as! [String: Any]
    value["credential"] = "not-public-settings"
    let malformed = try JSONSerialization.data(withJSONObject: value)
    try malformed.write(to: file)
    XCTAssertThrowsError(try registry.load())
    XCTAssertThrowsError(try registry.save(original, replacing: original))
    XCTAssertEqual(try Data(contentsOf: file), malformed)
    try FileManager.default.removeItem(at: file)
    let target = root.appendingPathComponent("original.bin")
    try JSONEncoder().encode(original.configuration).write(to: target)
    try FileManager.default.createSymbolicLink(at: file, withDestinationURL: target)
    XCTAssertThrowsError(try registry.load())
    XCTAssertThrowsError(try registry.save(nil, replacing: original))
    XCTAssertTrue(FileManager.default.fileExists(atPath: target.path))
  }
}
