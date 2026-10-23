import XCTest
@testable import ZenithKit

final class WorkServerSettingsTests: XCTestCase {
  private func profile(_ origin: String = "https://devgraph.example") throws -> WorkAccessConfiguration {
    try WorkAccessConfiguration(name: "Example work", receiver: URL(string: origin)!,
      issuer: "example-issuer", keyID: "example-key", publicKey: String(repeating: "12", count: 32))
  }
  func testUserAddressIsBoundedHTTPSOrigin() throws {
    XCTAssertEqual(try WorkServerSettings.address(" https://devgraph.example:443/ ").absoluteString,
      "https://devgraph.example:443")
    for text in ["http://devgraph.example", "https://user:password@devgraph.example",
      "https://devgraph.example/path", "https://devgraph.example?secret=x",
      "https://devgraph.example#fragment", "", "https://devgraph.example:65536"] {
      XCTAssertThrowsError(try WorkServerSettings.address(text))
    }
  }
  func testProfilePreservesPinWithoutGrantingAuthority() throws {
    let expected = try profile()
    XCTAssertEqual(try WorkServerSettings.decode(JSONEncoder().encode(expected)), expected)
    let privateNetwork = try WorkAccessConfiguration(name: "Private work",
      receiver: URL(string: "https://private.example")!, issuer: "private-issuer",
      keyID: "key", publicKey: String(repeating: "34", count: 32), network: .tailscale)
    XCTAssertEqual(try WorkServerSettings.decode(JSONEncoder().encode(privateNetwork)), privateNetwork)
    XCTAssertThrowsError(try WorkServerSettings.decode(Data(repeating: 65, count: 16_385)))
    var object = try JSONSerialization.jsonObject(with: JSONEncoder().encode(expected)) as! [String: Any]
    object["credential"] = ["secret": "must-never-be-imported"]
    XCTAssertThrowsError(try WorkServerSettings.decode(JSONSerialization.data(withJSONObject: object)))
    object.removeValue(forKey: "credential")
    object["receiver"] = "https://different.example"
    XCTAssertThrowsError(try WorkServerSettings.decode(JSONSerialization.data(withJSONObject: object)))
    object["receiver"] = expected.origin
    var authority = object["authority"] as! [String: Any]
    authority["private_key"] = "never-import"
    object["authority"] = authority
    XCTAssertThrowsError(try WorkServerSettings.decode(JSONSerialization.data(withJSONObject: object)))
  }
  func testSettingsAreExplicitDurableAndRejectStaleReplacement() throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = try WorkServerStore(directory: directory)
    XCTAssertNil(try store.load())
    let first = try profile()
    try store.save(first, replacing: nil)
    XCTAssertEqual(try WorkServerStore(directory: directory).load(), first)
    let second = try profile("https://other.example")
    XCTAssertThrowsError(try store.save(second, replacing: nil))
    XCTAssertEqual(try store.load(), first)
    try store.save(second, replacing: first)
    XCTAssertEqual(try store.load(), second)
    XCTAssertThrowsError(try store.save(nil, replacing: first))
    XCTAssertEqual(try store.load(), second)
    try store.save(nil, replacing: second)
    XCTAssertNil(try store.load())
  }
}
