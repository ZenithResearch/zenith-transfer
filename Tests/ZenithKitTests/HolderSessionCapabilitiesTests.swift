import XCTest
@testable import ZenithKit

final class HolderSessionCapabilitiesTests: XCTestCase {
  private func configuration() throws -> WorkAccessConfiguration {
    try .init(name: "Synthetic service", receiver: URL(string: "https://graph.example")!, issuer: "issuer:example", keyID: "key:one", publicKey: String(repeating: "ab", count: 32), network: nil)
  }
  private func capabilities() -> [String: Any] {
    ["schema": "secs.holder-session-capabilities.v1", "supported": true, "profile": "secs.holder-session.v1",
      "issuer_pin": ["issuer": "issuer:example", "key_id": "key:one", "public_key": String(repeating: "ab", count: 32), "service": "service:example"],
      "audience": "devgraph", "grant_schemas": ["secs.holder-grant.v2"], "credential_schema": "secs.holder-session-credential.v1",
      "presentation_schema": "secs.holder-session-presentation.v1", "read_only": true, "max_ttl_seconds": 300,
      "review_ttl_seconds": 120, "proof_max_ttl_seconds": 60, "challenge_path": "/holder-sessions/v1/challenges",
      "exchange_path": "/holder-sessions/v1/exchange", "status_path": "/holder-sessions/v1/status"]
  }
  func testDiscoveryBindsSavedPinAndRejectsRouteAuthoritySubstitution() throws {
    let c = try configuration(), value = capabilities()
    let decoded = try XCTUnwrap(HolderSessionCapabilities.decode(HS.encode(value), configuration: c, origin: "app://zenith-ios"))
    XCTAssertEqual(decoded.provider.service, "service:example")
    XCTAssertEqual(decoded.context.origin, "app://zenith-ios")
    XCTAssertEqual(try HolderSessionAgentProfile.decode(decoded.custodyProfile).maximumSessionSeconds, 300)
    for field in ["challenge_path", "exchange_path", "status_path"] {
      for path in ["https://attacker.example/", "//attacker.example/status", "/other/status"] {
        var changed = value; changed[field] = path
        XCTAssertThrowsError(try HolderSessionCapabilities.decode(HS.encode(changed), configuration: c, origin: "app://zenith-ios"))
      }
    }
    var changed = value, pin = value["issuer_pin"] as! [String: Any]; pin["public_key"] = String(repeating: "cd", count: 32); changed["issuer_pin"] = pin
    XCTAssertThrowsError(try HolderSessionCapabilities.decode(HS.encode(changed), configuration: c, origin: "app://zenith-ios"))
  }
  func testUnsupportedDoesNotChooseLegacyAuthorityAndStrictVersionsRemainClosed() throws {
    let c = try configuration(); var value = capabilities(); value["supported"] = false
    XCTAssertNil(try HolderSessionCapabilities.decode(HS.encode(value), configuration: c, origin: "app://zenith-ios"))
    value["profile"] = "unknown"
    XCTAssertThrowsError(try HolderSessionCapabilities.decode(HS.encode(value), configuration: c, origin: "app://zenith-ios"))
    value = capabilities(); value["max_ttl_seconds"] = 3601
    XCTAssertThrowsError(try HolderSessionCapabilities.decode(HS.encode(value), configuration: c, origin: "app://zenith-ios"))
    value = capabilities(); value["parent_grant"] = "not-metadata"
    XCTAssertThrowsError(try HolderSessionCapabilities.decode(HS.encode(value), configuration: c, origin: "app://zenith-ios"))
  }
}
