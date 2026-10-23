import XCTest

@testable import ZenithKit

private final class HermesStub: URLProtocol {
  static let lock = NSLock()
  static var handler: ((URLRequest) throws -> (Int, [String: Any]))?
  static func use(_ callback: @escaping (URLRequest) throws -> (Int, [String: Any])) {
    lock.lock()
    defer { lock.unlock() }
    handler = callback
  }
  override class func canInit(with request: URLRequest) -> Bool { true }
  override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
  override func startLoading() {
    Self.lock.lock()
    defer { Self.lock.unlock() }
    do {
      let (status, body) = try XCTUnwrap(Self.handler)(request)
      let response = try XCTUnwrap(
        HTTPURLResponse(
          url: XCTUnwrap(request.url), statusCode: status, httpVersion: nil, headerFields: nil))
      client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
      client?.urlProtocol(self, didLoad: try JSONSerialization.data(withJSONObject: body))
      client?.urlProtocolDidFinishLoading(self)
    } catch { client?.urlProtocol(self, didFailWithError: error) }
  }
  override func stopLoading() {}
}
final class HermesChatTests: XCTestCase {
  private func settings() throws -> HermesChatSettings {
    try HermesChatSettings(
      connection: HermesChatConnection(
        name: "Hermes", receiver: URL(string: "https://gateway.example.test:10443")!),
      key: "disposable-test-connection-key")
  }
  private func client() throws -> HermesChatClient {
    let configuration = URLSessionConfiguration.ephemeral
    configuration.protocolClasses = [HermesStub.self]
    return try HermesChatClient(
      settings: settings(), transport: PrivateTransport(configuration: configuration))
  }
  func testLiveGatewayWhenExplicitlyConfigured() async throws {
    guard let path = ProcessInfo.processInfo.environment["HERMES_CHAT_TEST_PROFILE"] else {
      throw XCTSkip("No explicitly selected live Hermes test connection")
    }
    let settings = try HermesChatSettings.importFile(Data(contentsOf: URL(fileURLWithPath: path)))
    let client = try HermesChatClient(settings: settings,
      transport: PrivateTransport(configurationProvider: { URLSessionConfiguration.ephemeral }, requestTimeout: 300, resourceTimeout: 600))
    try await client.check()
    let id = "zenith_native_check_" + UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
    try await client.createSession(id: id)
    let reply = try await client.send("Reply exactly: Zenith chat ready. Do not use any tools.", sessionID: id)
    XCTAssertEqual(reply.text.trimmingCharacters(in: .whitespacesAndNewlines), "Zenith chat ready.")
    let history = try await client.history(sessionID: id)
    XCTAssertEqual(history.messages.last?.text, reply.text)
    XCTAssertTrue(history.hasReply(after: 0))
  }
  func testNormalGatewaySessionsAPIAuthAndHistoryFiltering() async throws {
    HermesStub.use { request in
      XCTAssertEqual(
        request.value(forHTTPHeaderField: "Authorization"), "Bearer disposable-test-connection-key")
      XCTAssertEqual(request.url?.host, "gateway.example.test")
      XCTAssertNil(request.url?.query)
      switch request.url!.path {
      case "/v1/capabilities":
        XCTAssertEqual(request.httpMethod, "GET")
        return (
          200,
          [
            "object": "hermes.api_server.capabilities",
            "features": ["session_chat": true, "session_key_header": "X-Hermes-Session-Key"],
            "endpoints": [
              "session_create": ["method": "POST", "path": "/api/sessions"],
              "session_messages": ["method": "GET", "path": "/api/sessions/{session_id}/messages"],
            ],
          ]
        )
      case "/api/sessions":
        XCTAssertEqual(request.httpMethod, "POST")
        return (201, ["session": ["id": "zenith_test"]])
      case "/api/sessions/zenith_test/chat":
        XCTAssertEqual(request.httpMethod, "POST")
        XCTAssertEqual(request.timeoutInterval, 300)
        return (
          200,
          [
            "session_id": "zenith_test",
            "message": ["role": "assistant", "content": "Hello from Hermes"],
          ]
        )
      case "/api/sessions/zenith_test/messages":
        return (
          200,
          [
            "session_id": "zenith_test",
            "data": [
              ["role": "system", "content": "hidden system context"],
              ["role": "user", "content": "Hello"],
              [
                "role": "assistant", "content": "hidden tool preamble",
                "tool_calls": [["id": "tool_1"]],
              ],
              ["role": "tool", "content": "hidden tool output"],
              [
                "role": "assistant",
                "content": [["type": "output_text", "text": "Hello from Hermes"]],
              ],
            ],
          ]
        )
      default:
        XCTFail("Unexpected endpoint")
        return (404, [:])
      }
    }
    let client = try client()
    try await client.check()
    try await client.createSession(id: "zenith_test")
    let response = try await client.send("Hello", sessionID: "zenith_test")
    XCTAssertEqual(response.text, "Hello from Hermes")
    let history = try await client.history(sessionID: "zenith_test")
    XCTAssertEqual(history.messages.map(\.role), ["user", "assistant"])
    XCTAssertTrue(history.hasReply(after: 0))
    XCTAssertFalse(history.hasReply(after: 2))
  }
  func testAuthenticationAndRedirectFailuresNeverBecomeAssistantMessages() async throws {
    for status in [401, 403, 302] {
      HermesStub.use { _ in (status, ["secret": "must never reach UI"]) }
      do {
        _ = try await client().send("Hello", sessionID: "zenith_test")
        XCTFail("Request should fail")
      } catch {
        if status != 302 {
          XCTAssertEqual(error as? HermesChatError, .authentication)
        } else {
          XCTAssertEqual(error as? WalletFailure, .core("service_rejected_request"))
        }
        XCTAssertFalse(error.localizedDescription.contains("must never reach UI"))
      }
    }
  }
  func testConfigurationAndPrivateFileImportRejectUnsafeAuthority() throws {
    for url in [
      "http://example.test", "https://key@example.test", "https://example.test/?key=secret",
      "https://example.test/path",
    ] {
      XCTAssertThrowsError(try HermesChatConnection(name: "Hermes", receiver: URL(string: url)!))
    }
    for key in ["short", "bad\r\nAuthorization: key"] {
      XCTAssertThrowsError(try HermesChatConnection.validateKey(key))
    }
    let value: [String: Any] = [
      "schema": "zenith.hermes-chat.v1", "name": "My Hermes", "receiver": "https://example.test",
      "key": "private-test-connection",
    ]
    let imported = try HermesChatSettings.importFile(JSONSerialization.data(withJSONObject: value))
    XCTAssertEqual(imported.connection.name, "My Hermes")
    XCTAssertNil(imported.sessionID)
    var unknown = value
    unknown["wallet_seed"] = "unsupported"
    XCTAssertThrowsError(
      try HermesChatSettings.importFile(JSONSerialization.data(withJSONObject: unknown)))
    XCTAssertThrowsError(try HermesChatSettings.importFile(Data(repeating: 65, count: 8193)))
  }
  func testInvalidSessionCannotDispatchOrChangeTheEndpoint() async throws {
    HermesStub.use { _ in
      XCTFail("Invalid session must not dispatch")
      return (500, [:])
    }
    for id in ["../another", "a/b", "x?token=value", "", String(repeating: "a", count: 257)] {
      do {
        _ = try await client().history(sessionID: id)
        XCTFail("Bad session")
      } catch { XCTAssertEqual(error as? HermesChatError, .invalidResponse) }
    }
  }
}
