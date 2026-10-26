import XCTest
@testable import ZenithKit

final class TailscaleKeyCreationTests: XCTestCase {
  private let token = "tskey-api-synthetic-0123456789abcdef0123456789abcdef"
  private let now = Date(timeIntervalSince1970: 1_800_000_000)
  private func response(reusable: Bool = false, ephemeral: Bool = false, preauthorized: Bool = false, tags: [String] = []) throws -> Data {
    let date = ISO8601DateFormatter()
    return try JSONSerialization.data(withJSONObject: [
      "id": "synthetic123CNTRL", "key": "tskey-auth-synthetic-0123456789abcdef0123456789abcdef",
      "created": date.string(from: now), "expires": date.string(from: now.addingTimeInterval(86_400)),
      "capabilities": ["devices": ["create": ["reusable": reusable, "ephemeral": ephemeral, "preauthorized": preauthorized, "tags": tags]]]
    ])
  }
  func testOnlyFixedOfficialEndpointAndReviewedLeastPrivilegeBodyAreSent() async throws {
    let body = try response(), calls = KeyCreationCalls()
    let client = TailscaleKeyCreator(exchange: { request in
      await calls.record(request)
      return PrivateHTTPResponse(status: 200, data: body)
    })
    let result = try await client.generate(tailnet: "example.test", description: "Zenith iPad", expiryDays: 1, apiToken: token, now: now)
    let recorded = await calls.requests
    let request = try XCTUnwrap(recorded.first)
    XCTAssertEqual(recorded.count, 1)
    XCTAssertEqual(request.url?.absoluteString, "https://api.tailscale.com/api/v2/tailnet/example.test/keys")
    XCTAssertEqual(request.httpMethod, "POST")
    XCTAssertEqual(request.value(forHTTPHeaderField: "Authorization"), "Basic " + Data((token + ":").utf8).base64EncodedString())
    let payload = try JSONSerialization.jsonObject(with: XCTUnwrap(request.httpBody)) as! [String: Any]
    XCTAssertEqual(payload["description"] as? String, "Zenith iPad")
    XCTAssertEqual(payload["expirySeconds"] as? Int, 86_400)
    let capabilities = payload["capabilities"] as! [String: Any]
    let create = (capabilities["devices"] as! [String: Any])["create"] as! [String: Any]
    XCTAssertEqual(create["reusable"] as? Bool, false)
    XCTAssertEqual(create["ephemeral"] as? Bool, false)
    XCTAssertEqual(create["preauthorized"] as? Bool, false)
    XCTAssertEqual(create["tags"] as? [String], [])
    XCTAssertEqual(result.id, "synthetic123CNTRL")
    XCTAssertFalse(String(describing: result).contains("tskey-auth-"))
  }
  func testInvalidTailnetsTokensAndLifetimeFailBeforeDispatch() async throws {
    let calls = KeyCreationCalls()
    let client = TailscaleKeyCreator(exchange: { request in
      await calls.record(request); throw URLError(.badServerResponse)
    })
    for tailnet in ["", "..", "../other", "example.test?x=1", "https://evil.test", "user:password@example.test", "example.test/%2f"] {
      do { _ = try await client.generate(tailnet: tailnet, description: "iPad", expiryDays: 1, apiToken: token, now: now); XCTFail("Invalid tailnet") }
      catch TailscaleKeyCreationFailure.invalidInput { }
    }
    for invalid in ["tskey-auth-synthetic-0123456789abcdef0123456789abcdef", token + "\nAuthorization: bad"] {
      do { _ = try await client.generate(tailnet: "example.test", description: "iPad", expiryDays: 1, apiToken: invalid, now: now); XCTFail("API token required") }
      catch TailscaleKeyCreationFailure.invalidInput { }
    }
    for days in [0, 91] {
      do { _ = try await client.generate(tailnet: "example.test", description: "iPad", expiryDays: days, apiToken: token, now: now); XCTFail("Bounded lifetime") }
      catch TailscaleKeyCreationFailure.invalidInput { }
    }
    let count = await calls.requests.count; XCTAssertEqual(count, 0)
  }
  func testNoRetriesOrUpstreamSecretDisclosureAfterUncertainResult() async throws {
    let calls = KeyCreationCalls()
    let client = TailscaleKeyCreator(exchange: { request in
      await calls.record(request); throw NSError(domain: "secret-tskey-api-do-not-display", code: 1)
    })
    do { _ = try await client.generate(tailnet: "example.test", description: "iPad", expiryDays: 1, apiToken: token, now: now); XCTFail("Uncertain") }
    catch {
      XCTAssertEqual(error as? TailscaleKeyCreationFailure, .outcomeUnknown)
      XCTAssertFalse(error.localizedDescription.contains("tskey"))
    }
    let count = await calls.requests.count; XCTAssertEqual(count, 1)
  }
  func testWidenedOrWrongKindResponsesAreNotDisclosed() async throws {
    var invalid = [try response(reusable: true), try response(ephemeral: true), try response(preauthorized: true), try response(tags: ["tag:admin"])]
    invalid.append(try response().replacingOccurrences(of: "tskey-auth-", with: "tskey-api-"))
    for body in invalid {
      let client = TailscaleKeyCreator(exchange: { _ in PrivateHTTPResponse(status: 200, data: body) })
      do { _ = try await client.generate(tailnet: "example.test", description: "iPad", expiryDays: 1, apiToken: token, now: now); XCTFail("Response cannot widen") }
      catch TailscaleKeyCreationFailure.outcomeUnknown { }
    }
  }
  func testRejectsOversizeDuplicateAndExcessiveExpiryResponses() async throws {
    let valid = try response()
    let date = ISO8601DateFormatter()
    let long = String(data: valid, encoding: .utf8)!.replacingOccurrences(of: date.string(from: now.addingTimeInterval(86_400)), with: date.string(from: now.addingTimeInterval(90 * 86_400)))
    for body in [Data(repeating: 65, count: 65_537), Data("{\"key\":\"a\",\"key\":\"b\"}".utf8), Data(long.utf8)] {
      let client = TailscaleKeyCreator(exchange: { _ in PrivateHTTPResponse(status: 200, data: body) })
      do { _ = try await client.generate(tailnet: "example.test", description: "iPad", expiryDays: 1, apiToken: token, now: now); XCTFail("Bounded response") }
      catch TailscaleKeyCreationFailure.outcomeUnknown { }
    }
  }
  func testRedirectServerFailureAndAuthorizationDenialDoNotRetry() async throws {
    for status in [302, 500, 401, 403, 400, 404] {
      let calls = KeyCreationCalls()
      let client = TailscaleKeyCreator(exchange: { request in
        await calls.record(request); return PrivateHTTPResponse(status: status, data: Data("secret body".utf8))
      })
      do { _ = try await client.generate(tailnet: "example.test", description: "iPad", expiryDays: 1, apiToken: token, now: now); XCTFail("Must reject") }
      catch {
        let expected: TailscaleKeyCreationFailure = [400, 401, 403, 404].contains(status) ? .rejected : .outcomeUnknown
        XCTAssertEqual(error as? TailscaleKeyCreationFailure, expected)
        XCTAssertFalse(error.localizedDescription.contains("secret body"))
      }
      let count = await calls.requests.count; XCTAssertEqual(count, 1)
    }
  }
  func testCancellationBeforeDispatchDoesNotCreateAKey() async throws {
    let calls = KeyCreationCalls()
    let client = TailscaleKeyCreator(exchange: { request in await calls.record(request); throw CancellationError() })
    let task = Task { withUnsafeCurrentTask { $0?.cancel() }; return try await client.generate(tailnet: "example.test", description: "iPad", expiryDays: 1, apiToken: token, now: now) }
    do { _ = try await task.value; XCTFail("Cancelled") } catch is CancellationError { }
    let count = await calls.requests.count; XCTAssertEqual(count, 0)
  }
  func testDefaultTailnetUsesTheTokenDefaultWithoutGuessingHostNetwork() async throws {
    let body = try response(), calls = KeyCreationCalls()
    let client = TailscaleKeyCreator(exchange: { request in await calls.record(request); return PrivateHTTPResponse(status: 200, data: body) })
    _ = try await client.generate(tailnet: "-", description: "iPad", expiryDays: 1, apiToken: token, now: now)
    let requests = await calls.requests
    XCTAssertEqual(requests.first?.url?.absoluteString, "https://api.tailscale.com/api/v2/tailnet/-/keys")
  }
  func testCancellationAfterDispatchWithholdsTheReturnedSecret() async throws {
    let body = try response(), calls = KeyCreationCalls()
    let client = TailscaleKeyCreator(exchange: { request in
      await calls.record(request)
      withUnsafeCurrentTask { $0?.cancel() }
      return PrivateHTTPResponse(status: 200, data: body)
    })
    let task = Task { try await client.generate(tailnet: "example.test", description: "iPad", expiryDays: 1, apiToken: token, now: now) }
    do { _ = try await task.value; XCTFail("No secret after cancellation") }
    catch TailscaleKeyCreationFailure.outcomeUnknown { }
    let count = await calls.requests.count; XCTAssertEqual(count, 1)
  }
  func testUnknownCapabilitiesAndAdministrativeScopesFailClosed() async throws {
    for field in ["extraCapability", "scopes", "tags"] {
      var object = try JSONSerialization.jsonObject(with: response()) as! [String: Any]
      if field == "extraCapability" {
        var caps = object["capabilities"] as! [String: Any]; caps["admin"] = true; object["capabilities"] = caps
      } else { object[field] = ["admin"] }
      let body = try JSONSerialization.data(withJSONObject: object)
      let client = TailscaleKeyCreator(exchange: { _ in PrivateHTTPResponse(status: 200, data: body) })
      do { _ = try await client.generate(tailnet: "example.test", description: "iPad", expiryDays: 1, apiToken: token, now: now); XCTFail("Extra capabilities") }
      catch TailscaleKeyCreationFailure.outcomeUnknown { }
    }
  }
}
private actor KeyCreationCalls {
  var requests: [URLRequest] = []
  func record(_ request: URLRequest) { requests.append(request) }
}
private extension Data {
  func replacingOccurrences(of old: String, with new: String) -> Data { Data(String(data: self, encoding: .utf8)!.replacingOccurrences(of: old, with: new).utf8) }
}
