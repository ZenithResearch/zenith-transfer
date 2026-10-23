import XCTest

@testable import ZenithKit

private func networkStatus(
  _ state: String, authURL: String? = nil, name: String? = nil
) throws -> PrivateNetworkStatus {
  var object: [String: Any] = ["BackendState": state]
  if let authURL { object["AuthURL"] = authURL }
  if let name { object["CurrentTailnet"] = ["Name": name] }
  return try PrivateNetworkStatus(data: JSONSerialization.data(withJSONObject: object))
}

/// Only this reserved test host is handled; every intercepted request stays in-process.
private final class PrivateNetworkResponseProtocol: URLProtocol {
  private static let lock = NSLock()
  private static var counts: [String: Int] = [:]
  static func dispatchCount(for url: URL) -> Int {
    lock.lock(); defer { lock.unlock() }
    return counts[url.absoluteString, default: 0]
  }
  override class func canInit(with request: URLRequest) -> Bool {
    request.url?.host == "zenith-private-transport.invalid"
  }
  override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
  override func startLoading() {
    guard let url = request.url else { return }
    Self.lock.lock()
    Self.counts[url.absoluteString, default: 0] += 1
    Self.lock.unlock()
    let response = HTTPURLResponse(
      url: url, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: ["Content-Length": "2"])!
    client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
    client?.urlProtocol(self, didLoad: Data("{}".utf8))
    client?.urlProtocolDidFinishLoading(self)
  }
  override func stopLoading() {}
}

private func interceptedConfiguration() -> URLSessionConfiguration {
  let configuration = URLSessionConfiguration.ephemeral
  configuration.protocolClasses = [PrivateNetworkResponseProtocol.self]
  return configuration
}

/// Gates deliberately ignore cancellation to exercise late driver completions.
private actor FakePrivateNetworkDriver: PrivateNetworkDriver {
  private var current: PrivateNetworkStatus
  private(set) var starts: [Bool] = []
  private(set) var enrollments = 0
  private(set) var submittedKey: String?
  private var rejectEnrollment = false
  private(set) var stops = 0
  private(set) var statusCalls = 0
  private(set) var configurationCalls = 0
  private var holdStatus = false
  private var holdConfiguration = false
  private var pendingStatus: CheckedContinuation<PrivateNetworkStatus, Never>?
  private var pendingConfiguration: CheckedContinuation<URLSessionConfiguration, Never>?

  init(status: PrivateNetworkStatus) { current = status }
  func start(interactive: Bool) async throws { starts.append(interactive) }
  func enroll(authKey: String) async throws {
    enrollments += 1
    submittedKey = authKey
    if rejectEnrollment { throw NSError(domain: "upstream secret: " + authKey, code: 1) }
  }
  func rejectNextEnrollment() { rejectEnrollment = true }
  func stop() async { stops += 1 }
  func status() async throws -> PrivateNetworkStatus {
    statusCalls += 1
    if holdStatus {
      holdStatus = false
      return await withCheckedContinuation { pendingStatus = $0 }
    }
    return current
  }
  func configuration() async throws -> URLSessionConfiguration {
    configurationCalls += 1
    if holdConfiguration {
      holdConfiguration = false
      return await withCheckedContinuation { pendingConfiguration = $0 }
    }
    return interceptedConfiguration()
  }
  func pauseNextStatus() { holdStatus = true }
  func pauseNextConfiguration() { holdConfiguration = true }
  var statusIsPending: Bool { pendingStatus != nil }
  var configurationIsPending: Bool { pendingConfiguration != nil }
  func releaseStatus(_ status: PrivateNetworkStatus) {
    let continuation = pendingStatus
    pendingStatus = nil
    continuation?.resume(returning: status)
  }
  func releaseConfiguration() {
    let continuation = pendingConfiguration
    pendingConfiguration = nil
    continuation?.resume(returning: interceptedConfiguration())
  }
}

private actor ConfigurationGate {
  private var continuation: CheckedContinuation<URLSessionConfiguration, Never>?
  var isPending: Bool { continuation != nil }
  func configuration() async -> URLSessionConfiguration {
    await withCheckedContinuation { continuation = $0 }
  }
  func release() {
    let pending = continuation
    continuation = nil
    pending?.resume(returning: interceptedConfiguration())
  }
}

final class PrivateNetworkTests: XCTestCase {
  override func setUp() {
    super.setUp()
    URLProtocol.registerClass(PrivateNetworkResponseProtocol.self)
  }
  override func tearDown() {
    URLProtocol.unregisterClass(PrivateNetworkResponseProtocol.self)
    super.tearDown()
  }

  func testEnrollmentAdmissionRejectsOtherSecretsAndOversizedFiles() throws {
    let key = "tskey-auth-0123456789ABCDEF-0123456789abcdef0123456789abcdef"
    XCTAssertEqual(try TailscaleEnrollment.validatedKey("  " + key + "\n"), key)
    XCTAssertEqual(try TailscaleEnrollment.importKey(Data((key + "\n").utf8)), key)
    for value in ["", "tskey-auth-short", "tskey-api-" + String(repeating: "a", count: 50),
      "tskey-client-" + String(repeating: "a", count: 50), key + "\ninjected", key + "?x=1",
      "tskey-auth-" + String(repeating: "a", count: 513)] {
      XCTAssertThrowsError(try TailscaleEnrollment.validatedKey(value)) {
        XCTAssertEqual($0 as? PrivateNetworkError, .invalidAuthKey)
      }
    }
    XCTAssertThrowsError(try TailscaleEnrollment.importKey(Data(repeating: 65, count: 1025)))
    XCTAssertThrowsError(try TailscaleEnrollment.importKey(Data([0xff, 0xfe])))
    XCTAssertThrowsError(try TailscaleEnrollment.importKey(Data(#"{"key":"gateway-secret"}"#.utf8)))
  }

  @MainActor
  func testEnrollmentResumesSavedIdentityWithoutReplayingKey() async throws {
    let driver = FakePrivateNetworkDriver(status: try networkStatus("Running"))
    let session = PrivateNetworkSession(driver: driver)
    let key = "tskey-auth-0123456789ABCDEF-0123456789abcdef0123456789abcdef"
    try session.enroll(authKey: key)
    await eventually { session.phase == .connected }
    let submitted = await driver.submittedKey
    XCTAssertEqual(submitted, key)
    session.suspend()
    session.resume()
    await eventually { session.phase == .connected }
    let starts = await driver.starts
    let enrollments = await driver.enrollments
    XCTAssertEqual(starts, [false])
    XCTAssertEqual(enrollments, 1)
    session.disconnect()
  }

  @MainActor
  func testEnrollmentNeverExposesBrowserFallbackAndCancellationDoesNotReplay() async throws {
    let driver = FakePrivateNetworkDriver(status: try networkStatus(
      "NeedsLogin", authURL: "https://login.tailscale.com/a/not-for-key-enrollment"))
    let session = PrivateNetworkSession(driver: driver)
    try session.enroll(authKey: "tskey-auth-0123456789ABCDEF-0123456789abcdef0123456789abcdef")
    await eventually { await driver.statusCalls > 0 }
    XCTAssertEqual(session.phase, .connecting)
    XCTAssertNil(session.authURL)
    session.cancelSignIn()
    session.resume()
    await eventually { await driver.stops >= 3 }
    let starts = await driver.starts
    let enrollments = await driver.enrollments
    XCTAssertTrue(starts.isEmpty)
    XCTAssertEqual(enrollments, 1)
    XCTAssertEqual(session.phase, .idle)
  }

  @MainActor
  func testEnrollmentFailureRedactsUpstreamErrorAndInvalidInputDoesNotDisconnect() async throws {
    let driver = FakePrivateNetworkDriver(status: try networkStatus("Running"))
    let session = PrivateNetworkSession(driver: driver)
    session.connect()
    await eventually { session.phase == .connected }
    let generation = session.generation
    XCTAssertThrowsError(try session.enroll(authKey: "wrong-token"))
    XCTAssertEqual(session.phase, .connected)
    XCTAssertEqual(session.generation, generation)
    await driver.rejectNextEnrollment()
    try session.enroll(authKey: "tskey-auth-0123456789ABCDEF-0123456789abcdef0123456789abcdef")
    await eventually { session.phase == .failed }
    XCTAssertEqual(session.message, PrivateNetworkError.enrollmentFailed.localizedDescription)
    XCTAssertFalse(session.message?.contains("tskey") ?? true)
    session.disconnect()
  }

  func testSignInRejectsUntrustedURLs() throws {
    let urls = [
      "http://login.tailscale.com/a/test", "https://untrusted.invalid/a/test",
      "https://login.tailscale.com.untrusted.invalid/a/test",
      "https://login.tailscale.com@untrusted.invalid/a/test",
      "https://user:password@login.tailscale.com/a/test",
      "https://login.tailscale.com:444/a/test", "https://login.tailscale.com/a/test#fragment",
      "file:///a/test", "javascript:alert(1)", "/a/test",
      "https://login.tailscale.com/" + String(repeating: "a", count: 4096),
    ]
    for url in urls {
      XCTAssertThrowsError(try networkStatus("NeedsLogin", authURL: url), url) {
        XCTAssertEqual($0 as? PrivateNetworkError, .invalidStatus)
      }
    }
    let allowed = "https://login.tailscale.com:443/a/test?next=approved"
    let status = try networkStatus("NeedsLogin", authURL: allowed)
    XCTAssertEqual(status.phase, .signInRequired)
    XCTAssertEqual(status.authURL?.absoluteString, allowed)
  }

  func testUnknownAndMalformedStatusNeverBecomeConnected() throws {
    for state in ["", "running", "Unknown", "FutureBackendState"] {
      XCTAssertThrowsError(try networkStatus(state)) {
        XCTAssertEqual($0 as? PrivateNetworkError, .invalidStatus)
      }
    }
    XCTAssertThrowsError(try PrivateNetworkStatus(data: Data("{}".utf8)))
    XCTAssertThrowsError(try PrivateNetworkStatus(data: Data(repeating: 32, count: 4_194_305))) {
      XCTAssertEqual($0 as? PrivateNetworkError, .invalidStatus)
    }
    XCTAssertEqual(try networkStatus("NeedsMachineAuth").phase, .awaitingApproval)
    XCTAssertEqual(try networkStatus("Stopped").phase, .paused)
  }

  func testAuthenticationURLIsOnlyExposedForSignInAndNetworkNameIsBounded() throws {
    let status = try networkStatus(
      "Running", authURL: "https://untrusted.invalid", name: String(repeating: "n", count: 257))
    XCTAssertEqual(status.phase, .connected)
    XCTAssertNil(status.authURL)
    XCTAssertNil(status.networkName)
    XCTAssertNil(try networkStatus("NeedsLogin", authURL: "").authURL)
    XCTAssertEqual(try networkStatus("Running", name: "Example network").networkName, "Example network")
  }

  @MainActor
  func testTransportCannotStartNetworkBeforeExplicitConnect() async throws {
    let driver = FakePrivateNetworkDriver(status: try networkStatus("Running"))
    let session = PrivateNetworkSession(driver: driver)
    let transport = session.transport()
    session.resume()
    let request = request()
    do {
      _ = try await transport.request(request)
      XCTFail("Transport must require an explicit connection")
    } catch { XCTAssertEqual(error as? PrivateNetworkError, .disconnected) }
    let starts = await driver.starts
    let statusCalls = await driver.statusCalls
    let configurationCalls = await driver.configurationCalls
    XCTAssertTrue(starts.isEmpty)
    XCTAssertEqual(statusCalls, 0)
    XCTAssertEqual(configurationCalls, 0)
    XCTAssertEqual(session.phase, .idle)
    XCTAssertEqual(PrivateNetworkResponseProtocol.dispatchCount(for: request.url!), 0)
  }

  @MainActor
  func testSignInCancellationClearsURLAndDoesNotResume() async throws {
    let driver = FakePrivateNetworkDriver(status: try networkStatus(
      "NeedsLogin", authURL: "https://login.tailscale.com/a/test"))
    let session = PrivateNetworkSession(driver: driver)
    session.connect()
    await eventually { session.phase == .signInRequired }
    XCTAssertNotNil(session.authURL)
    let generation = session.generation
    session.cancelSignIn()
    session.resume()
    await eventually { await driver.stops >= 3 }
    XCTAssertEqual(session.phase, .idle)
    XCTAssertNil(session.authURL)
    XCTAssertNil(session.message)
    XCTAssertGreaterThan(session.generation, generation)
    let starts = await driver.starts
    XCTAssertEqual(starts, [true])
  }

  @MainActor
  func testLateSignInCompletionCannotReviveCancelledSession() async throws {
    let driver = FakePrivateNetworkDriver(status: try networkStatus("Running"))
    await driver.pauseNextStatus()
    let session = PrivateNetworkSession(driver: driver)
    session.connect()
    await eventually { await driver.statusIsPending }
    session.cancelSignIn()
    let generation = session.generation
    await driver.releaseStatus(try networkStatus(
      "NeedsLogin", authURL: "https://login.tailscale.com/a/stale"))
    await eventually { await driver.stops >= 3 }
    XCTAssertEqual(session.phase, .idle)
    XCTAssertNil(session.authURL)
    XCTAssertEqual(session.generation, generation)
  }

  @MainActor
  func testSuspendResumeSerializesDriverAndRejectsStaleAuthentication() async throws {
    let driver = FakePrivateNetworkDriver(status: try networkStatus("Running", name: "Example network"))
    await driver.pauseNextStatus()
    let session = PrivateNetworkSession(driver: driver)
    session.connect()
    await eventually { await driver.statusIsPending }
    session.suspend()
    XCTAssertEqual(session.phase, .paused)
    XCTAssertNil(session.authURL)
    session.resume()
    session.resume()
    let beforeRelease = await driver.starts
    XCTAssertEqual(beforeRelease, [true], "A new driver start must wait for old work to finish")
    await driver.releaseStatus(try networkStatus(
      "NeedsLogin", authURL: "https://login.tailscale.com/a/stale"))
    await eventually { session.phase == .connected }
    let starts = await driver.starts
    XCTAssertEqual(starts, [true, false], "Foreground resume must be noninteractive and happen once")
    XCTAssertNil(session.authURL)
    XCTAssertEqual(session.networkName, "Example network")
    session.disconnect()
  }

  @MainActor
  func testSuspendingInvalidatesAnAlreadyCreatedTransportWhileConfigurationIsPending() async throws {
    let driver = FakePrivateNetworkDriver(status: try networkStatus("Running"))
    let session = PrivateNetworkSession(driver: driver)
    session.connect()
    await eventually { session.phase == .connected }
    await driver.pauseNextConfiguration()
    let request = request()
    let transport = session.transport()
    let pending = Task { try await transport.request(request) }
    await eventually { await driver.configurationIsPending }
    session.suspend()
    await driver.releaseConfiguration()
    do {
      _ = try await pending.value
      XCTFail("Backgrounding must invalidate a pending transport")
    } catch { XCTAssertEqual(error as? PrivateNetworkError, .interrupted) }
    XCTAssertEqual(session.phase, .paused)
    XCTAssertEqual(PrivateNetworkResponseProtocol.dispatchCount(for: request.url!), 0)
    session.disconnect()
  }

  func testProviderFailurePropagatesWithoutDirectFallback() async throws {
    let transport = PrivateTransport(configurationProvider: { throw PrivateNetworkError.disconnected })
    let request = request()
    do {
      _ = try await transport.request(request)
      XCTFail("Provider failure must not fall back to a direct request")
    } catch { XCTAssertEqual(error as? PrivateNetworkError, .disconnected) }
    XCTAssertEqual(PrivateNetworkResponseProtocol.dispatchCount(for: request.url!), 0)
    let origin = URL(string: "https://zenith-private-transport.invalid")!
    do {
      try await transport.checkReadReceiver(at: origin)
      XCTFail("Connection checks must also require the configured route")
    } catch { XCTAssertEqual(error as? PrivateNetworkError, .disconnected) }
    XCTAssertEqual(PrivateNetworkResponseProtocol.dispatchCount(
      for: origin.appendingPathComponent("devgraph/native-read/v2/requests")), 0)
  }

  @MainActor
  func testTransportCancellationWhileProviderIsPendingNeverDispatches() async throws {
    try await assertPendingProviderCancellation(cancelTransport: true)
  }

  @MainActor
  func testTaskCancellationWhileProviderIsPendingNeverDispatches() async throws {
    try await assertPendingProviderCancellation(cancelTransport: false)
  }

  @MainActor
  private func assertPendingProviderCancellation(cancelTransport: Bool) async throws {
    let gate = ConfigurationGate()
    let transport = PrivateTransport(configurationProvider: { await gate.configuration() })
    let request = request()
    let pending = Task { try await transport.request(request) }
    await eventually { await gate.isPending }
    if cancelTransport { transport.cancel() } else { pending.cancel() }
    await gate.release()
    do {
      _ = try await pending.value
      XCTFail("Cancelled work must not dispatch after its provider returns")
    } catch { XCTAssertTrue(error is CancellationError, "Unexpected failure: \(error)") }
    XCTAssertEqual(PrivateNetworkResponseProtocol.dispatchCount(for: request.url!), 0)
  }

  private func request() -> URLRequest {
    URLRequest(url: URL(string: "https://zenith-private-transport.invalid/\(UUID().uuidString)")!)
  }

  @MainActor
  private func eventually(
    file: StaticString = #filePath, line: UInt = #line,
    _ predicate: @escaping @MainActor () async -> Bool
  ) async {
    for _ in 0..<300 {
      if await predicate() { return }
      try? await Task.sleep(nanoseconds: 10_000_000)
    }
    XCTFail("Timed out waiting for the fake driver", file: file, line: line)
  }
}
