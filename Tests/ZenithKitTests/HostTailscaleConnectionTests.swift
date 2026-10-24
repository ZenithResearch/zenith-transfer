#if os(macOS)
import XCTest
@testable import ZenithKit

final class HostTailscaleConnectionTests: XCTestCase {
  func testEnrollmentUsesPrivateSnapshotFileAndNeverPassesKeyAsArgument() async throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let key = "tskey-auth-0123456789ABCDEF-0123456789abcdef0123456789abcdef"
    let file = root.appendingPathComponent("network.txt"); try NetworkConnectionFiles.saveEnrollmentKey(key, to: file)
    let review = try ConnectionFileReview.read(file, as: .tailscale)
    let fake = EnrollmentCommands(key: key)
    let client = HostTailscaleConnection(command: { try await fake.run($0) })
    let result = try await client.connect(using: review)
    XCTAssertEqual(result.phase, .connected)
    let args = await fake.arguments
    XCTAssertEqual(args.count, 3)
    XCTAssertEqual(args[1].first, "up")
    XCTAssertTrue(args[1][1].hasPrefix("--auth-key=file:"))
    XCTAssertFalse(args.joined().joined().contains(key))
    let snapshot = String(args[1][1].dropFirst("--auth-key=file:".count))
    XCTAssertFalse(FileManager.default.fileExists(atPath: snapshot))
    XCTAssertEqual(try review.selectedEnrollmentKey(), key, "Original user file remains intact")
  }
  func testCancellingEnrollmentRemovesTemporaryKeyAndDoesNotRetry() async throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let file = root.appendingPathComponent("key.txt")
    try NetworkConnectionFiles.saveEnrollmentKey("tskey-auth-0123456789ABCDEF-0123456789abcdef0123456789abcdef", to: file)
    let review = try ConnectionFileReview.read(file, as: .tailscale)
    let fake = PendingEnrollmentCommands()
    let client = HostTailscaleConnection(command: { try await fake.run($0) })
    let task = Task { try await client.connect(using: review) }
    let deadline = Date().addingTimeInterval(2)
    while await fake.keyPath == nil && Date() < deadline { try await Task.sleep(nanoseconds: 5_000_000) }
    let snapshot = await fake.snapshotPath()
    let path = try XCTUnwrap(snapshot)
    task.cancel()
    do { _ = try await task.value; XCTFail("Cancellation must stop the pending call") }
    catch is CancellationError { }
    XCTAssertFalse(FileManager.default.fileExists(atPath: path))
    let calls = await fake.count(); XCTAssertEqual(calls, 2)
    XCTAssertEqual(try review.selectedEnrollmentKey(), "tskey-auth-0123456789ABCDEF-0123456789abcdef0123456789abcdef")
  }
  func testHostTransportRefusesRequestsWhenDisconnected() async throws {
    let client = HostTailscaleConnection(command: { args in
      XCTAssertEqual(args, ["status", "--json"])
      return Data(#"{"BackendState":"NeedsLogin"}"#.utf8)
    })
    do {
      _ = try await client.transport().exchange(URLRequest(url: URL(string: "https://never-request.invalid")!), maximum: 1024)
      XCTFail("Disconnected host must not send a request")
    } catch PrivateNetworkError.disconnected { }
  }
  func testConnectedHostConfigurationIsEphemeralAndCookieFree() async throws {
    let fake = EnrollmentCommands(key: "", alreadyConnected: true)
    let client = HostTailscaleConnection(command: { try await fake.run($0) })
    let configuration = try await client.configuration()
    XCTAssertFalse(configuration.httpShouldSetCookies)
    XCTAssertNil(configuration.urlCache)
    XCTAssertNil(configuration.httpCookieStorage)
    XCTAssertNil(configuration.urlCredentialStorage)
    let calls = await fake.arguments; XCTAssertEqual(calls, [["status", "--json"]])
  }
  func testConnectedMacDoesNotChangeNetworkOrInvokeEnrollment() async throws {
    let file = URL(fileURLWithPath: "/does-not-exist.txt")
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let key = root.appendingPathComponent("key.txt")
    try NetworkConnectionFiles.saveEnrollmentKey("tskey-auth-0123456789ABCDEF-0123456789abcdef0123456789abcdef", to: key)
    let review = try ConnectionFileReview.read(key, as: .tailscale)
    try FileManager.default.removeItem(at: key)
    let fake = EnrollmentCommands(key: "", alreadyConnected: true)
    let client = HostTailscaleConnection(command: { try await fake.run($0) })
    do { _ = try await client.connect(using: review); XCTFail("Must not switch a connected Mac") }
    catch HostTailscaleFailure.alreadyConnected { }
    let calls = await fake.arguments; XCTAssertEqual(calls, [["status", "--json"]])
    XCTAssertFalse(FileManager.default.fileExists(atPath: file.path))
  }
}
private actor EnrollmentCommands {
  let key: String; let alreadyConnected: Bool
  var arguments: [[String]] = []
  init(key: String, alreadyConnected: Bool = false) { self.key = key; self.alreadyConnected = alreadyConnected }
  func run(_ args: [String]) throws -> Data {
    arguments.append(args)
    if args.first == "up" {
      let path = String(args[1].dropFirst("--auth-key=file:".count))
      XCTAssertEqual(try String(contentsOfFile: path, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines), key)
      XCTAssertEqual((try FileManager.default.attributesOfItem(atPath: path)[.posixPermissions] as? NSNumber)?.intValue, 0o600)
      return Data("ok".utf8)
    }
    return Data((alreadyConnected || arguments.count > 1 ? #"{"BackendState":"Running","CurrentTailnet":{"Name":"example.test"}}"# : #"{"BackendState":"NeedsLogin"}"#).utf8)
  }
}
#endif

#if os(macOS)
private actor PendingEnrollmentCommands {
  var keyPath: String?
  var calls = 0
  func count() -> Int { calls }
  func snapshotPath() -> String? { keyPath }
  func run(_ args: [String]) async throws -> Data {
    calls += 1
    if args.first == "status" { return Data(#"{"BackendState":"NeedsLogin"}"#.utf8) }
    keyPath = String(args[1].dropFirst("--auth-key=file:".count))
    try await Task.sleep(nanoseconds: 30_000_000_000)
    return Data()
  }
}
#endif
