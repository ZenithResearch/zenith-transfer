#if os(macOS)
import AppKit
import Foundation
import SwiftUI
import XCTest
import ZenithKit
@testable import ZenithTransfer

private let sessionTestNow: UInt64 = 2_000_000_000
private func sessionFixture() throws -> [String: Any] {
  let file = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
    .appendingPathComponent("ZenithKitTests/Fixtures/session-access-review-v1.json")
  return try SessionReviewWire.object(Data(contentsOf: file))
}
private actor FixtureSessionProvider: SessionReviewProvider {
  var preparations = 0
  var submissions = 0
  func closeClient(_ clientID: String) async throws {}
  func services() async throws -> [SessionReviewService] {
    [.init(service: "urn:zenith:service:example-devgraph", name: "Disposable test provider", readAvailable: true, writeAvailable: false)]
  }
  func preparation(_ name: String) throws -> SessionReviewPreparation {
    let b = try sessionFixture(), cap = b["simulated_read_qualified"] as! [String: Any]
    let raw = b[name] as! [String: Any], manifest = raw["manifest"] as! [String: Any]
    let provider = manifest["provider"] as! [String: Any]
    let pin: [String: Any] = ["issuer": provider["issuer"]!, "key_id": provider["key_id"]!, "public_key": provider["public_key"]!, "receiver": "https://example.invalid", "audience": "devgraph"]
    return try .init(review: SessionReviewWire.encode(raw), capabilities: SessionReviewWire.encode(cap), trustedProvider: SessionReviewWire.encode(provider),
      holder: SessionReviewWire.encode(manifest["holder"]!), authority: JSONDecoder().decode(ReadAuthorityPin.self, from: SessionReviewWire.encode(pin)))
  }
  func prepare(clientID: String, request: Data) async throws -> SessionReviewPreparation {
    preparations += 1; return try preparation("initial_review")
  }
  func updateExpiry(_ preparation: SessionReviewPreparation, expiresAt: UInt64) async throws -> SessionReviewPreparation {
    try self.preparation("expiry_adjusted_review")
  }
  func ownerChallenge(_ preparation: SessionReviewPreparation, ownerIdentity: Data) async throws -> Data { throw SessionAccessReviewError.unavailable }
  func submit(_ preparation: SessionReviewPreparation, ownerProof: Data) async throws -> Data { submissions += 1; throw SessionAccessReviewError.unavailable }
  func reconcile(_ preparation: SessionReviewPreparation) async throws -> Data {
    let review = try preparation.checked(now: sessionTestNow, retained: true)
    return try SessionReviewWire.publicOutcome(review, state: .outcomeUnknown)
  }
  func counts() -> (Int, Int) { (preparations, submissions) }
}

final class SessionReviewBridgeTests: XCTestCase {
  func testRegistrationPinsSourcesAndRejectsUnsafeOrSubstitutedFiles() throws {
    let root = try directory("session-registration")
    defer { try? FileManager.default.removeItem(at: root) }
    let fixture = URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("Fixtures/session-provider-registration-v1.json")
    var raw = try SessionReviewWire.object(Data(contentsOf: fixture))
    _ = try SessionProviderRegistration.decode(SessionReviewWire.encode(raw))
    let script = root.appendingPathComponent("provider.py"), profile = root.appendingPathComponent("profile.dat"), source = root.appendingPathComponent("source.py")
    for file in [script, profile, source] {
      try Data("example".utf8).write(to: file)
      try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
    }
    func filePin(_ file: URL) throws -> [String:Any] { ["path":file.path, "sha256":OwnerSetupPlan.sha256(try Data(contentsOf: file))] }
    raw["launch"] = try ["interpreter":filePin(URL(fileURLWithPath:"/usr/bin/true")), "script":filePin(script), "profile":filePin(profile), "sources":[filePin(source)]]
    let descriptor = root.appendingPathComponent("provider.json"), bytes = try SessionReviewWire.encode(raw)
    try bytes.write(to: descriptor); try FileManager.default.setAttributes([.posixPermissions:0o600], ofItemAtPath:descriptor.path)
    XCTAssertNotNil(try SessionProviderRegistration.loadIfPresent(directory: root))
    XCTAssertTrue(try SessionReviewJournal(directory: root).load().isEmpty, "Provider registration is not a recovery record")
    try Data("substituted".utf8).write(to: source)
    XCTAssertThrowsError(try SessionProviderRegistration.loadIfPresent(directory: root))
    try FileManager.default.setAttributes([.posixPermissions:0o644], ofItemAtPath:descriptor.path)
    XCTAssertThrowsError(try SessionProviderRegistration.loadIfPresent(directory: root))
    var bad = raw; bad["endpoint"] = "https://untrusted.invalid"
    XCTAssertThrowsError(try SessionProviderRegistration.decode(SessionReviewWire.encode(bad)))
    for address in ["https://example.invalid/path", "https://example.invalid?route=other", "https://example.invalid/#other"] {
      bad = raw; var receiver = raw["receiver_pin"] as! [String:Any]; receiver["receiver"] = address; bad["receiver_pin"] = receiver
      XCTAssertThrowsError(try SessionProviderRegistration.decode(SessionReviewWire.encode(bad)))
    }
    var launch = raw["launch"] as! [String:Any]
    launch["sources"] = [try filePin(script), try filePin(script)]; bad = raw; bad["launch"] = launch
    XCTAssertThrowsError(try SessionProviderRegistration.decode(SessionReviewWire.encode(bad)))
  }
  func testCodexConfigurationPointsToPackagedResourceAndUsesTOML() throws {
    let resources = try XCTUnwrap(Bundle.module.resourceURL)
    // The test bundle has fixtures; the executable's bundle is alongside it.
    let executableResources = resources.deletingLastPathComponent().appendingPathComponent("ZenithKit_ZenithTransfer.bundle")
    let script = try TransferMCPConfiguration.script(resourceDirectory: executableResources)
    XCTAssertTrue(script.path.hasSuffix("Resources/MCP/transfer_mcp.py"))
    let config = try TransferMCPConfiguration.codex(resourceDirectory: executableResources)
    XCTAssertTrue(config.hasPrefix("[mcp_servers.zenith_transfer_wallet]\n"))
    XCTAssertTrue(config.contains("command = \"/usr/bin/python3\""))
    XCTAssertTrue(config.contains("\"-I\""))
    XCTAssertFalse(config.contains("mcpServers"))
    XCTAssertThrowsError(try TransferMCPConfiguration.script(resourceDirectory: executableResources.appendingPathComponent("missing")))
  }
  func directory(_ prefix: String) throws -> URL {
    let path = URL(fileURLWithPath: "/tmp/" + prefix + "-" + UUID().uuidString.prefix(8))
    try FileManager.default.createDirectory(at: path, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    return path
  }
  func request() throws -> Data {
    let b = try sessionFixture(), m = (b["initial_review"] as! [String: Any])["manifest"] as! [String: Any]
    return try SessionReviewWire.encode(["request_id": m["request_id"]!, "service": (m["provider"] as! [String: Any])["service"]!,
      "permissions": m["permissions"]!, "session_label": "Example coding session", "purpose": "Read one task"])
  }
  @MainActor func testRequestIsIdempotentClientBoundAndDoesNotIssue() async throws {
    let root = try directory("session-broker"), socket = root.appendingPathComponent("ipc")
    defer { try? FileManager.default.removeItem(at: root) }
    let suite = "SessionBroker." + UUID().uuidString, defaults = UserDefaults(suiteName: suite)!
    defer { defaults.removePersistentDomain(forName: suite) }
    let provider = FixtureSessionProvider()
    let controller = TransferSessionReviewController(walletModel: nil, directory: root.appendingPathComponent("journal"), defaults: defaults,
      provider: provider, socketDirectory: socket, presentWindows: false, clock: { sessionTestNow })
    controller.setEnabled(true); defer { controller.stop() }
    let client = String(repeating: "ab", count: 16)
    let first = try await controller.exchange(client: client, method: "request_review", params: request())
    let second = try await controller.exchange(client: client, method: "request_review", params: request())
    XCTAssertEqual(first, second)
    let result = try SessionReviewWire.object(first)
    XCTAssertEqual(result["state"] as? String, "awaiting_human")
    XCTAssertTrue(result["credential_handle"] is NSNull)
    let counts = await provider.counts(); XCTAssertEqual(counts.0, 1); XCTAssertEqual(counts.1, 0)
    do {
      _ = try await controller.exchange(client: String(repeating: "cd", count: 16), method: "get_result", params: SessionReviewWire.encode(["request_handle": "request_example"]))
      XCTFail("Another MCP process cannot retrieve this request")
    } catch { }
    do { _ = try await controller.exchange(client: client, method: "approve", params: Data("{}".utf8)); XCTFail("No exported approval method") } catch { }
    var changed = try SessionReviewWire.object(request()); changed["purpose"] = "Changed request"
    do { _ = try await controller.exchange(client: client, method: "request_review", params: SessionReviewWire.encode(changed)); XCTFail("ID cannot be rebound") } catch { }
    controller.declineNativeReview()
    let declined = try SessionReviewWire.object(controller.publicResult("request_example"))
    XCTAssertEqual(declined["state"] as? String, "denied")
    XCTAssertFalse(controller.records["request_example"]!.dispatched)
  }
  @MainActor func testExpiryAndDurableDispatchFenceSurviveRestart() async throws {
    let root = try directory("session-journal"), socket = root.appendingPathComponent("ipc")
    defer { try? FileManager.default.removeItem(at: root) }
    let suite = "SessionJournal." + UUID().uuidString, defaults = UserDefaults(suiteName: suite)!
    defer { defaults.removePersistentDomain(forName: suite) }
    let provider = FixtureSessionProvider(), journalURL = root.appendingPathComponent("journal")
    let controller = TransferSessionReviewController(walletModel: nil, directory: journalURL, defaults: defaults,
      provider: provider, socketDirectory: socket, presentWindows: false, clock: { sessionTestNow })
    controller.setEnabled(true)
    let client = String(repeating: "ab", count: 16)
    _ = try await controller.exchange(client: client, method: "request_review", params: request())
    await controller.changeExpiry(sessionTestNow + 1800)
    let previous = try XCTUnwrap(controller.records["request_example"])
    XCTAssertEqual(try controller.review("request_example").expiresAt, sessionTestNow + 1800)
    var dispatched = previous; dispatched.version += 1; dispatched.dispatched = true; dispatched.state = .submitting
    let journal = try SessionReviewJournal(directory: journalURL)
    try journal.save(dispatched, replacing: previous)
    controller.stop()
    let restored = TransferSessionReviewController(walletModel: nil, directory: journalURL, defaults: defaults,
      provider: provider, socketDirectory: socket, presentWindows: false, clock: { sessionTestNow })
    restored.setEnabled(true); defer { restored.stop() }
    _ = try await restored.exchange(client: client, method: "request_review", params: request())
    XCTAssertTrue(restored.records["request_example"]!.dispatched)
    XCTAssertEqual(try SessionReviewWire.object(restored.publicResult("request_example"))["state"] as? String, "outcome_unknown")
    await restored.changeExpiry(sessionTestNow + 3600)
    XCTAssertEqual(try restored.review("request_example").expiresAt, sessionTestNow + 1800)
    let counts = await provider.counts(); XCTAssertEqual(counts.0, 1); XCTAssertEqual(counts.1, 0)
    var attemptedRewrite = previous; attemptedRewrite.version = dispatched.version + 1
    XCTAssertThrowsError(try journal.save(attemptedRewrite, replacing: dispatched))
  }
  @MainActor func testActualMCPSubprocessUsesPrivateSocketAndCannotApprove() async throws {
    let root = try directory("session-mcp"), socket = root.appendingPathComponent("ipc")
    defer { try? FileManager.default.removeItem(at: root) }
    let suite = "SessionMCP." + UUID().uuidString, defaults = UserDefaults(suiteName: suite)!
    defer { defaults.removePersistentDomain(forName: suite) }
    let provider = FixtureSessionProvider()
    let controller = TransferSessionReviewController(walletModel: nil, directory: root.appendingPathComponent("journal"), defaults: defaults,
      provider: provider, socketDirectory: socket, presentWindows: false, clock: { sessionTestNow })
    controller.setEnabled(true); defer { controller.stop() }
    let args = try SessionReviewWire.object(request())
    let messages: [[String: Any]] = [
      ["jsonrpc":"2.0", "id":1, "method":"initialize", "params":["protocolVersion":"2025-03-26"]],
      ["jsonrpc":"2.0", "method":"notifications/initialized"],
      ["jsonrpc":"2.0", "id":2, "method":"tools/list"],
      ["jsonrpc":"2.0", "id":3, "method":"tools/call", "params":["name":"list_wallet_services", "arguments":[:]]],
      ["jsonrpc":"2.0", "id":4, "method":"tools/call", "params":["name":"request_session_credential", "arguments":args]],
      ["jsonrpc":"2.0", "id":5, "method":"tools/call", "params":["name":"get_session_credential_status", "arguments":["request_handle":"request_example"]]],
      ["jsonrpc":"2.0", "id":6, "method":"tools/call", "params":["name":"approve", "arguments":[:]]]
    ]
    let input = try messages.reduce(into: Data()) { data, value in data.append(try SessionReviewWire.encode(value)); data.append(10) }
    let script = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
      .appendingPathComponent("Sources/ZenithTransfer/Resources/MCP/transfer_mcp.py")
    let output = try await Task.detached { () throws -> Data in
      let process = Process(), stdin = Pipe(), stdout = Pipe()
      process.executableURL = URL(fileURLWithPath: "/usr/bin/python3"); process.arguments = ["-I", script.path, "--broker-directory", socket.path]
      process.standardInput = stdin; process.standardOutput = stdout; process.standardError = FileHandle.nullDevice
      try process.run(); try stdin.fileHandleForWriting.write(contentsOf: input); try stdin.fileHandleForWriting.close()
      let result = stdout.fileHandleForReading.readDataToEndOfFile(); process.waitUntilExit()
      guard process.terminationStatus == 0 else { throw SessionReviewBridgeError.unavailable }; return result
    }.value
    let rows = try output.split(separator: 10).map { try SessionReviewWire.object(Data($0)) }
    XCTAssertEqual(rows.count, 6)
    let tools = ((rows[1]["result"] as! [String: Any])["tools"] as! [[String: Any]]).map { $0["name"] as! String }
    XCTAssertEqual(Set(tools), ["list_wallet_services", "request_session_credential", "get_session_credential_status", "call_service_with_session_credential"])
    let pending = (rows[3]["result"] as! [String: Any])["structuredContent"] as! [String: Any]
    XCTAssertEqual(pending["state"] as? String, "awaiting_human")
    XCTAssertTrue(pending["credential_handle"] is NSNull)
    XCTAssertEqual((rows[5]["result"] as! [String: Any])["isError"] as? Bool, true)
    let counts = await provider.counts(); XCTAssertEqual(counts.0, 1); XCTAssertEqual(counts.1, 0)
    XCTAssertFalse(String(decoding: output, as: UTF8.self).contains("pairing-token"))
  }
  func testUnsafeSocketDirectoryAndDuplicateServerAreRejected() throws {
    let root = try directory("session-socket")
    defer { try? FileManager.default.removeItem(at: root) }
    let server = SessionReviewSocket(directory: root) { _,_,_ in Data("{}".utf8) }
    try server.start(); defer { server.stop() }
    let duplicate = SessionReviewSocket(directory: root) { _,_,_ in Data("{}".utf8) }
    XCTAssertThrowsError(try duplicate.start())
    let linked = root.appendingPathComponent("link")
    try FileManager.default.createSymbolicLink(at: linked, withDestinationURL: root)
    let unsafe = SessionReviewSocket(directory: linked) { _,_,_ in Data("{}".utf8) }
    XCTAssertThrowsError(try unsafe.start())
  }
  func testSocketTokenCannotTruncateAHardLinkedFile() throws {
    let root = try directory("session-hardlink")
    defer { try? FileManager.default.removeItem(at: root) }
    let protected = root.appendingPathComponent("protected")
    try Data("DO-NOT-CHANGE".utf8).write(to: protected)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: protected.path)
    try FileManager.default.linkItem(at: protected, to: root.appendingPathComponent("pairing-token"))
    let server = SessionReviewSocket(directory: root) { _,_,_ in Data("{}".utf8) }
    XCTAssertThrowsError(try server.start())
    XCTAssertEqual(try Data(contentsOf: protected), Data("DO-NOT-CHANGE".utf8))
  }
  @MainActor func testNativePopupRenderWhenRequested() async throws {
    guard let output = ProcessInfo.processInfo.environment["TRANSFER_SESSION_REVIEW_RENDER"] else { throw XCTSkip("Optional offscreen native session review render") }
    let root = try directory("session-render")
    defer { try? FileManager.default.removeItem(at: root) }
    let suite = "SessionRender." + UUID().uuidString, defaults = UserDefaults(suiteName: suite)!
    defer { defaults.removePersistentDomain(forName: suite) }
    let model = TransferModel(directory: root.appendingPathComponent("app"), defaults: defaults)
    let controller = TransferSessionReviewController(walletModel: model, directory: root.appendingPathComponent("journal"), defaults: defaults,
      provider: FixtureSessionProvider(), socketDirectory: root.appendingPathComponent("ipc"), presentWindows: false, clock: { sessionTestNow })
    controller.setEnabled(true); defer { controller.stop() }
    _ = try await controller.exchange(client: String(repeating: "ab", count: 16), method: "request_review", params: request())
    _ = NSApplication.shared
    let view = NSHostingView(rootView: TransferSessionReviewView(controller: controller, walletModel: model)
      .background(Color(nsColor: .windowBackgroundColor)).environment(\.colorScheme, .light))
    view.frame = NSRect(x: 0, y: 0, width: 760, height: 800)
    let window = NSWindow(contentRect: view.frame, styleMask: .borderless, backing: .buffered, defer: false)
    window.contentView = view; view.layoutSubtreeIfNeeded()
    defer { window.contentView = nil; window.orderOut(nil) }
    try await Task.sleep(nanoseconds: 200_000_000)
    let bitmap = try XCTUnwrap(view.bitmapImageRepForCachingDisplay(in: view.bounds))
    view.cacheDisplay(in: view.bounds, to: bitmap)
    try XCTUnwrap(bitmap.representation(using: .png, properties: [:])).write(to: URL(fileURLWithPath: output))
    XCTAssertNotNil(controller.active)
    XCTAssertFalse(model.walletUnlocked)
    XCTAssertTrue(controller.records.values.allSatisfy { !$0.dispatched && $0.state == .awaitingHuman })
  }
}
#endif
