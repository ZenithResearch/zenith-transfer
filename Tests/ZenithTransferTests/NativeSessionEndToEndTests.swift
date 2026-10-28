#if os(macOS)
import Foundation
import XCTest
import ZenithKit
@testable import ZenithTransfer

private actor SessionMCPHarness {
  private let child: Process
  private let input: FileHandle, output: FileHandle
  private var nextID = 0
  private var busy = false
  init(script: URL, directory: URL) throws {
    let child = Process(), stdin = Pipe(), stdout = Pipe()
    child.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
    child.arguments = ["-I", script.path, "--broker-directory", directory.path]
    child.standardInput = stdin; child.standardOutput = stdout; child.standardError = FileHandle.nullDevice
    try child.run(); self.child = child; input = stdin.fileHandleForWriting; output = stdout.fileHandleForReading
  }
  func stop() async {
    try? input.close()
    let child = self.child
    await Task.detached {
      let deadline = Date().addingTimeInterval(3)
      while child.isRunning && Date() < deadline { Thread.sleep(forTimeInterval: 0.01) }
      if child.isRunning { child.terminate() }
    }.value
  }
  func call(_ method: String, _ params: [String: Any]) async throws -> [String: Any] {
    guard !busy else { throw SessionReviewBridgeError.unavailable }
    busy = true; defer { busy = false }; nextID += 1; let id = nextID
    var data = try SessionReviewWire.encode(["jsonrpc":"2.0", "id":id, "method":method, "params":params]); data.append(10)
    let wire = data, child = self.child, input = self.input, output = self.output
    let response = try await Task.detached { () throws -> Data in
      let timeout = DispatchWorkItem { if child.isRunning { child.terminate() } }
      DispatchQueue.global().asyncAfter(deadline: .now() + 20, execute: timeout)
      defer { timeout.cancel() }
      try input.write(contentsOf: wire)
      var data = Data()
      while data.count < 65536 {
        guard let byte = try output.read(upToCount: 1), !byte.isEmpty else { throw SessionReviewBridgeError.unavailable }
        if byte[0] == 10 { return data }; data.append(byte)
      }
      throw SessionReviewBridgeError.invalid
    }.value
    let value = try SessionReviewWire.object(response)
    guard value["id"] as? Int == id, let result = value["result"] as? [String: Any] else { throw SessionReviewBridgeError.invalid }
    return result
  }
  func tool(_ name: String, _ args: [String: Any]) async throws -> [String: Any] {
    try await call("tools/call", ["name":name, "arguments":args])
  }
}

final class NativeSessionEndToEndTests: XCTestCase {
  private func sourceInventory(_ root: URL) throws -> [URL: String] {
    let enumerator = try XCTUnwrap(FileManager.default.enumerator(at: root, includingPropertiesForKeys: nil))
    var sources: [URL: String] = [:]
    for case let file as URL in enumerator where file.pathExtension == "py" {
      sources[file] = OwnerSetupPlan.sha256(try Data(contentsOf: file))
    }
    return sources
  }
  private func run(_ executable: URL, _ args: [String]) async throws {
    try await Task.detached {
      let child = Process()
      child.executableURL = executable; child.arguments = args
      child.standardInput = FileHandle.nullDevice; child.standardOutput = FileHandle.nullDevice; child.standardError = FileHandle.nullDevice
      try child.run(); child.waitUntilExit()
      guard child.terminationStatus == 0 else { throw SessionReviewBridgeError.unavailable }
    }.value
  }
  @MainActor func testRealNativeWalletMCPAndSessionCredentialReadWhenConfigured() async throws {
    let env = ProcessInfo.processInfo.environment
    let names = ["TRANSFER_SESSION_TEST_PYTHON", "TRANSFER_SESSION_TEST_GENERATOR", "TRANSFER_SESSION_TEST_PROVIDER", "TRANSFER_SESSION_TEST_BINARY", "TRANSFER_SESSION_TEST_HOLDER", "TRANSFER_SESSION_TEST_READ"]
    guard names.allSatisfy({ env[$0] != nil }) else { throw XCTSkip("Explicit matched native provider/custody/receiver executables required") }
    let root = URL(fileURLWithPath: "/tmp/session-native-" + UUID().uuidString.prefix(8))
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: root) }
    let suite = "NativeSessionE2E." + UUID().uuidString, defaults = UserDefaults(suiteName: suite)!
    defer { defaults.removePersistentDomain(forName: suite) }
    let model = TransferModel(directory: root.appendingPathComponent("app"), defaults: defaults)
    let repository = try XCTUnwrap(model.repository), password = "disposable native session qualification password"
    let owner = try await repository.create(password: password)
    let backup = try await repository.exportRecovery(password: password)
    _ = try await repository.verifyBackup(file: backup, password: password)
    await model.refresh()
    let ownerPublic = try XCTUnwrap(owner.publicKey)
    let python = URL(fileURLWithPath: env[names[0]]!)
    let generator = URL(fileURLWithPath: env[names[1]]!), script = URL(fileURLWithPath: env[names[2]]!)
    let fixture = root.appendingPathComponent("provider")
    try await run(python, ["-I", generator.path, "--directory", fixture.path, "--operator-public-key", ownerPublic,
      "--session-binary", env[names[3]]!, "--holder-binary", env[names[4]]!, "--read-binary", env[names[5]]!])
    let profileURL = fixture.appendingPathComponent("profile.json"), profileData = try Data(contentsOf: profileURL)
    let profile = try SessionReviewWire.object(profileData)
    XCTAssertEqual(profile["mode"] as? String, "disposable")
    let service = try XCTUnwrap(profile["service"] as? String)
    let pin = HolderIssuerPin(issuer: profile["issuer"] as! String, keyID: profile["key_id"] as! String,
      publicKey: profile["public_key"] as! String, service: service)
    let authority = try JSONDecoder().decode(ReadAuthorityPin.self, from: SessionReviewWire.encode([
      "issuer":pin.issuer, "key_id":pin.key_id, "public_key":pin.public_key, "receiver":profile["receiver"]!, "audience":"devgraph"]))
    let sourceRoot = script.deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("src/devgraph")
    var sources = try sourceInventory(sourceRoot)
    let venvConfiguration = python.deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("pyvenv.cfg")
    if FileManager.default.fileExists(atPath: venvConfiguration.path) { sources[venvConfiguration] = OwnerSetupPlan.sha256(try Data(contentsOf: venvConfiguration)) }
    let launch = SessionProviderLaunch(interpreter: python, script: script, profile: profileURL,
      interpreterSHA256: OwnerSetupPlan.sha256(try Data(contentsOf: python.resolvingSymlinksInPath())), scriptSHA256: OwnerSetupPlan.sha256(try Data(contentsOf: script)),
      profileSHA256: OwnerSetupPlan.sha256(profileData), sources: sources)
    let process = SessionProviderProcess(launch: launch)
    let wrongMode = LocalSessionReviewProvider(process: process, pin: pin, authority: authority,
      profileDigest: OwnerSetupPlan.sha256(try SessionReviewWire.encode(profile)), expectedMode: "production")
    do { _ = try await wrongMode.services(); XCTFail("Disposable provider cannot satisfy a production registration") }
    catch { /* No authority is activated by service discovery. */ }
    let provider = LocalSessionReviewProvider(process: process, pin: pin, authority: authority,
      profileDigest: OwnerSetupPlan.sha256(try SessionReviewWire.encode(profile)))
    let ipc = root.appendingPathComponent("ipc")
    let controller = TransferSessionReviewController(walletModel: model, directory: root.appendingPathComponent("journal"), defaults: defaults,
      provider: provider, socketDirectory: ipc, presentWindows: false)
    controller.setEnabled(true)
    let mcpScript = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
      .appendingPathComponent("Sources/ZenithTransfer/Resources/MCP/transfer_mcp.py")
    let mcp = try SessionMCPHarness(script: mcpScript, directory: ipc)
    do {
      _ = try await mcp.call("initialize", ["protocolVersion":"2025-03-26"])
      let discovered = try await mcp.tool("list_wallet_services", [:])
      XCTAssertEqual(discovered["isError"] as? Bool, false)
      let constraints: [String:Any] = ["scope":"devgraph.work.read", "operations":["get"], "relationship_types":["parent"], "work_kinds":["Task"], "include_archived":false, "work_ids":["Task/example-task"]]
      let permission: [String:Any] = ["operation":"devgraph.work.get", "resource":"https://work.zenith-research.ca/devgraph",
        "roles":[["role":"target", "selector":["schema":"secs.resource-selector.v1", "service":service, "kinds":["Task"], "selection":["mode":"objects", "refs":[["kind":"Task", "id":"example-task"]]]]]], "constraints":constraints]
      let requested = try await mcp.tool("request_session_credential", ["request_id":String(repeating:"12", count:16), "service":service,
        "permissions":[permission], "session_label":"Disposable Codex session", "purpose":"Read one disposable task", "lifetime_seconds":300])
      XCTAssertEqual(requested["isError"] as? Bool, false)
      let pending = try XCTUnwrap(requested["structuredContent"] as? [String:Any])
      XCTAssertEqual(pending["state"] as? String, "awaiting_human")
      XCTAssertTrue(pending["credential_handle"] is NSNull)
      let handle = try XCTUnwrap(pending["request_handle"] as? String)
      let first = try controller.review(handle)
      XCTAssertNotEqual(first.holderPublicKey, ownerPublic)
      let chosen = UInt64(Date().timeIntervalSince1970) + 180
      await controller.changeExpiry(chosen)
      let reviewed = try controller.review(handle)
      XCTAssertEqual(reviewed.expiresAt, chosen)
      XCTAssertNotEqual(reviewed.digest, first.digest)
      await controller.prepareNativeReview()
      XCTAssertNotNil(controller.consent, controller.error ?? "Expected real native verified consent")
      // Automated UI approval is confined to this NEW disposable Wallet/provider.
      // It never acts on an installed Wallet, real graph or production request.
      await controller.approveNativeReview(reviewedDigest: reviewed.digest, reviewedExpiry: reviewed.expiresAt)
      XCTAssertEqual(controller.records[handle]?.state, .issued, controller.error ?? "Expected isolated issuance")
      let issued = try await mcp.tool("get_session_credential_status", ["request_handle":handle])
      XCTAssertEqual(issued["isError"] as? Bool, false)
      let outcome = try XCTUnwrap(issued["structuredContent"] as? [String:Any])
      XCTAssertEqual(outcome["expires_at"] as? UInt64, chosen)
      let credential = try XCTUnwrap(outcome["credential_handle"] as? String)
      let otherMCP = try SessionMCPHarness(script: mcpScript, directory: ipc)
      _ = try await otherMCP.call("initialize", ["protocolVersion":"2025-03-26"])
      let crossedStatus = try await otherMCP.tool("get_session_credential_status", ["request_handle":handle])
      let crossedRead = try await otherMCP.tool("call_service_with_session_credential", ["credential_handle":credential,
        "operation":"devgraph.work.get", "resource":"https://work.zenith-research.ca/devgraph", "parameters":["kind":"Task", "work_id":"example-task"]])
      await otherMCP.stop()
      XCTAssertEqual(crossedStatus["isError"] as? Bool, true)
      XCTAssertEqual(crossedRead["isError"] as? Bool, true)
      await repository.lock(); await model.refresh()
      XCTAssertFalse(model.walletUnlocked)
      let read = try await mcp.tool("call_service_with_session_credential", ["credential_handle":credential,
        "operation":"devgraph.work.get", "resource":"https://work.zenith-research.ca/devgraph", "parameters":["kind":"Task", "work_id":"example-task"]])
      XCTAssertEqual(read["isError"] as? Bool, false)
      let response = try XCTUnwrap(read["structuredContent"] as? [String:Any])
      XCTAssertEqual((response["result"] as? [String:Any])?["title"] as? String, "Disposable example task")
      let denied = try await mcp.tool("call_service_with_session_credential", ["credential_handle":credential,
        "operation":"devgraph.work.get", "resource":"https://work.zenith-research.ca/devgraph", "parameters":["kind":"Task", "work_id":"hidden-task"]])
      XCTAssertEqual(denied["isError"] as? Bool, true)
      XCTAssertFalse(String(decoding: try SessionReviewWire.encode(denied), as: UTF8.self).contains("Outside the fixture grant"))
      _ = try await repository.unlock(password: password)
      let finalOwner = try await repository.state(), ownerGrants = try await repository.holderGrantSummaries()
      XCTAssertEqual(finalOwner.publicKey, ownerPublic)
      XCTAssertTrue(ownerGrants.isEmpty, "Session grant belongs in the session custody process, not the owner Wallet")
      await mcp.stop()
      let ended = try XCTUnwrap(controller.records[handle]?.clientID)
      XCTAssertTrue(controller.endedClients.contains(ended), "MCP EOF closes its private custody client")
      XCTAssertEqual(controller.records[handle]?.state, .issued, "Local key destruction is not server revocation")
      controller.stop(); await process.stop()
    } catch {
      await mcp.stop(); controller.stop(); await process.stop(); throw error
    }
  }
}
#endif
