#if os(macOS)
import Foundation
import Security
import XCTest
@testable import CastaliaCustody
@testable import ZenithKit

/// Explicitly selected disposable receiver only. Never imports host profiles,
/// opens a production graph, reuses a personal Wallet or grants live access.
final class HolderSessionReceiverIntegrationTests: XCTestCase {
  private func sourceInventory(script: URL, authority: URL, read: URL) throws -> [URL: String] {
    let sourceRoot = script.deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("src")
    var sources: [URL: String] = [script: HS.digest(try Data(contentsOf: script))]
    let enumerator = try XCTUnwrap(FileManager.default.enumerator(at: sourceRoot, includingPropertiesForKeys: [.isRegularFileKey]))
    for case let file as URL in enumerator where file.pathExtension == "py" {
      sources[file] = HS.digest(try Data(contentsOf: file))
    }
    sources[authority] = HS.digest(try Data(contentsOf: authority)); sources[read] = HS.digest(try Data(contentsOf: read))
    return sources
  }
  private struct Harness {
    let directory: URL, fixtureDirectory: URL, profile: URL
    let pin: HolderIssuerPin, context: HolderSessionContext
    let wallet: WalletRepository, observedWallet: ObservedHolderWallet
    let issuer: LocalHolderSessionIssuer, process: SessionProviderProcess
    let custody: RecordingHolderCustody
    let droppedReply: DropHolderReply?
    let flow: HolderSessionFlow, call: Data
  }
  private func setup(lifetime: UInt64, dropReply: Bool = false, nativeCustody: Bool = false, approve: Bool = true, origin: String = "app://zenith-transfer") async throws -> Harness {
    let env = ProcessInfo.processInfo.environment
    func selected(_ key: String) throws -> URL {
      guard let value = env[key], value.hasPrefix("/") else { throw XCTSkip("Explicit disposable receiver inputs required: " + key) }
      return URL(fileURLWithPath: value)
    }
    let python = try selected("HOLDER_SESSION_DG_TEST_PYTHON")
    let script = try selected("HOLDER_SESSION_DG_TEST_FIXTURE")
    let authority = try selected("HOLDER_SESSION_DG_TEST_AUTHORITY")
    let read = try selected("HOLDER_SESSION_DG_TEST_READ_AUTHORITY")
    let agentBinary = try selected("HOLDER_SESSION_AGENT_TEST_BINARY")
    let directory = URL(fileURLWithPath: "/private/tmp", isDirectory: true).appendingPathComponent("holder-receiver-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    var ownedProcess: SessionProviderProcess?, ownedCustody: RecordingHolderCustody?
    do {
    let fixtureDirectory = directory.appendingPathComponent("issuer", isDirectory: true)
    let wallet = try WalletRepository(directory: directory.appendingPathComponent("wallet"), holderSessionCoreQualified: true)
    let password = "disposable receiver qualification password"
    let state = try await wallet.create(password: password)
    let backup = try await wallet.exportRecovery(password: password)
    _ = try await wallet.verifyBackup(file: backup, password: password)
    let child = Process(), output = Pipe(), errors = Pipe()
    child.executableURL = python
    child.arguments = ["-I", script.path, "--directory", fixtureDirectory.path,
      "--holder-public-key", try XCTUnwrap(state.publicKey), "--holder-binary", authority.path,
      "--read-binary", read.path, "--origin", origin]
    child.environment = ["PATH": "/usr/bin:/bin"]
    child.standardOutput = output; child.standardError = errors
    let timeout = DispatchWorkItem { if child.isRunning { child.terminate() } }
    DispatchQueue.global().asyncAfter(deadline: .now() + 15, execute: timeout)
    defer { timeout.cancel() }
    try child.run(); child.waitUntilExit()
    guard child.terminationStatus == 0 else {
      let code = child.terminationStatus
      throw NSError(domain: "DisposableHolderFixture", code: Int(code), userInfo: [NSLocalizedDescriptionKey: "Disposable receiver setup failed; no production fallback"])
    }
    let setup = try HS.object(try XCTUnwrap(output.fileHandleForReading.readToEnd()))
    let pin = try HS.pin(setup["provider"]), context = try JSONDecoder().decode(HolderSessionContext.self, from: HS.encode(setup["context"]!))
    let parentFile = URL(fileURLWithPath: try XCTUnwrap(setup["parent"] as? String))
    let parentData = try Data(contentsOf: parentFile)
    let now = UInt64(Date().timeIntervalSince1970)
    let parentReview = try await wallet.reviewHolderGrant(parentData, pin: pin, now: now)
    try await wallet.saveHolderGrant(parentReview, now: now)
    let profile = URL(fileURLWithPath: try XCTUnwrap(setup["profile"] as? String))
    // Pin the actual first-party source closure before starting the interpreter.
    let sources = try sourceInventory(script: script, authority: authority, read: read)
    let process = SessionProviderProcess(launch: .init(interpreter: python, script: script, profile: profile,
      interpreterSHA256: HS.digest(try Data(contentsOf: python)), scriptSHA256: sources[script]!,
      profileSHA256: HS.digest(try Data(contentsOf: profile)), sources: sources))
    ownedProcess = process
    let client = String(repeating: "ab", count: 16)
    let issuer = try LocalHolderSessionIssuer(process: process, clientID: client, pin: pin, context: context)
    let services = try await issuer.services()
    XCTAssertEqual(services.count, 1); XCTAssertEqual(services.first?.service, pin.service)
    let agentProfile = directory.appendingPathComponent("agent.json")
    let agentBytes = try HS.encode(["schema": "castalia.holder-session-agent-profile.v1",
      "provider": HS.object(JSONEncoder().encode(pin)), "context": setup["context"]!, "maximum_session_seconds": 300])
    try agentBytes.write(to: agentProfile)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: agentProfile.path)
    let agent = HolderSessionAgentProcess(launch: .init(executable: agentBinary, profileFile: agentProfile,
      executableSHA256: HS.digest(try Data(contentsOf: agentBinary)), profileSHA256: HS.digest(agentBytes)))
    let selectedCustody: any HolderSessionCustody = nativeCustody ? try NativeHolderSessionCustody(profileData: agentBytes) : agent
    let custody = RecordingHolderCustody(agent: selectedCustody), observed = ObservedHolderWallet(wallet: wallet)
    ownedCustody = custody
    let dropping = dropReply ? DropHolderReply(issuer: issuer) : nil
    let selectedIssuer: any HolderSessionIssuer = dropping.map { $0 as any HolderSessionIssuer } ?? issuer
    let flow = try HolderSessionFlow(clientID: client, requestID: UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased(),
      service: pin.service, context: context, wallet: observed, custody: custody,
      issuer: selectedIssuer,
      journal: HolderSessionJournal(directory: directory.appendingPathComponent("journal")))
    let challenge = try await flow.prepare(permissions: nil, lifetime: lifetime, maximumSessionSeconds: try XCTUnwrap(services.first).maximumTTL)
    if approve {
      _ = try await flow.prepareNativeReview()
      try await flow.approveNativeReview(digest: challenge.digest, expiresAt: challenge.expiresAt)
    }
    let permission = try XCTUnwrap(challenge.permissions.first { $0.operation == "devgraph.work.list" })
    let call = try HS.encode(["operation": permission.operation, "resource": permission.resource,
      "parameters": ["path": "/todos/v2?kind=Task"]])
    return Harness(directory: directory, fixtureDirectory: fixtureDirectory, profile: profile, pin: pin, context: context, wallet: wallet, observedWallet: observed,
      issuer: issuer, process: process, custody: custody, droppedReply: dropping, flow: flow, call: call)
    } catch {
      await ownedCustody?.stop(); await ownedProcess?.stop()
      try? FileManager.default.removeItem(at: directory)
      throw error
    }
  }
  private func cleanup(_ h: Harness) async {
    try? await h.flow.close(); await h.process.stop()
    try? FileManager.default.removeItem(at: h.directory)
  }
  func testActualReceiverRootLockReplayOriginalStatusAndRevocation() async throws { try await exerciseReceiver(nativeCustody: false) }
  func testPortableNativeCustodyReceiverRecoveryRootLockAndRevocation() async throws { try await exerciseReceiver(nativeCustody: true) }
  private func exerciseReceiver(nativeCustody: Bool) async throws {
    let h = try await setup(lifetime: 60, dropReply: true, nativeCustody: nativeCustody)
    do {
      let unknown = await h.flow.currentPhase(); XCTAssertEqual(unknown, .outcomeUnknown)
      let preparedChallenge = await h.flow.reviewedChallenge(), challenge = try XCTUnwrap(preparedChallenge)
      await h.wallet.lock(); let count = await h.observedWallet.calls()
      let originalResult = await h.droppedReply?.originalIssuedCredential(), originalIssued = try XCTUnwrap(originalResult)
      try await h.flow.checkOriginalResult()
      let installed = await h.custody.installedCredential()
      XCTAssertEqual(installed, originalIssued, "Recovery must return the byte-exact original finite credential")
      let offered = await h.flow.publicCredentialHandle(), handle = try XCTUnwrap(offered)
      for _ in 0..<2 {
        let data = try await h.flow.execute(client: String(repeating: "ab", count: 16), handle: handle, call: h.call)
        let value = try HS.object(data), items = try XCTUnwrap(value["items"] as? [[String: Any]])
        XCTAssertEqual(items.compactMap { $0["key"] as? String }, ["Task/allowed-1"])
      }
      let originalPresentation = await h.custody.lastPresentation(), replay = try XCTUnwrap(originalPresentation)
      do { _ = try await h.issuer.execute(replay); XCTFail("Receiver must reject replay") } catch { }
      // A denied replay cannot renew or replace the original credential.
      try await h.flow.checkOriginalResult()
      let retained = await h.flow.reviewedChallenge(); XCTAssertEqual(retained?.expiresAt, challenge.expiresAt)
      let after = await h.observedWallet.calls(); XCTAssertEqual(after, count, "No root use or second approval")
      let approvals = await h.observedWallet.approvalCount(); XCTAssertEqual(approvals, 1)
      try Data().write(to: h.fixtureDirectory.appendingPathComponent("REVOKE"))
      do { _ = try await h.flow.execute(client: String(repeating: "ab", count: 16), handle: handle, call: h.call); XCTFail("Current parent revocation must reject") } catch { }
      try await h.flow.checkOriginalResult()
      let phase = await h.flow.currentPhase(); XCTAssertEqual(phase, .revoked)
      let unavailable = await h.flow.publicCredentialHandle(); XCTAssertNil(unavailable)
      await cleanup(h)
    } catch { await cleanup(h); throw error }
  }
  @MainActor func testPortableNativeSignerEditsAndReadsThroughActualHTTPSReceiver() async throws {
    let h = try await setup(lifetime: 60, nativeCustody: true, approve: false, origin: "app://zenith-ios")
    let env = ProcessInfo.processInfo.environment, server = Process(), output = Pipe()
    var transport: PrivateTransport?
    do {
      server.executableURL = URL(fileURLWithPath: try XCTUnwrap(env["HOLDER_SESSION_DG_TEST_PYTHON"]))
      server.arguments = ["-I", try XCTUnwrap(env["HOLDER_SESSION_DG_TEST_FIXTURE"]), "--profile-file", h.profile.path, "--https"]
      server.environment = ["PATH": "/usr/bin:/bin"]; server.standardOutput = output; server.standardError = Pipe()
      let timeout = DispatchWorkItem { if server.isRunning { server.terminate() } }
      DispatchQueue.global().asyncAfter(deadline: .now() + 15, execute: timeout)
      try server.run()
      var line = Data()
      while line.count < 16384, let byte = try output.fileHandleForReading.read(upToCount: 1), !byte.isEmpty {
        if byte == Data([10]) { break }; line.append(byte)
      }
      timeout.cancel()
      let info = try HS.object(line), address = try XCTUnwrap(info["base_url"] as? String)
      let certificate = try String(contentsOfFile: XCTUnwrap(info["certificate"] as? String), encoding: .utf8)
      let body = certificate.split(separator: "\n").filter { !$0.hasPrefix("-----") }.joined()
      let der = try XCTUnwrap(Data(base64Encoded: body))
      let c = try WorkAccessConfiguration(name: "Disposable HTTPS fixture", receiver: XCTUnwrap(URL(string: address)), issuer: h.pin.issuer,
        keyID: h.pin.key_id, publicKey: h.pin.public_key, network: .local, tlsCertificateSHA256: HS.digest(der))
      let leaf = try XCTUnwrap(SecCertificateCreateWithData(nil, der as CFData))
      var trust: SecTrust?
      XCTAssertEqual(SecTrustCreateWithCertificates(leaf, SecPolicyCreateSSL(true, "127.0.0.1" as CFString), &trust), errSecSuccess)
      let selectedTrust = try XCTUnwrap(trust)
      let accepted = try LANServerTrust(configuration: c).accepts(selectedTrust, host: "127.0.0.1", port: c.receiver.port!)
      var trustError: CFError?
      _ = SecTrustEvaluateWithError(selectedTrust, &trustError)
      XCTAssertTrue(accepted, "Fixture certificate: \(String(describing: trustError))")
      let http = try PrivateTransport(workServer: c); transport = http
      var found: HolderSessionCapabilities?
      var lastDiscoveryError: Error?
      for _ in 0..<30 {
        do { found = try await HTTPSHolderSessionIssuer.discover(transport: http, configuration: c); break }
        catch { lastDiscoveryError = error; try await Task.sleep(nanoseconds: 100_000_000) }
      }
      let caps = try XCTUnwrap(found, "Discovery: \(String(describing: lastDiscoveryError))"), client = String(repeating: "ac", count: 16)
      let model = try HolderSessionReviewModel(service: caps.provider.service, label: "Synthetic iOS native review", purpose: "Actual HTTPS scoped read", maximumLifetime: caps.maximumLifetime) {
        try HolderSessionFlow(clientID: client, requestID: UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased(),
          service: caps.provider.service, context: caps.context, wallet: h.observedWallet,
          custody: NativeHolderSessionCustody(profileData: caps.custodyProfile),
          issuer: HTTPSHolderSessionIssuer(transport: http, configuration: c, capabilities: caps),
          journal: HolderSessionJournal(directory: h.directory.appendingPathComponent("https-journal")))
      }
      await model.prepare(lifetime: 60)
      let old = try XCTUnwrap(model.challenge)
      await model.prepare(lifetime: 120)
      let reviewed = try XCTUnwrap(model.challenge)
      XCTAssertNotEqual(old.intent.requestID, reviewed.intent.requestID)
      XCTAssertNotEqual(old.intent.session.publicKey, reviewed.intent.session.publicKey)
      XCTAssertGreaterThan(reviewed.expiresAt, old.expiresAt)
      await model.approve(digest: reviewed.digest, expiresAt: reviewed.expiresAt)
      XCTAssertEqual(model.phase, .issued, model.error ?? "")
      let handle = try XCTUnwrap(model.credentialHandle)
      await h.wallet.lock(); let before = await h.observedWallet.calls()
      for _ in 0..<2 {
        let bytes = try await model.execute(client: client, handle: handle, call: h.call)
        let result = String(decoding: bytes, as: UTF8.self)
        XCTAssertTrue(result.contains("allowed-1")); XCTAssertFalse(result.contains("Task/hidden"))
      }
      await model.checkOriginalResult()
      await model.approve(digest: reviewed.digest, expiresAt: reviewed.expiresAt)
      let after = await h.observedWallet.calls(), approvals = await h.observedWallet.approvalCount()
      XCTAssertEqual(before, after); XCTAssertEqual(approvals, 1)
      XCTAssertEqual(model.challenge?.expiresAt, reviewed.expiresAt)
      try Data().write(to: h.fixtureDirectory.appendingPathComponent("REVOKE"))
      await model.checkOriginalResult(); XCTAssertEqual(model.phase, .revoked); XCTAssertNil(model.credentialHandle)
      await model.close(); http.cancel()
      if server.isRunning { server.terminate(); server.waitUntilExit() }
      await cleanup(h)
    } catch {
      transport?.cancel(); if server.isRunning { server.terminate(); server.waitUntilExit() }
      await cleanup(h); throw error
    }
  }
  func testActualReceiverAndClientRejectAtFixedExpiryWithoutNewApproval() async throws {
    let h = try await setup(lifetime: 8)
    do {
      let offered = await h.flow.publicCredentialHandle(), handle = try XCTUnwrap(offered)
      _ = try await h.flow.execute(client: String(repeating: "ab", count: 16), handle: handle, call: h.call)
      let originalPresentation = await h.custody.lastPresentation(), presentation = try XCTUnwrap(originalPresentation)
      let preparedChallenge = await h.flow.reviewedChallenge(), challenge = try XCTUnwrap(preparedChallenge)
      await h.wallet.lock(); let count = await h.observedWallet.calls()
      let now = Date().timeIntervalSince1970
      if Double(challenge.expiresAt) > now {
        try await Task.sleep(nanoseconds: UInt64((Double(challenge.expiresAt) - now + 0.1) * 1_000_000_000))
      }
      do { _ = try await h.issuer.execute(presentation); XCTFail("Receiver rejects expired original proof/token") } catch { }
      do { _ = try await h.flow.execute(client: String(repeating: "ab", count: 16), handle: handle, call: h.call); XCTFail("Client cannot renew or call after end") } catch { }
      let after = await h.observedWallet.calls(); XCTAssertEqual(after, count)
      let phase = await h.flow.currentPhase(); XCTAssertEqual(phase, .expired)
      await cleanup(h)
    } catch { await cleanup(h); throw error }
  }
}

private actor ObservedHolderWallet: HolderSessionWalletPort {
  private let port: NativeHolderSessionWalletPort
  private var count = 0
  private var approvals = 0
  init(wallet: WalletRepository) { port = .init(wallet: wallet) }
  func calls() -> Int { count }
  func approvalCount() -> Int { approvals }
  func parent(service: String, now: UInt64) async throws -> HolderSessionParentReference { count += 1; return try await port.parent(service: service, now: now) }
  func prepare(_ intent: HolderSessionPrepareIntent, now: UInt64) async throws -> HolderSessionPrivatePayload { count += 1; return try await port.prepare(intent, now: now) }
  func review(_ challenge: HolderSessionChallenge, now: UInt64) async throws -> HolderSessionAuthorizationReview { count += 1; return try await port.review(challenge, now: now) }
  func approve(_ review: HolderSessionAuthorizationReview, signature: String, now: UInt64) async throws -> HolderSessionPrivatePayload { count += 1; approvals += 1; return try await port.approve(review, signature: signature, now: now) }
}
private actor RecordingHolderCustody: HolderSessionCustody {
  let agent: any HolderSessionCustody
  private var last: Data?
  private var installed: Data?
  init(agent: any HolderSessionCustody) { self.agent = agent }
  func lastPresentation() -> Data? { last }
  func installedCredential() -> Data? { installed }
  func create(expiresAt: UInt64, now: UInt64) async throws -> HolderSessionIdentity { try await agent.create(expiresAt: expiresAt, now: now) }
  func possession(_ challenge: HolderSessionChallenge, now: UInt64) async throws -> String { try await agent.possession(challenge, now: now) }
  func install(_ credential: HolderSessionCredential, now: UInt64) async throws { try await agent.install(credential, now: now); installed = credential.data }
  func present(_ credential: HolderSessionCredential, call: Data, now: UInt64) async throws -> Data { let p = try await agent.present(credential, call: call, now: now); last = p; return p }
  func status(_ challenge: HolderSessionChallenge, now: UInt64) async throws -> Data { try await agent.status(challenge, now: now) }
  func stop() async { await agent.stop() }
}
private actor DropHolderReply: HolderSessionIssuer {
  let issuer: LocalHolderSessionIssuer
  private var original: Data?
  init(issuer: LocalHolderSessionIssuer) { self.issuer = issuer }
  func originalIssuedCredential() -> Data? { original }
  func prepare(_ body: HolderSessionPrivatePayload) async throws -> Data { try await issuer.prepare(body) }
  func exchange(_ authorization: HolderSessionPrivatePayload, challenge: HolderSessionChallenge) async throws -> HolderSessionExchangeResult {
    let outcome = try await issuer.exchange(authorization, challenge: challenge)
    if case .issued(let data) = outcome { original = data }
    return .unknown // Actual issuer committed; only the local reply is lost.
  }
  func status(_ proof: Data, challenge: HolderSessionChallenge) async throws -> HolderSessionExchangeResult { try await issuer.status(proof, challenge: challenge) }
  func execute(_ presentation: Data) async throws -> Data { try await issuer.execute(presentation) }
}
#endif
