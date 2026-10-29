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
  var challenges = 0
  var closedClients: Set<String> = []
  var shutdowns = 0
  var holdPreparation = false
  private var preparationGate: CheckedContinuation<Void, Never>?
  private var holdSubmission = false
  private var submissionGate: CheckedContinuation<Void, Never>?
  func suspendPreparation() { holdPreparation = true }
  func isPreparationSuspended() -> Bool { preparationGate != nil }
  func resumePreparation() { preparationGate?.resume(); preparationGate = nil; holdPreparation = false }
  func suspendSubmission() { holdSubmission = true }
  func isSubmissionSuspended() -> Bool { submissionGate != nil }
  func resumeSubmission() { submissionGate?.resume(); submissionGate = nil }
  func closeClient(_ clientID: String) async throws { closedClients.insert(clientID) }
  func shutdown() async { shutdowns += 1 }
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
    preparations += 1
    if holdPreparation { await withCheckedContinuation { preparationGate = $0 } }
    return try preparation("initial_review")
  }
  func updateExpiry(_ preparation: SessionReviewPreparation, expiresAt: UInt64) async throws -> SessionReviewPreparation {
    try self.preparation("expiry_adjusted_review")
  }
  func ownerChallenge(_ preparation: SessionReviewPreparation, ownerIdentity: Data) async throws -> Data {
    challenges += 1
    let review = try preparation.checked(now: sessionTestNow)
    // Fake consent ONLY for scheduling tests. The separate opt-in E2E uses
    // the actual issuer challenge and Wallet Core verification/signature.
    return try SessionReviewWire.encode(["token":"synthetic-consent", "summary":[
      "issuer":preparation.authority.issuer, "receiver":preparation.authority.receiver,
      "operation":"access.decide", "expires_at":sessionTestNow + 120, "native_protocol":"synthetic-test-only",
      "details":["session_review":["manifest":SessionReviewWire.object(review.manifest), "review_digest_sha256":review.digest]]]])
  }
  func submit(_ preparation: SessionReviewPreparation, ownerProof: Data) async throws -> Data {
    submissions += 1
    guard holdSubmission else { throw SessionAccessReviewError.unavailable }
    await withCheckedContinuation { submissionGate = $0 }
    let review = try preparation.checked(now:sessionTestNow)
    var result = try SessionReviewWire.object(SessionReviewWire.publicOutcome(review,state:.awaitingHuman))
    result["state"] = "issued"; result["credential_handle"] = "synthetic-issued-handle"; result["expires_at"] = review.expiresAt
    return try SessionReviewWire.encode(result)
  }
  func reconcile(_ preparation: SessionReviewPreparation) async throws -> Data {
    let review = try preparation.checked(now: sessionTestNow, retained: true)
    return try SessionReviewWire.publicOutcome(review, state: .outcomeUnknown)
  }
  func counts() -> (Int, Int) { (preparations, submissions) }
}

private actor SuspendedSessionOwner: SessionReviewOwner {
  var approvals = 0
  private var pauseState = false, pauseApproval = false, pauseReview = false
  private var gate: CheckedContinuation<Void, Never>?
  func suspendNextState() { pauseState = true }
  func suspendApproval() { pauseApproval = true }
  func suspendReview() { pauseReview = true }
  func isSuspended() -> Bool { gate != nil }
  func resume() { gate?.resume(); gate = nil }
  func state() async throws -> WalletState {
    if pauseState { pauseState = false; await withCheckedContinuation { gate = $0 } }
    return try Self.publicState()
  }
  nonisolated static func publicState() throws -> WalletState {
    try JSONDecoder().decode(WalletState.self, from: SessionReviewWire.encode([
      "configured":true, "unlocked":true, "revision":1, "public_key":String(repeating:"ab", count:32),
      "backup_verified":true, "membership_active":false]))
  }
  func graphAccessIdentityV2() async throws -> Data { Data("{}".utf8) }
  func prepareOperatorAccess(_ challenge: Data, pin: ReadAuthorityPin, now: UInt64) async throws -> OperatorConsent {
    if pauseReview { pauseReview = false; await withCheckedContinuation { gate = $0 } }
    return try JSONDecoder().decode(OperatorConsent.self, from: challenge)
  }
  func approveOperatorAccess(_ consent: OperatorConsent, now: UInt64) async throws -> Data {
    approvals += 1
    if pauseApproval { pauseApproval = false; await withCheckedContinuation { gate = $0 } }
    return Data("{}".utf8) // Never a usable proof.
  }
}

@MainActor private final class FixtureHolderRouting: HolderSessionReviewRouting {
  var exchanges = 0
  private var originals: [String: Data] = [:]
  func ownsOriginalRequest(client: String, params: [String: Any]) throws -> Bool {
    guard let id = params["request_id"] as? String, let original = originals[client + ":" + id] else { return false }
    guard try SessionReviewWire.encode(params) == original else { throw SessionAccessReviewError.changed }
    return true
  }
  func services() async throws -> [SessionReviewService] { [] }
  func owns(client: String, method: String, params: [String: Any]) -> Bool {
    if method == "request_review" { return params["service"] as? String == "urn:example:member-service" }
    return params["request_handle"] as? String == "member-request"
  }
  func exchange(client: String, method: String, params: Data) async throws -> Data {
    exchanges += 1
    if method == "request_review", let id = try SessionReviewWire.object(params)["request_id"] as? String {
      originals[client + ":" + id] = params
    }
    return Data("{}".utf8)
  }
  func close(client: String) async {}
  func stop() async {}
}

final class SessionReviewBridgeTests: XCTestCase {
  @MainActor func testSourceChangeDuringPreparationCannotCreateAnotherRequest() async throws {
    let root = try directory("session-source-race")
    defer { try? FileManager.default.removeItem(at: root) }
    let suite = "SessionSourceRace." + UUID().uuidString, defaults = UserDefaults(suiteName: suite)!
    defer { defaults.removePersistentDomain(forName: suite) }
    let owner = FixtureSessionProvider(), member = FixtureHolderRouting()
    let controller = TransferSessionReviewController(walletModel: nil, directory: root.appendingPathComponent("journal"), defaults: defaults,
      provider: owner, holderProvider: member, socketDirectory: root.appendingPathComponent("ipc"), presentWindows: false, clock: { sessionTestNow })
    controller.setEnabled(true); defer { controller.stop() }
    await owner.suspendPreparation()
    let bytes = try request(), client = String(repeating: "ab", count: 16)
    let pending = Task { try await controller.exchange(client: client, method: "request_review", params: bytes) }
    try await waitFor { await owner.isPreparationSuspended() }
    controller.approvalSource = .savedGrant
    do {
      _ = try await controller.exchange(client: client, method: "request_review", params: bytes)
      XCTFail("An in-flight original request cannot be sent to another source")
    } catch SessionReviewBridgeError.unavailable {}
    await owner.resumePreparation()
    let original = try await pending.value
    let retried = try await controller.exchange(client: client, method: "request_review", params: bytes)
    XCTAssertEqual(original, retried)
    let counts = await owner.counts(); XCTAssertEqual(counts.0, 1); XCTAssertEqual(counts.1, 0)
    XCTAssertEqual(member.exchanges, 0)
  }
  @MainActor func testOriginalRequestRetryRetainsSourceWhenSelectionChanges() async throws {
    for originalMember in [false, true] {
      let root = try directory("session-original-retry")
      defer { try? FileManager.default.removeItem(at: root) }
      let suite = "SessionOriginalRetry." + UUID().uuidString, defaults = UserDefaults(suiteName: suite)!
      defer { defaults.removePersistentDomain(forName: suite) }
      let owner = FixtureSessionProvider(), member = FixtureHolderRouting()
      let controller = TransferSessionReviewController(walletModel: nil, directory: root.appendingPathComponent("journal"), defaults: defaults,
        provider: owner, holderProvider: member, socketDirectory: root.appendingPathComponent("ipc"), presentWindows: false, clock: { sessionTestNow })
      controller.setEnabled(true); defer { controller.stop() }
      controller.approvalSource = originalMember ? .savedGrant : .owner
      var input = try SessionReviewWire.object(request())
      if originalMember { input["service"] = "urn:example:member-service" }
      let client = String(repeating: "ab", count: 16), bytes = try SessionReviewWire.encode(input)
      let first = try await controller.exchange(client: client, method: "request_review", params: bytes)
      controller.approvalSource = originalMember ? .owner : .savedGrant
      let retried = try await controller.exchange(client: client, method: "request_review", params: bytes)
      XCTAssertEqual(first, retried)
      input["purpose"] = "Changed bytes must not create a second request"
      do {
        _ = try await controller.exchange(client: client, method: "request_review", params: SessionReviewWire.encode(input))
        XCTFail("An original request ID cannot be rebound across source changes")
      } catch SessionAccessReviewError.changed {}
      let counts = await owner.counts()
      XCTAssertEqual(counts.0, originalMember ? 0 : 1); XCTAssertEqual(counts.1, 0)
      XCTAssertEqual(member.exchanges, originalMember ? 2 : 0)
    }
  }
  @MainActor func testSavedGrantSourceNeverFallsThroughToOwner() async throws {
    for missingRegistration in [true, false] {
      let root = try directory("session-exclusive-source")
      defer { try? FileManager.default.removeItem(at: root) }
      let suite = "SessionExclusiveSource." + UUID().uuidString, defaults = UserDefaults(suiteName: suite)!
      defer { defaults.removePersistentDomain(forName: suite) }
      // Reproduce a saved choice surviving removal of its registration.
      defaults.set(true, forKey: "Transfer.sessionReview.savedGrantSource.v1")
      let owner = FixtureSessionProvider(), member = FixtureHolderRouting()
      let controller = TransferSessionReviewController(walletModel: nil, directory: root.appendingPathComponent("journal"), defaults: defaults,
        provider: owner, holderProvider: missingRegistration ? nil : member,
        socketDirectory: root.appendingPathComponent("ipc"), presentWindows: false, clock: { sessionTestNow })
      controller.setEnabled(true); defer { controller.stop() }
      XCTAssertTrue(controller.enabled)
      XCTAssertEqual(controller.approvalSource, .savedGrant)
      do {
        _ = try await controller.exchange(client: String(repeating: "ab", count: 16), method: "request_review", params: request())
        XCTFail("Missing registration or mismatched service must fail closed")
      } catch SessionReviewBridgeError.unavailable {} // The expected rejection, before either provider prepares.
      let counts = await owner.counts()
      XCTAssertEqual(counts.0, 0); XCTAssertEqual(counts.1, 0)
      XCTAssertEqual(member.exchanges, 0); XCTAssertTrue(controller.records.isEmpty)
    }
  }
  @MainActor func testExistingMemberHandleKeepsItsSourceAfterSelectionChanges() async throws {
    let root = try directory("session-original-source")
    defer { try? FileManager.default.removeItem(at: root) }
    let suite = "SessionOriginalSource." + UUID().uuidString, defaults = UserDefaults(suiteName: suite)!
    defer { defaults.removePersistentDomain(forName: suite) }
    let owner = FixtureSessionProvider(), member = FixtureHolderRouting()
    let controller = TransferSessionReviewController(walletModel: nil, directory: root.appendingPathComponent("journal"), defaults: defaults,
      provider: owner, holderProvider: member, socketDirectory: root.appendingPathComponent("ipc"), presentWindows: false, clock: { sessionTestNow })
    controller.setEnabled(true); defer { controller.stop() }
    controller.approvalSource = .savedGrant
    var input = try SessionReviewWire.object(request()); input["service"] = "urn:example:member-service"
    _ = try await controller.exchange(client: String(repeating: "ab", count: 16), method: "request_review", params: SessionReviewWire.encode(input))
    controller.approvalSource = .owner
    _ = try await controller.exchange(client: String(repeating: "ab", count: 16), method: "get_result", params: SessionReviewWire.encode(["request_handle": "member-request"]))
    XCTAssertEqual(member.exchanges, 2)
    let counts = await owner.counts(); XCTAssertEqual(counts.0, 0); XCTAssertEqual(counts.1, 0)
  }
  func testExternalRegistrationMetadataWhenExplicitlyRequested() throws {
    let environment = ProcessInfo.processInfo.environment
    guard let path = environment["TRANSFER_SESSION_REGISTRATION_REVIEW_DIRECTORY"] else {
      throw XCTSkip("Explicit owner-private provider review directory required")
    }
    // Validation constructs an inert actor only. Do NOT call services here:
    // no provider/store/listener, issuer-key access or grant is started.
    let directory = URL(fileURLWithPath:path)
    if let mappingPath = environment["TRANSFER_SESSION_REGISTRATION_POSTIMAGE_MAP"] {
      // Pre-activation test only: validate the exact future hashes against the
      // separately audited replacement bytes. Never launch this shadow mapping.
      let descriptor = directory.appendingPathComponent("provider.json"), bytes = try Data(contentsOf:descriptor)
      let registration = try SessionProviderRegistration.decode(bytes)
      let mapping = try JSONDecoder().decode([String:String].self,from:Data(contentsOf:URL(fileURLWithPath:mappingPath)))
      XCTAssertTrue(Set(mapping.keys).isSubset(of:Set(registration.launch.sources.map(\.path))))
      var sources = Dictionary(uniqueKeysWithValues:registration.launch.sources.map { (URL(fileURLWithPath:mapping[$0.path] ?? $0.path),$0.sha256) })
      sources[descriptor] = OwnerSetupPlan.sha256(bytes)
      let files = registration.launch
      try SessionProviderLaunch(interpreter:URL(fileURLWithPath:files.interpreter.path),script:URL(fileURLWithPath:files.script.path),
        profile:URL(fileURLWithPath:files.profile.path),interpreterSHA256:files.interpreter.sha256,scriptSHA256:files.script.sha256,
        profileSHA256:files.profile.sha256,sources:sources).validate()
    } else {
      XCTAssertNotNil(try SessionProviderRegistration.loadIfPresent(directory:directory))
    }
  }
  func testPinnedInventoryRejectsOversizedFileAndAggregateWithoutLaunching() throws {
    let root = try directory("session-inventory-budget")
    defer { try? FileManager.default.removeItem(at:root) }
    let script = root.appendingPathComponent("provider.py"), profile = root.appendingPathComponent("profile.json"), large = root.appendingPathComponent("native0")
    try Data("fixture".utf8).write(to:script); try Data("{}".utf8).write(to:profile)
    try FileManager.default.setAttributes([.posixPermissions:0o600],ofItemAtPath:profile.path)
    XCTAssertTrue(FileManager.default.createFile(atPath:large.path,contents:nil))
    let file = try FileHandle(forWritingTo:large)
    try file.truncate(atOffset:64 * 1024 * 1024); try file.close() // Sparse, no 64MiB disk allocation.
    let digest = OwnerSetupPlan.sha256(try Data(contentsOf:large))
    let interpreter = URL(fileURLWithPath:"/usr/bin/true")
    func launch(_ sources:[URL:String]) throws -> SessionProviderLaunch {
      .init(interpreter:interpreter,script:script,profile:profile,
        interpreterSHA256:OwnerSetupPlan.sha256(try Data(contentsOf:interpreter)),scriptSHA256:OwnerSetupPlan.sha256(try Data(contentsOf:script)),
        profileSHA256:OwnerSetupPlan.sha256(try Data(contentsOf:profile)),sources:sources)
    }
    try launch([large:digest]).validate()
    var inventory = [large:digest]
    for i in 1...4 {
      let link = root.appendingPathComponent("native\(i)")
      try FileManager.default.linkItem(at:large,to:link); inventory[link] = digest
    }
    XCTAssertThrowsError(try launch(inventory).validate(),"More than256MiB of pinned input is rejected")
    let oversized = try FileHandle(forWritingTo:large)
    try oversized.truncate(atOffset:65 * 1024 * 1024); try oversized.close()
    XCTAssertThrowsError(try launch([large:digest]).validate(),"File size is checked before reading/hash work")
  }
  @MainActor func testDisablingBridgeClosesKnownClientsWithoutStoppingReenableableProvider() async throws {
    let root = try directory("session-disable")
    defer { try? FileManager.default.removeItem(at:root) }
    let suite = "SessionDisable." + UUID().uuidString, defaults = UserDefaults(suiteName:suite)!
    defer { defaults.removePersistentDomain(forName:suite) }
    let provider = FixtureSessionProvider()
    let controller = TransferSessionReviewController(walletModel:nil,directory:root.appendingPathComponent("journal"),defaults:defaults,
      provider:provider,socketDirectory:root.appendingPathComponent("ipc"),presentWindows:false,clock:{sessionTestNow})
    controller.setEnabled(true); defer { controller.stop() }
    let client = String(repeating:"ab",count:16)
    _ = try await controller.exchange(client:client,method:"request_review",params:request())
    controller.setEnabled(false)
    try await waitFor { await provider.closedClients.contains(client) }
    XCTAssertTrue(controller.endedClients.contains(client)); XCTAssertEqual(controller.records.count,1)
    controller.setEnabled(true); XCTAssertTrue(controller.enabled)
    do { _ = try await controller.exchange(client:client,method:"list_services",params:Data("{}".utf8)); XCTFail("Old adapter stays ended") } catch {}
    _ = try await controller.exchange(client:String(repeating:"cd",count:16),method:"list_services",params:Data("{}".utf8))
    let stopped = await provider.shutdowns
    XCTAssertEqual(stopped,0,"Disabling releases clients without permanently stopping the provider")
  }
  func testPrivateProviderSerializesConcurrentExchangesWithoutCrossingReplies() async throws {
    let root = try directory("session-process-queue")
    defer { try? FileManager.default.removeItem(at: root) }
    let script = root.appendingPathComponent("provider.py"), profile = root.appendingPathComponent("profile.json")
    try Data("""
    import json,sys,time
    for line in sys.stdin:
        request=json.loads(line)
        time.sleep(0.1)
        result={"client":request["client_id"]}
        print(json.dumps({"schema":"devgraph.session-provider-result.v1","request_id":request["request_id"],"ok":True,"value":result}),flush=True)
    """.utf8).write(to:script)
    try Data("{}".utf8).write(to:profile)
    try FileManager.default.setAttributes([.posixPermissions:0o600],ofItemAtPath:profile.path)
    let python = URL(fileURLWithPath:"/usr/bin/python3")
    let process = SessionProviderProcess(launch:.init(interpreter:python,script:script,profile:profile,
      interpreterSHA256:OwnerSetupPlan.sha256(try Data(contentsOf:python.resolvingSymlinksInPath())),
      scriptSHA256:OwnerSetupPlan.sha256(try Data(contentsOf:script)),profileSHA256:OwnerSetupPlan.sha256(try Data(contentsOf:profile)),
      sources:[script:OwnerSetupPlan.sha256(try Data(contentsOf:script))]))
    do {
      async let first = process.exchange(clientID:String(repeating:"ab",count:16),operation:"services",arguments:Data("{}".utf8))
      async let second = process.exchange(clientID:String(repeating:"cd",count:16),operation:"services",arguments:Data("{}".utf8))
      let replies = try await [first,second]
      XCTAssertEqual(try SessionReviewWire.object(replies[0])["client"] as? String,String(repeating:"ab",count:16))
      XCTAssertEqual(try SessionReviewWire.object(replies[1])["client"] as? String,String(repeating:"cd",count:16))
      await process.stop()
    } catch { await process.stop(); throw error }
  }
  private func waitFor(_ condition: @escaping () async -> Bool) async throws {
    let deadline = Date().addingTimeInterval(3)
    while !(await condition()) {
      guard Date() < deadline else { XCTFail("Scheduling gate not reached"); throw SessionReviewBridgeError.unavailable }
      try await Task.sleep(nanoseconds: 1_000_000)
    }
  }
  @MainActor func testEOFDuringPreparationCannotSaveOrShowDeadCustodyReview() async throws {
    let root = try directory("session-prepare-race")
    defer { try? FileManager.default.removeItem(at: root) }
    let provider = FixtureSessionProvider(); await provider.suspendPreparation()
    let controller = TransferSessionReviewController(walletModel:nil, directory:root.appendingPathComponent("journal"),
      provider:provider, socketDirectory:root.appendingPathComponent("ipc"), presentWindows:false, clock:{sessionTestNow})
    controller.setEnabled(true); defer { controller.stop() }
    let client = String(repeating:"ab",count:16), input = try request()
    let pending = Task { try await controller.exchange(client:client, method:"request_review", params:input) }
    try await waitFor { await provider.isPreparationSuspended() }
    _ = try await controller.exchange(client:client, method:"close_client", params:Data("{}".utf8))
    await provider.resumePreparation()
    do { _ = try await pending.value; XCTFail("An ended adapter cannot retain a prepared review") } catch {}
    XCTAssertTrue(controller.endedClients.contains(client)); XCTAssertTrue(controller.records.isEmpty); XCTAssertNil(controller.active)
  }
  @MainActor func testEOFWhileOwnerStateOrSigningIsSuspendedCannotDispatch() async throws {
    for stage in ["prepare-state", "native-review", "approve-state", "signing", "submit"] {
      let root = try directory("session-owner-race")
      defer { try? FileManager.default.removeItem(at: root) }
      let suite = "SessionRace." + UUID().uuidString, defaults = UserDefaults(suiteName:suite)!
      defer { defaults.removePersistentDomain(forName:suite) }
      let model = TransferModel(directory:root.appendingPathComponent("app"), defaults:defaults)
      model.wallet = try SuspendedSessionOwner.publicState()
      let provider = FixtureSessionProvider(), owner = SuspendedSessionOwner()
      let controller = TransferSessionReviewController(walletModel:model, directory:root.appendingPathComponent("journal"), defaults:defaults,
        provider:provider, owner:owner, socketDirectory:root.appendingPathComponent("ipc"), presentWindows:false, clock:{sessionTestNow})
      controller.setEnabled(true); defer { controller.stop() }
      let client = String(repeating:"ab",count:16)
      _ = try await controller.exchange(client:client, method:"request_review", params:request())
      let handle = try XCTUnwrap(controller.active), review = try controller.review(handle)
      let work: Task<Void, Never>
      if stage == "prepare-state" || stage == "native-review" {
        if stage == "prepare-state" { await owner.suspendNextState() } else { await owner.suspendReview() }
        work = Task { await controller.prepareNativeReview() }
      } else {
        await controller.prepareNativeReview(); XCTAssertNotNil(controller.consent)
        if stage == "approve-state" { await owner.suspendNextState() }
        else if stage == "signing" { await owner.suspendApproval() }
        else { await provider.suspendSubmission() }
        work = Task { await controller.approveNativeReview(reviewedDigest:review.digest, reviewedExpiry:review.expiresAt) }
      }
      if stage == "submit" { try await waitFor { await provider.isSubmissionSuspended() } }
      else { try await waitFor { await owner.isSuspended() } }
      _ = try await controller.exchange(client:client, method:"close_client", params:Data("{}".utf8))
      if stage == "submit" { await provider.resumeSubmission() } else { await owner.resume() }
      await work.value
      XCTAssertNil(controller.consent, stage)
      let counts = await provider.counts(), approvals = await owner.approvals
      let fenced = stage == "signing" || stage == "submit"
      XCTAssertEqual(counts.1,stage == "submit" ? 1 : 0,stage)
      XCTAssertEqual(approvals,fenced ? 1 : 0,stage)
      XCTAssertEqual(controller.records[handle]?.dispatched,fenced,stage)
      XCTAssertEqual(controller.records[handle]?.state,fenced ? .outcomeUnknown : .awaitingHuman,stage)
    }
  }
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
    // Actual custody helpers are several MiB. A pinned native dependency must
    // fit the inventory while remaining subject to the same drift checks.
    let helper = root.appendingPathComponent("custody-helper")
    try Data(repeating:0x41,count:2 * 1024 * 1024).write(to:helper)
    func filePin(_ file: URL) throws -> [String:Any] { ["path":file.path, "sha256":OwnerSetupPlan.sha256(try Data(contentsOf: file))] }
    raw["launch"] = try ["interpreter":filePin(URL(fileURLWithPath:"/usr/bin/true")), "script":filePin(script), "profile":filePin(profile), "sources":[filePin(source),filePin(helper)]]
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
