import CastaliaWallet
import Foundation

public struct WalletState: Decodable, Sendable {
  public let configured: Bool
  public let unlocked: Bool
  public let revision: UInt64
  public let publicKey: String?
  public let backupVerified: Bool
  public let membershipActive: Bool
  public let backupEligible: Bool?
  public let graphAccessProtocol: String?
  public let operatorAccessProtocol: String?
  public let resourceOwnerProtocol: String?
  public var canRequestWorkAccess: Bool {
    unlocked && (backupEligible ?? backupVerified) && graphAccessProtocol == "castalia.graph-access.v2"
  }
  enum CodingKeys: String, CodingKey {
    case membershipActive = "membership_active"
    case backupEligible = "backup_eligible"
    case graphAccessProtocol = "graph_access_protocol"
    case operatorAccessProtocol = "operator_access_protocol"
    case resourceOwnerProtocol = "resource_owner_protocol"
    case configured, unlocked, revision
    case publicKey = "public_key"
    case backupVerified = "backup_verified"
  }
}
public struct RestorePreview: Decodable, Sendable {
  public let token: String
  public let expectedRevision: UInt64
  public let publicKey: String
  public let backupVerified: Bool
  public let profile: PortableProfile?
  public let chainAccounts: PublicAccounts?
  public let memberships: PortableSections?
  public let replacesProfile: Bool?
  public let replacedProofs: [String]?
  enum CodingKeys: String, CodingKey {
    case profile, memberships
    case chainAccounts = "chain_accounts"
    case replacesProfile = "replaces_profile"
    case replacedProofs = "replaced_proofs"
    case token
    case expectedRevision = "expected_revision"
    case publicKey = "public_key"
    case backupVerified = "backup_verified"
  }
}
private final class NativeCore {
  let handle: UInt64
  init() throws {
    guard castalia_abi_version() == 1 else { throw WalletFailure.core("unsupported_version") }
    handle = castalia_session_new()
    guard handle != 0 else { throw WalletFailure.core("core_unavailable") }
  }
  deinit { castalia_session_free(handle) }
  func invoke(_ request: [String: Any]) throws -> Data {
    var input = try JSONSerialization.data(withJSONObject: request, options: [.sortedKeys])
    defer { input.resetBytes(in: 0..<input.count) }
    let result = input.withUnsafeBytes {
      castalia_session_invoke(handle, $0.bindMemory(to: UInt8.self).baseAddress, input.count)
    }
    guard result != 0 else { throw WalletFailure.core("core_unavailable") }
    defer { castalia_result_free(result) }
    let size = castalia_result_length(result)
    guard size > 0 && size <= 4_194_304 else { throw WalletFailure.core("invalid_response") }
    var output = Data(count: size)
    let copied = output.withUnsafeMutableBytes {
      castalia_result_copy(result, $0.bindMemory(to: UInt8.self).baseAddress, size)
    }
    defer { output.resetBytes(in: 0..<output.count) }
    guard copied == size,
      let response = try JSONSerialization.jsonObject(with: output) as? [String: Any]
    else { throw WalletFailure.core("invalid_response") }
    guard response["ok"] as? Bool == true else {
      throw WalletFailure.core(response["error"] as? String ?? "core_failed")
    }
    guard let value = response["value"] else { throw WalletFailure.core("invalid_response") }
    return try JSONSerialization.data(withJSONObject: value)
  }
  func decode<T: Decodable>(_ request: [String: Any], as type: T.Type) throws -> T {
    try JSONDecoder().decode(type, from: invoke(request))
  }
}

/// Serializes core calls and durable commits. No actor suspension occurs between
/// candidate validation, storage CAS and core acknowledgement.
public actor WalletRepository {
  private let core: NativeCore
  private let store: SnapshotStore
  private var previewTickets: [String: UInt64] = [:]
  private nonisolated let lifecycle = LifecycleGate()
  public nonisolated func lifecycleTicket() -> UInt64 { lifecycle.ticket() }
  public nonisolated func checkLifecycle(_ ticket: UInt64) throws {
    try lifecycle.withCurrent(ticket) {}
  }
  public nonisolated func invalidatePendingWork() { lifecycle.invalidate() }
  /// Backgrounding cancels drafts and invalidates old proofs immediately, while
  /// retaining the already-unlocked core in this process. No secret is persisted.
  /// Foreground callers wait for this task before preparing fresh consent.
  public nonisolated func pauseForBackground() -> Task<Void, Never> {
    lifecycle.invalidate()
    return Task { await self.cancel() }
  }
  public init(directory: URL) throws {
    core = try NativeCore()
    store = try SnapshotStore(directory: directory)
    if let saved = try store.read() {
      _ = try core.invoke(["operation": "observe", "snapshot": saved.snapshot])
    }
  }
  public func state() throws -> WalletState {
    try core.decode(["operation": "state"], as: WalletState.self)
  }
  public func create(password: String) throws -> WalletState {
    try Task.checkCancellation()
    let ticket = lifecycle.ticket()
    let preview = try core.decode(
      [
        "operation": "prepare_create", "password": password,
        "created_at": UInt64(Date().timeIntervalSince1970 * 1000),
        "expected_revision": try state().revision,
      ], as: RestorePreview.self)
    return try commit(preview, ticket: ticket)
  }
  public func prepareRestore(
    file: Data, filePassword: String, password: String, dataFile: Data? = nil,
    dataPassword: String? = nil
  ) throws -> RestorePreview {
    try Task.checkCancellation()
    let ticket = lifecycle.ticket()
    guard file.count <= 1_048_576, let text = String(data: file, encoding: .utf8) else {
      throw WalletFailure.invalidFile
    }
    var request: [String: Any] = [
      "operation": "prepare_restore", "file": text, "file_password": filePassword,
      "password": password, "expected_revision": try state().revision,
    ]
    if let dataFile, let dataPassword {
      guard dataFile.count <= 1_048_576, let encoded = String(data: dataFile, encoding: .utf8)
      else { throw WalletFailure.invalidFile }
      request["data_file"] = encoded
      request["data_password"] = dataPassword
    } else if dataFile != nil || dataPassword != nil {
      throw WalletFailure.invalidFile
    }
    return try prepare(request, ticket: ticket)
  }
  public func commit(_ preview: RestorePreview) throws -> WalletState {
    guard let ticket = previewTickets.removeValue(forKey: preview.token) else {
      throw WalletFailure.conflict
    }
    return try commit(preview, ticket: ticket)
  }
  private func commit(_ preview: RestorePreview, ticket: UInt64) throws -> WalletState {
    struct Candidate: Decodable {
      let snapshot: String
      let expected_revision: UInt64
    }
    let candidate = try core.decode(
      [
        "operation": "commit_candidate", "token": preview.token,
        "expected_revision": preview.expectedRevision,
      ], as: Candidate.self)
    do {
      try lifecycle.withCurrent(ticket) {
        try Task.checkCancellation()
        try store.commit(
          snapshot: candidate.snapshot, expectedRevision: preview.expectedRevision,
          revision: preview.expectedRevision + 1)
      }
    } catch {
      // A response failure after a durable commit must not invent failure or write twice.
      guard let saved = try? store.read(), saved.snapshot == candidate.snapshot else {
        _ = try? core.invoke(["operation": "cancel"])
        throw error
      }
    }
    do {
      return try core.decode(
        ["operation": "confirm_commit", "token": preview.token, "snapshot": candidate.snapshot],
        as: WalletState.self)
    } catch {
      _ = try? core.invoke(["operation": "lock"])
      throw WalletFailure.conflict
    }
  }
  public func unlock(password: String, expectedLifecycle: UInt64? = nil, expectedIdentity: String? = nil) throws -> WalletState {
    try Task.checkCancellation()
    let ticket = expectedLifecycle ?? lifecycle.ticket()
    try checkLifecycle(ticket)
    guard let saved = try store.read() else { throw WalletFailure.locked }
    let state = try core.decode(
      ["operation": "unlock", "snapshot": saved.snapshot, "password": password],
      as: WalletState.self)
    do {
      return try lifecycle.withCurrent(ticket) {
        guard expectedIdentity == nil || state.publicKey == expectedIdentity else { throw WalletFailure.conflict }
        return state
      }
    } catch {
      _ = try? core.invoke(["operation": "lock"])
      throw error
    }
  }
  public func exportRecovery(password: String) throws -> Data {
    struct Export: Decodable { let file: String }
    return Data(
      try core.decode(["operation": "export_recovery", "password": password], as: Export.self).file
        .utf8)
  }
  public func verifyBackup(file: Data, password: String) throws -> WalletState {
    try Task.checkCancellation()
    let ticket = lifecycle.ticket()
    guard file.count <= 1_048_576, let text = String(data: file, encoding: .utf8) else {
      throw WalletFailure.invalidFile
    }
    let preview = try core.decode(
      ["operation": "verify_backup", "file": text, "password": password], as: RestorePreview.self)
    return try commit(preview, ticket: ticket)
  }
  public func prepareData(file: Data, password: String) throws -> RestorePreview {
    guard file.count <= 1_048_576, let text = String(data: file, encoding: .utf8) else {
      throw WalletFailure.invalidFile
    }
    return try prepare(
      ["operation": "prepare_data", "file": text, "password": password], ticket: lifecycle.ticket())
  }
  public func exportData(password: String) throws -> Data {
    struct Export: Decodable { let file: String }
    return Data(
      try core.decode(
        [
          "operation": "export_data", "password": password,
          "exported_at": UInt64(Date().timeIntervalSince1970 * 1000),
        ], as: Export.self
      ).file.utf8)
  }
  public func prepareLegacy(key: String, password: String) throws -> RestorePreview {
    try prepare(
      [
        "operation": "prepare_legacy", "key": key, "password": password,
        "created_at": UInt64(Date().timeIntervalSince1970 * 1000),
        "expected_revision": try state().revision,
      ], ticket: lifecycle.ticket())
  }
  public func approveTrust(_ trust: Data) throws -> WalletState {
    try Task.checkCancellation()
    let ticket = lifecycle.ticket()
    let value = try JSONSerialization.jsonObject(with: trust)
    let preview = try core.decode(
      ["operation": "prepare_trust", "trust": value], as: RestorePreview.self)
    return try commit(preview, ticket: ticket)
  }
  public func membershipRequest(scope: String?) throws -> Data {
    var request: [String: Any] = ["operation": "membership_request"]
    if let scope { request["scope_id"] = scope }
    return try core.invoke(request)
  }
  public func activateMembership(_ proof: Data, scoped: Bool) throws -> WalletState {
    try Task.checkCancellation()
    let ticket = lifecycle.ticket()
    let value = try JSONSerialization.jsonObject(with: proof)
    let preview = try core.decode(
      ["operation": "activate_membership", "proof": value, "scoped": scoped],
      as: RestorePreview.self)
    return try commit(preview, ticket: ticket)
  }
  public func trustMatches(_ trust: Data) throws -> Bool {
    let summary = try JSONSerialization.jsonObject(with: dataSummary()) as? [String: Any]
    let proposed = try JSONSerialization.jsonObject(with: trust) as? [String: Any] ?? [:]
    let current = summary?["trust"] as? [String: Any] ?? [:]
    // Optional absent fields and explicit null have the same contract meaning.
    return NSDictionary(dictionary: current.filter { !($0.value is NSNull) })
      .isEqual(to: proposed.filter { !($0.value is NSNull) })
  }
  public func importedMemberships(scope: String?) throws -> [Data] {
    let summary = try JSONSerialization.jsonObject(with: dataSummary()) as? [String: Any]
    let contents = summary?["contents"] as? [String: Any]
    let sections = contents?["sections"] as? [String: Any]
    let values =
      sections?[scope == nil ? "memberships" : "scopedMemberships"] as? [[String: Any]] ?? []
    return try values.filter { scope == nil || $0["scopeId"] as? String == scope }.map {
      try JSONSerialization.data(withJSONObject: $0)
    }
  }
  public func dataSummary() throws -> Data { try core.invoke(["operation": "data_summary"]) }
  public func readAccessIdentity() throws -> Data {
    try core.invoke(["operation": "read_access_identity"])
  }
  public func approveReadAccess(_ challenge: Data, receiver: String, now: UInt64) throws -> Data {
    try Task.checkCancellation()
    let ticket = lifecycle.ticket()
    guard let text = String(data: challenge, encoding: .utf8) else {
      throw WalletFailure.invalidFile
    }
    let result = try core.invoke([
      "operation": "approve_read_access", "challenge": text, "receiver": receiver, "now": now,
    ])
    try checkLifecycle(ticket)
    return result
  }
  public func storeReadAccess(
    requestID: String, secret: String, expires: UInt64, metadata: Data, now: UInt64, ticket: UInt64
  ) throws {
    try checkLifecycle(ticket)
    let preview = try core.decode(
      [
        "operation": "store_read_access", "request_id": requestID, "secret": secret,
        "expires_at": expires, "metadata": JSONSerialization.jsonObject(with: metadata), "now": now,
      ], as: RestorePreview.self)
    _ = try commit(preview, ticket: ticket)
  }
  public func prepareAccessRequest(_ challenge: Data, pin: ReadAuthorityPin, now: UInt64) throws -> NativeAccessRequestPreview {
    try Task.checkCancellation()
    let ticket = lifecycle.ticket()
    guard let text = String(data: challenge, encoding: .utf8) else { throw WalletFailure.invalidFile }
    let result = try core.decode(["operation":"prepare_access_request","challenge":text,
      "pin":JSONSerialization.jsonObject(with:JSONEncoder().encode(pin)),"now":now], as:NativeAccessRequestPreview.self)
    try checkLifecycle(ticket)
    return result
  }
  public func approveAccessRequest(_ preview: NativeAccessRequestPreview, now: UInt64, ticket: UInt64) throws -> Data {
    try Task.checkCancellation()
    try checkLifecycle(ticket)
    let result = try core.invoke(["operation":"approve_access_request","token":preview.token,"now":now])
    try checkLifecycle(ticket)
    return result
  }
  public func approveReadCredential(_ challenge: Data, pin: ReadAuthorityPin, now: UInt64) throws -> Data {
    let ticket = lifecycle.ticket()
    guard let text = String(data: challenge, encoding: .utf8) else { throw WalletFailure.invalidFile }
    let result = try core.invoke(["operation":"approve_read_credential", "challenge":text,
      "pin":JSONSerialization.jsonObject(with: JSONEncoder().encode(pin)), "now":now])
    try checkLifecycle(ticket)
    return result
  }
  public func storeReadCredential(requestID: String, credential: Data, now: UInt64, ticket: UInt64) throws {
    try checkLifecycle(ticket)
    let preview = try core.decode(["operation":"store_read_credential", "request_id":requestID,
      "credential":JSONSerialization.jsonObject(with: credential), "now":now], as: RestorePreview.self)
    _ = try commit(preview, ticket: ticket)
  }
  public func readCredential(receiver: String, now: UInt64) throws -> Data {
    try core.invoke(["operation":"read_credential", "receiver":receiver, "now":now])
  }
  public func signReadCall(receiver: String, call: Data, now: UInt64) throws -> Data {
    try core.invoke(["operation":"sign_read_call", "receiver":receiver,
      "call":JSONSerialization.jsonObject(with: call), "now":now])
  }

  // Explicit opt-in graph protocol v2. Do not silently fall back to legacy APIs.
  public func graphAccessIdentityV2() throws -> Data {
    let value = try core.invoke(["operation": "graph_access_identity_v2"])
    guard let identity = try JSONSerialization.jsonObject(with: value) as? [String: String],
      identity["protocol"] == "castalia.graph-access.v2",
      let owner = identity["subject_public_key"], let installation = identity["installation_id"]
    else { throw WalletFailure.core("wallet_update_required") }
    // The native API marker is local capability metadata, not a server field.
    return try JSONSerialization.data(withJSONObject: ["subject_public_key":owner,"installation_id":installation])
  }
  public func prepareGraphAccessRequestV2(_ challenge: Data, pin: ReadAuthorityPin, now: UInt64) throws -> NativeAccessRequestPreview {
    try Task.checkCancellation()
    let ticket = lifecycle.ticket()
    guard let text = String(data: challenge, encoding: .utf8) else { throw WalletFailure.invalidFile }
    let result = try core.decode(["operation":"prepare_graph_access_request_v2","challenge":text,
      "pin":JSONSerialization.jsonObject(with:JSONEncoder().encode(pin)),"now":now], as:NativeAccessRequestPreview.self)
    try checkLifecycle(ticket)
    return result
  }
  public func approveGraphAccessRequestV2(_ preview: NativeAccessRequestPreview, now: UInt64, ticket: UInt64) throws -> Data {
    try Task.checkCancellation()
    try checkLifecycle(ticket)
    let result = try core.invoke(["operation":"approve_graph_access_request_v2","token":preview.token,"now":now])
    try checkLifecycle(ticket)
    return result
  }
  #if os(macOS)
  /// First-owner consent is a separate protocol and never a member credential.
  public func prepareResourceOwner(_ challenge: Data, binding: ResourceOwnerBinding, now: UInt64) throws -> ResourceOwnerConsent {
    try Task.checkCancellation()
    let ticket = lifecycle.ticket()
    guard try state().resourceOwnerProtocol == "zenith.resource-owner.v1",
      let text = String(data: challenge, encoding: .utf8) else { throw WalletFailure.core("owner_update_required") }
    let checked = try ResourceOwnerChallenge.decode(challenge, binding: binding, now: now)
    guard try state().publicKey == checked.adminGrant.holderPublicKey else { throw OwnerSetupError.changed }
    let result = try core.invoke(["operation":"prepare_resource_owner_v1", "challenge":text,
      "binding":JSONSerialization.jsonObject(with:JSONEncoder().encode(binding)), "now":now])
    let consent = try ResourceOwnerConsent.decode(result, challenge: checked, lifecycle: ticket)
    try checkLifecycle(ticket); return consent
  }
  public func approveResourceOwner(_ consent: ResourceOwnerConsent, now: UInt64) throws -> Data {
    try Task.checkCancellation(); try checkLifecycle(consent.lifecycle)
    let result = try core.invoke(["operation":"approve_resource_owner_v1", "token":consent.token, "now":now])
    try consent.challenge.validateProof(result)
    try checkLifecycle(consent.lifecycle); return result
  }
  #endif
  /// Separate native operator capability. Never fall back to member consent.
  public func prepareOperatorAccess(_ challenge: Data, pin: ReadAuthorityPin, now: UInt64) throws -> OperatorConsent {
    let ticket = lifecycle.ticket()
    guard try state().operatorAccessProtocol == "castalia.operator-access.v1",
      let text = String(data: challenge, encoding: .utf8) else { throw WalletFailure.core("operator_update_required") }
    let data = try core.invoke(["operation":"prepare_operator_access_v1","challenge":text,
      "pin":JSONSerialization.jsonObject(with:JSONEncoder().encode(pin)),"now":now])
    let value = try JSONDecoder().decode(OperatorConsent.self, from: data)
    guard value.summary.native_protocol == "castalia.operator-access.v1" else { throw WalletFailure.invalidFile }
    try checkLifecycle(ticket)
    return OperatorConsent(token: value.token, summary: value.summary, lifecycle: ticket)
  }
  public func approveOperatorAccess(_ consent: OperatorConsent, now: UInt64) throws -> Data {
    try Task.checkCancellation(); try checkLifecycle(consent.lifecycle)
    let result = try core.invoke(["operation":"approve_operator_access_v1","token":consent.token,"now":now])
    try checkLifecycle(consent.lifecycle); return result
  }
  public func approveGraphReadCredentialV2(_ challenge: Data, pin: ReadAuthorityPin, now: UInt64) throws -> Data {
    let ticket = lifecycle.ticket()
    guard let text = String(data: challenge, encoding: .utf8) else { throw WalletFailure.invalidFile }
    let result = try core.invoke(["operation":"approve_graph_read_credential_v2", "challenge":text,
      "pin":JSONSerialization.jsonObject(with: JSONEncoder().encode(pin)), "now":now])
    try checkLifecycle(ticket)
    return result
  }
  public func graphReadCredentialV2(receiver: String, now: UInt64) throws -> Data {
    try core.invoke(["operation":"graph_read_credential_v2", "receiver":receiver, "now":now])
  }
  public func signGraphReadCallV2(receiver: String, call: Data, now: UInt64) throws -> Data {
    try core.invoke(["operation":"sign_graph_read_call_v2", "receiver":receiver,
      "call":JSONSerialization.jsonObject(with: call), "now":now])
  }
  public func readAccess(receiver: String, now: UInt64) throws -> Data {
    try core.invoke(["operation": "read_access", "receiver": receiver, "now": now])
  }
  public func forgetReadAccess(receiver: String) throws {
    try Task.checkCancellation()
    let ticket = lifecycle.ticket()
    let preview = try core.decode(
      ["operation": "forget_read_access", "receiver": receiver], as: RestorePreview.self)
    _ = try commit(preview, ticket: ticket)
  }
  private func prepare(_ request: [String: Any], ticket: UInt64) throws -> RestorePreview {
    previewTickets.removeAll()
    _ = try core.invoke(["operation": "cancel"])
    let preview = try core.decode(request, as: RestorePreview.self)
    do {
      return try lifecycle.withCurrent(ticket) {
        previewTickets[preview.token] = ticket
        return preview
      }
    } catch {
      _ = try? core.invoke(["operation": "cancel"])
      throw error
    }
  }
  public func approveRestoreTrust(_ trust: Data) throws {
    _ = try core.invoke([
      "operation": "approve_restore_trust", "trust": JSONSerialization.jsonObject(with: trust),
    ])
    previewTickets.removeAll()
  }
  public func cancel() {
    previewTickets.removeAll()
    _ = try? core.invoke(["operation": "cancel"])
  }
  public func lock() {
    previewTickets.removeAll()
    _ = try? core.invoke(["operation": "lock"])
  }
}
