#if os(macOS)
import Foundation
import ZenithKit

/// Only fixed protocol codes become user-facing diagnostics. Server response
/// text may contain private details and must never be copied into the UI.
struct NativeOperatorServerError: LocalizedError {
  let status: Int
  let code: String
  var errorDescription: String? {
    let known: Set<String> = ["invalid_operator_selection", "operator_access_denied",
      "operator_request_changed", "operator_assignment_changed", "write_activation_unavailable",
      "write_activation_upgrade_required", "native_admission_required", "mixed_activation_unavailable",
      "activation_unavailable", "activation_upgrade_required", "operator_result_unknown"]
    let diagnostic = known.contains(code) ? "; " + code : ""
    return "The server could not prepare this step (HTTP \(status)\(diagnostic)). Your selection is preserved."
  }
}

struct NativeOperatorInbox {
  let raw: [String: Any]
  let ceiling: [String: Any]
  let digest: String
  let permissions: NativeGrantPermissions
  let requests: [NativeGrantRecipient]
  let total: Int
  let next: String?
  let catalog: WorkAccessCatalog?
  let activation: [String: Any]
  let activeGrants: [[String: Any]]
  init(_ raw: [String: Any], resource: RegisteredResource) throws {
    guard let inbox = raw["inbox"] as? [String: Any], let total = GrantJSON.integer(inbox["total"]),
      let ceiling = raw["ceiling"] as? [String: Any],
      ceiling["receiver"] as? String == resource.id, ceiling["issuer"] as? String == resource.configuration.issuer,
      GrantJSON.hex(raw["ceiling_digest_sha256"], 64),
      try GrantJSON.digest(ceiling) == raw["ceiling_digest_sha256"] as? String else { throw NativeGrantError.invalid }
    let rows = try GrantJSON.rows(inbox["items"])
    guard rows.count <= total, rows.count <= 100 else { throw NativeGrantError.invalid }
    requests = try rows.map(NativeGrantRecipient.init)
    guard Set(requests.map(\.id)).count == requests.count else { throw NativeGrantError.invalid }
    self.total = total; self.ceiling = ceiling; self.raw = raw
    digest = raw["ceiling_digest_sha256"] as! String; permissions = try NativeGrantPermissions(ceiling)
    if let value = inbox["next_cursor"], !(value is NSNull) {
      guard GrantJSON.hex(value, 32) else { throw NativeGrantError.invalid }; next = value as? String
    } else { next = nil }
    activation = raw["activation"] as? [String: Any] ?? [:]
    activeGrants = try GrantJSON.rows(raw["active_grants"] ?? [[String: Any]]())
    if var data = raw["catalog"] as? [String: Any], raw["scope_inventory_unavailable"] as? Bool != true {
      data["scopes"] = raw["scopes"] ?? [[String: Any]](); data["scope_semantics"] = "current_resources_at_access"
      catalog = try WorkAccessCatalog.decode(GrantJSON.data(data), receiver: resource.id, issuer: resource.configuration.issuer)
    } else { catalog = nil }
  }
  var scopes: [WorkScopeOption] { catalog?.scopes ?? [] }
  func actionSchema(writes: Bool) -> String? {
    let value = activation[writes ? "write_action_schema" : "read_action_schema"] as? String
    let allowed = writes ? ["devgraph.access-operator-action.v3", "devgraph.access-operator-action.v5", "devgraph.access-operator-action.v7"] : ["devgraph.access-operator-action.v2", "devgraph.access-operator-action.v4", "devgraph.access-operator-action.v6"]
    return value.flatMap { allowed.contains($0) ? $0 : nil }
  }
}

/// Native state machine. Journal bytes and original action IDs survive lock,
/// closure, relaunch and an uncertain HTTP outcome. Signing remains in Wallet.
@MainActor final class NativeOperatorClient {
  enum State: Equatable { case idle, prepared, unknown }
  let bridge: TransferOperatorBridge
  private(set) var state: State = .idle
  private(set) var original: [String: Any]?
  private(set) var challenge: [String: Any]?
  private var recoveryAction: [String: Any]?
  private var executing = false
  private func begin() throws {
    guard !executing else { throw NativeGrantError.busy }; executing = true
  }
  init(bridge: TransferOperatorBridge) throws {
    self.bridge = bridge
    if let data = try bridge.retainedNativeAction() {
      original = try GrantJSON.object(data)
      state = original?["dispatched"] as? Bool == true ? .unknown : .prepared
    }
  }
  var action: [String: Any]? { recoveryAction ?? original?["action"] as? [String: Any] }
  var now: Int { Int(Date().timeIntervalSince1970) }
  var approvalExpired: Bool { (GrantJSON.integer(challenge?["expires_at"]) ?? 0) <= now }
  private func identity() async throws -> [String: Any] {
    guard let value = try await bridge.invokeNative("identity") as? String else { throw NativeGrantError.invalid }
    return try GrantJSON.object(Data(value.utf8))
  }
  private func post(_ path: String, _ body: [String: Any]) async throws -> [String: Any] {
    let text = String(decoding: try GrantJSON.data(body), as: UTF8.self)
    guard let response = try await bridge.invokeNative("post", ["path": path, "body": text]) as? [String: Any],
      let status = response["status"] as? Int, let text = response["body"] as? String else { throw NativeGrantError.invalid }
    guard (200..<300).contains(status) else {
      let raw = try? GrantJSON.object(Data(text.utf8)), code = raw?["error"] as? String ?? ""
      throw NativeOperatorServerError(status: status, code: code)
    }
    return try GrantJSON.object(Data(text.utf8))
  }
  private func obtain(_ action: [String: Any], identity: [String: Any]) async throws -> [String: Any] {
    var body = identity; body["action"] = action
    let value = try await post("/devgraph/access-operator/v1/challenges", body)
    guard value["schema"] as? String == "castalia.access-request-challenge.v1",
      value["receiver"] as? String == bridge.resource.id,
      GrantJSON.equal(value["subject_public_key"], identity["subject_public_key"]),
      GrantJSON.equal(value["installation_id"], identity["installation_id"]),
      let details = value["details"] as? [String: Any], GrantJSON.equal(details["action"], action),
      let expires = GrantJSON.integer(value["expires_at"]), expires > now else { throw NativeGrantError.invalid }
    return value
  }
  static func assignmentDigest(_ action: [String: Any]) throws -> Any {
    let schema = action["schema"] as? String ?? "", s = action["selection"] as? [String: Any] ?? [:]
    if s["read"] != nil && s["write"] != nil && ["devgraph.access-operator-action.v5", "devgraph.access-operator-action.v7"].contains(schema) { return try GrantJSON.digest(s) }
    if let write = s["write"], ["devgraph.access-operator-action.v3", "devgraph.access-operator-action.v5", "devgraph.access-operator-action.v7"].contains(schema) { return try GrantJSON.digest(write) }
    if let read = s["read"], ["devgraph.access-operator-action.v2", "devgraph.access-operator-action.v4", "devgraph.access-operator-action.v6"].contains(schema) { return try GrantJSON.digest(read) }
    return NSNull()
  }
  func prepare(_ fields: [String: Any]) async throws {
    try begin(); defer { executing = false }
    guard state == .idle else { throw state == .unknown ? NativeGrantError.recovery : NativeGrantError.busy }
    let identity = try await identity()
    var action = fields
    action["action_id"] = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
    if action["schema"] == nil { action["schema"] = "devgraph.access-operator-action.v1" }
    let challenge = try await obtain(action, identity: identity)
    let record: [String: Any] = ["schema": "devgraph.operator-pending.v1", "origin": bridge.resource.id, "identity": identity,
      "action": action, "assignment_digest": try Self.assignmentDigest(action), "dispatched": false]
    _ = try await bridge.invokeNative("save", ["record": String(decoding: try GrantJSON.data(record), as: UTF8.self)])
    original = record; self.challenge = challenge; state = .prepared
  }
  func refreshPrepared() async throws {
    try begin(); defer { executing = false }
    guard state == .prepared, let action, let old = original else { throw NativeGrantError.busy }
    let identity = try await identity()
    guard GrantJSON.equal(identity, old["identity"]) else { throw NativeGrantError.changed }
    challenge = try await obtain(action, identity: identity)
  }
  func cancelPrepared() async throws {
    try begin(); defer { executing = false }
    guard state == .prepared, recoveryAction == nil, original?["dispatched"] as? Bool == false else { throw NativeGrantError.recovery }
    _ = try await bridge.invokeNative("clear"); original = nil; challenge = nil; state = .idle
  }
  func prepareRecovery() async throws {
    try begin(); defer { executing = false }
    guard state == .unknown, let originalAction = original?["action"] as? [String: Any], let originalID = originalAction["action_id"] as? String else { throw NativeGrantError.recovery }
    let identity = try await identity()
    guard GrantJSON.equal(identity, original?["identity"]) else { throw NativeGrantError.changed }
    let action: [String: Any] = ["schema": "devgraph.access-operator-action.v1", "action": "status", "original_action_id": originalID,
      "action_id": UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()]
    let challenge = try await obtain(action, identity: identity)
    recoveryAction = action; self.challenge = challenge; state = .prepared
  }
  func confirm() async throws -> [String: Any] {
    try begin(); defer { executing = false }
    guard state == .prepared, let challenge, let action else { throw NativeGrantError.busy }
    guard !approvalExpired else { throw NativeGrantError.expired }
    let proofText = try await bridge.invokeNative("approve", ["challenge": String(decoding: try GrantJSON.data(challenge), as: UTF8.self)])
    guard let text = proofText as? String else { throw NativeGrantError.invalid }
    let proof = try GrantJSON.object(Data(text.utf8))
    // The bridge persists dispatched=true before any /actions network call.
    state = .unknown; original?["dispatched"] = true
    let result: [String: Any]
    do { result = try await post("/devgraph/access-operator/v1/actions", proof) }
    catch {
      if recoveryAction == nil, let e = error as? NativeOperatorServerError,
        [400,401,409].contains(e.status), Self.closedRejections.contains(e.code) {
        _ = try await bridge.invokeNative("clear"); original = nil; self.challenge = nil; state = .idle
        throw NativeGrantError.changed
      }
      throw NativeGrantError.recovery
    }
    do {
      let accepted = try validate(result, pending: action)
      _ = try await bridge.invokeNative("clear")
      original = nil; self.challenge = nil; recoveryAction = nil; state = .idle
      return accepted
    } catch { recoveryAction = nil; self.challenge = nil; state = .unknown; throw NativeGrantError.recovery }
  }
  private static let closedRejections: Set<String> = ["invalid_operator_selection", "operator_access_denied", "operator_request_changed", "operator_assignment_changed", "write_activation_unavailable", "write_activation_upgrade_required", "native_admission_required", "mixed_activation_unavailable", "activation_unavailable", "activation_upgrade_required"]

  private func validate(_ response: [String: Any], pending: [String: Any]) throws -> [String: Any] {
    func envelope(_ value: [String: Any], _ action: [String: Any]) -> Bool {
      ["devgraph.access-operator-result.v1", "devgraph.access-operator-result.v2"].contains(value["schema"] as? String ?? "") &&
        GrantJSON.equal(value["action_id"], action["action_id"]) && GrantJSON.bool(value["authority_issued"]) == false
    }
    guard envelope(response, pending) else { throw NativeGrantError.recovery }
    var result = response; var action = pending
    if let recoveryAction {
      guard let originalAction = original?["action"] as? [String: Any],
        GrantJSON.equal(response["original_action_id"], originalAction["action_id"]),
        response["status"] as? String == "reconciled", let nested = response["result"] as? [String: Any],
        envelope(nested, originalAction), GrantJSON.equal(recoveryAction, pending) else { throw NativeGrantError.recovery }
      result = nested; action = originalAction
    }
    let name = action["action"] as? String ?? ""
    let activation = result["activation"] as? [String: Any] ?? [:]
    let sameRequest = GrantJSON.equal(result["request_id"], action["request_id"]) && GrantJSON.equal(result["request_digest_sha256"], action["request_digest_sha256"])
    let digest = original?["assignment_digest"]
    switch name {
    case "inbox": _ = try NativeOperatorInbox(result, resource: bridge.resource)
    case "review":
      guard sameRequest, GrantJSON.equal(result["review_id"], action["action_id"]),
        GrantJSON.equal(result["expected_version"], action["expected_version"]),
        let selection = action["selection"] as? [String: Any], GrantJSON.equal(result["selection"], selection),
        result["selection_digest_sha256"] as? String == (try GrantJSON.digest(selection)),
        let plans = result["plans"] as? [String: Any] else { throw NativeGrantError.recovery }
      if action["schema"] as? String != "devgraph.access-operator-action.v1" {
        guard let a = plans["activation"] as? [String: Any], GrantJSON.equal(a["assignment_digest"], digest) else { throw NativeGrantError.recovery }
        for key in ["previous_assignment_digest", "previous_write_assignment_digest"] {
          if let expected = action[key] {
            guard GrantJSON.equal(a[key], expected) else { throw NativeGrantError.recovery }
          }
        }
      }
    case "approve":
      guard GrantJSON.equal(result["request_id"], action["request_id"]), GrantJSON.integer(result["version"]) == 2 else { throw NativeGrantError.recovery }
      if action["schema"] as? String == "devgraph.access-operator-action.v1" {
        guard result["status"] as? String == "approved_pending_activation" else { throw NativeGrantError.recovery }
      } else {
        guard sameRequest, result["status"] as? String == "active", GrantJSON.bool(activation["active"]) == true,
          GrantJSON.bool(activation["credential_issued"]) == false, GrantJSON.equal(activation["assignment_digest"], digest) else { throw NativeGrantError.recovery }
      }
    case "deny":
      guard GrantJSON.equal(result["request_id"], action["request_id"]), result["status"] as? String == "denied", GrantJSON.integer(result["version"]) == 2 else { throw NativeGrantError.recovery }
    case "revoke":
      guard sameRequest, result["status"] as? String == "revoked", GrantJSON.integer(result["version"]) == 3,
        GrantJSON.bool(activation["active"]) == false, GrantJSON.equal(activation["assignment_digest"], action["previous_assignment_digest"]) else { throw NativeGrantError.recovery }
      if let previous = action["previous_write_assignment_digest"] {
        guard GrantJSON.equal(activation["write_assignment_digest"], previous) else { throw NativeGrantError.recovery }
      }
    default: throw NativeGrantError.recovery
    }
    return result
  }
}
#endif
