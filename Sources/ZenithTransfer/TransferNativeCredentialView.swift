#if os(macOS)
import SwiftUI
import ZenithKit

@MainActor final class NativeCredentialModel: ObservableObject {
  let bridge: TransferOperatorBridge
  private var client: NativeOperatorClient?
  @Published var state: NativeOperatorClient.State = .idle
  @Published var inbox: NativeOperatorInbox?
  @Published var selected: NativeGrantRecipient?
  @Published var choice = NativeGrantChoice()
  struct RuleDraft: Identifiable {
    let id = UUID()
    var choice = NativeGrantChoice()
    var scopeMode = "choose"
    var futureArenaMode = false
    var arenaReadEnabled = false
    var exactIDText: [String: String] = [:]
  }
  @Published var ruleDrafts: [RuleDraft] = []
  @Published var ruleIndex = 0
  @Published var exactIDText: [String: String] = [:]
  @Published var futureArenaMode = false
  @Published var arenaReadEnabled = false
  @Published var presetID = "custom"
  @Published var recipeNotice: String?
  @Published var scopeMode = "choose"
  @Published var hierarchyMode = false
  @Published var hierarchy = NativeHierarchyPermissions()
  @Published var hierarchyError: String?
  @Published var requestConfigurationError: String?
  private(set) var requestedConfiguration: NativeRequestedConfiguration?
  private(set) var existingConfiguration: NativeExistingGrantConfiguration?
  @Published var expanded: Set<String> = []
  @Published var review: [String: Any]?
  @Published var busy = false
  @Published var error: String?
  @Published var resultNotice: String?
  @Published var status = "Unlock Wallet, then review this resource’s requests."
  @Published var declineReason = ""
  private var presetReference: [String: Any]?
  init(bridge: TransferOperatorBridge) {
    self.bridge = bridge
    do { client = try NativeOperatorClient(bridge: bridge); state = client!.state }
    catch { self.error = "The original action could not be read safely. Its record is preserved." }
  }
  var preparedName: String {
    let action = client?.action?["action"] as? String ?? "action"
    return action == "upgrade_arena_policy" ? "authorization data update" : action.replacingOccurrences(of: "_", with: " ")
  }
  var isRecovery: Bool { client?.action?["action"] as? String == "status" || client?.action?["action"] as? String == "arena_policy_status" || client?.action?["action"] as? String == "arena_create_status" }
  var expiry: Date? { GrantJSON.integer(client?.challenge?["expires_at"]).map { Date(timeIntervalSince1970: Double($0)) } }
  func run(_ operation: @escaping () async throws -> Void) {
    guard !busy else { return }; busy = true; error = nil
    Task {
      defer { state = client?.state ?? .idle; busy = false }
      do { try await operation() }
      catch {
        if let e = error as? NativeGrantRuleError { self.error = e.errorDescription }
        else if let e = error as? NativeRequestedConfigurationError { self.error = e.errorDescription }
        else if let e = error as? NativeExistingGrantError { self.error = e.errorDescription }
        else if let e = error as? NativeGrantError { self.error = e.errorDescription }
        else if let e = error as? WalletFailure { self.error = NativeCredentialDiagnostic.message(e) }
        else if let e = error as? LocalAdminRPCError { self.error = e.errorDescription }
        else if let e = error as? NativeOperatorServerError { self.error = e.errorDescription }
        else { self.error = "Could not finish this step. Check the Wallet and saved server connection." }
      }
    }
  }
  func loadInbox(after: String? = nil) {
    run { [self] in
      guard let client else { throw NativeGrantError.invalid }
      try accept(await client.loadInbox(after: after))
    }
  }
  func loadServiceInbox(after: String? = nil) async throws {
    guard !busy, let client else { throw NativeGrantError.busy }
    busy = true; error = nil
    defer { state = client.state; busy = false }
    try accept(await client.loadInbox(after: after, allowAuthorizationUpdate: false))
  }
  func createArena(id: String, title: String, description: String) {
    run { [self] in
      guard let info = inbox?.raw["owner_arena_upgrade"] as? [String:Any], info["create_arenas"] as? Bool == true,
        let digest = info["policy_digest_sha256"] as? String, let client,
        id.range(of:"^[a-z0-9][a-z0-9-]{0,255}$",options:.regularExpression) != nil,
        !title.trimmingCharacters(in:.whitespacesAndNewlines).isEmpty else { throw NativeGrantError.invalid }
      try await client.prepare(["schema":"devgraph.access-operator-action.v11", "action":"create_arena",
        "expected_policy_digest_sha256":digest, "request":["schema":"devgraph.arena-request.v1", "operation":"create",
          "kind":"Arena","id":id,"expected_version":NSNull(),"payload":["id":id,"title":title,"description":description]]])
      state = client.state; try accept(await client.confirm())
    }
  }
  func select(_ item: NativeGrantRecipient) {
    guard !busy, state == .idle, let inbox else { return }
    existingConfiguration = nil
    selected = item; review = nil; presetID = "custom"; presetReference = nil; recipeNotice = nil
    choice = NativeGrantChoice(); exactIDText = [:]; futureArenaMode = false; arenaReadEnabled = defaultsToArenaRead; scopeMode = "choose"; expanded = []
    choice.kinds = Set(inbox.permissions.kinds).intersection(["Initiative", "Project", "Issue", "Task", "Todo", "Proposal"])
    choice.untilRevoked = inbox.permissions.validity.notAfter == nil
    if let end = inbox.permissions.validity.notAfter { choice.expiry = Date(timeIntervalSince1970: Double(end)) }
    ruleDrafts = []; ruleIndex = 0
    hierarchy = NativeHierarchyPermissions(); hierarchyError = nil; hierarchyMode = false
    requestedConfiguration = nil; requestConfigurationError = nil
    do {
      let requested = try NativeRequestedConfiguration(recipient: item, inbox: inbox)
      requestedConfiguration = requested
      if requested.hasRequestedFields {
        hierarchyMode = false
        if let preset = requested.preset {
          choice.reads = Set(preset.read_operations); choice.writes = Set(preset.write_operations)
          // A requested preset fixes its action set; the new-draft default must
          // not append Arena reads that the requester did not ask for.
          arenaReadEnabled = false
          presetID = "server:" + preset.id; presetReference = requested.reference
        }
        if let paths = requested.paths { choice.paths = paths; scopeMode = "paths" }
      }
    } catch {
      hierarchyMode = false
      requestConfigurationError = (error as? NativeRequestedConfigurationError)?.errorDescription ?? NativeRequestedConfigurationError.unsupported.errorDescription
    }
    updateArenaCoverage()
    ruleDrafts = [RuleDraft(choice: choice, scopeMode: scopeMode, arenaReadEnabled: arenaReadEnabled)]
    declineReason = ""
    status = "Choose the permissions and resources for this credential. No access has been granted."
  }
  func configure(_ grant: [String:Any]) {
    guard !busy, state == .idle, let inbox else { return }
    selected = nil; review = nil; existingConfiguration = nil
    do {
      let configuration = try NativeExistingGrantConfiguration(grant:grant, inbox:inbox, now:Int(Date().timeIntervalSince1970))
      select(configuration.recipient)
      existingConfiguration = configuration
      // An already approved request's preference is history, not an editing lock.
      requestedConfiguration = nil; requestConfigurationError = nil
      ruleDrafts = configuration.rules.map { rule in
        RuleDraft(choice:rule, scopeMode:rule.exactResources != nil ? "exact" : rule.wholeGraph ? "global" : "paths",
          futureArenaMode:rule.allArenas, arenaReadEnabled:rule.allArenas || !rule.arenaIDs.isEmpty,
          exactIDText:rule.exactResources?.mapValues { $0.sorted().joined(separator:", ") } ?? [:])
      }
      ruleIndex = 0; choice = ruleDrafts[0].choice; scopeMode = ruleDrafts[0].scopeMode
      futureArenaMode = ruleDrafts[0].futureArenaMode; arenaReadEnabled = ruleDrafts[0].arenaReadEnabled
      exactIDText = ruleDrafts[0].exactIDText
      error = nil; status = "Editing a draft of the existing grant. Current access stays unchanged until you approve the changes in Wallet."
    } catch {
      self.error = (error as? NativeExistingGrantError)?.errorDescription ?? NativeExistingGrantError.unsupported.errorDescription
    }
  }
  func discardConfiguration() {
    guard !busy, state == .idle else { return }
    selected = nil; review = nil; existingConfiguration = nil
    status = "Draft discarded. The existing grant is unchanged."
  }
  func beginHierarchySelection() {
    guard requestedConfiguration?.hasRequestedFields != true, requestConfigurationError == nil,
      inbox?.permissions.supportsPaths == true, inbox?.catalog != nil,
      scopeMode == "choose", permissionRules.allSatisfy({ $0.reads.isEmpty && $0.writes.isEmpty && $0.arenaIDs.isEmpty && !$0.allArenas }) else { return }
    hierarchyMode = true
  }
  func applyPreset(_ id: String, library: TransferPresetLibrary) {
    guard requestedConfiguration?.locksPermissions != true else { return }
    guard let inbox else { return }
    presetID = id; presetReference = nil; review = nil
    let reads: [String], writes: [String]
    choice.arenaIDs = []
    arenaReadEnabled = library.available.first { "local:" + $0.id == id }?.arenaRead == true
    if id.hasPrefix("server:"), let recipe = inbox.catalog?.presets.first(where: { "server:" + $0.id == id }) {
      reads = recipe.read_operations; writes = recipe.write_operations
      presetReference = ["id": recipe.id, "version": recipe.version, "catalog_digest_sha256": inbox.catalog!.catalog_digest_sha256]
    } else if let recipe = library.available.first(where: { "local:" + $0.id == id }) {
      reads = recipe.readOperations; writes = recipe.writeOperations.map { "devgraph.work." + $0 + ".v2" }
    } else { recipeNotice = nil; return }
    choice.reads = Set(reads).intersection(inbox.permissions.reads)
    let supported = Set(DevGraphPermissionCatalog.writes.map(\.id))
    choice.writes = Set(writes).intersection(inbox.permissions.writes).intersection(supported)
    if inbox.activation["write"] as? Bool == false { choice.writes = [] }
    if !choice.paths.isEmpty { choice.writes.remove("devgraph.work.create.v2") }
    let omitted = Set(reads).subtracting(choice.reads).count + Set(writes).subtracting(choice.writes).count
    updateArenaCoverage()
    recipeNotice = (arenaReadEnabled ? "Arena reads follow the selected scope. " : "") + (omitted > 0 ? "\(omitted) recipe permissions are unavailable for this server or path. Only the checked permissions will be reviewed." : "This recipe selects actions only. Choose scope separately.")
  }
  func editedPermissions() {
    review = nil; recipeNotice = nil
    if requestedConfiguration?.locksPermissions != true { presetID = "custom"; presetReference = nil }
  }
  func changeScope(_ value: String) {
    guard requestedConfiguration?.locksScope != true else { return }
    scopeMode = value; choice.wholeGraph = value == "global"
    futureArenaMode = value == "global" && canReadFutureArenas
    if value != "paths" { choice.paths = [] }
    choice.exactResources = value == "exact" ? Dictionary(uniqueKeysWithValues: choice.kinds.map { ($0, Set<String>()) }) : nil
    exactIDText = [:]
    updateArenaCoverage(); editedPermissions()
  }
  func storeRule() {
    guard ruleDrafts.indices.contains(ruleIndex) else { return }
    ruleDrafts[ruleIndex].choice = choice; ruleDrafts[ruleIndex].scopeMode = scopeMode
    ruleDrafts[ruleIndex].futureArenaMode = futureArenaMode
    ruleDrafts[ruleIndex].arenaReadEnabled = arenaReadEnabled
    ruleDrafts[ruleIndex].exactIDText = exactIDText
  }
  func selectRule(_ index: Int) {
    guard ruleDrafts.indices.contains(index), index != ruleIndex else { return }
    storeRule(); let validity = choice
    ruleIndex = index; choice = ruleDrafts[index].choice
    choice.untilRevoked = validity.untilRevoked; choice.expiry = validity.expiry
    futureArenaMode = ruleDrafts[index].futureArenaMode; scopeMode = ruleDrafts[index].scopeMode; arenaReadEnabled = ruleDrafts[index].arenaReadEnabled; exactIDText = ruleDrafts[index].exactIDText
    review = nil; expanded = []; editedPermissions()
  }
  func addRule() {
    guard requestConfigurationError == nil, ruleDrafts.count < 16 else { return }
    storeRule(); let current = choice
    var next = NativeGrantChoice(); next.kinds = current.kinds
    if let requested = requestedConfiguration {
      if let preset = requested.preset { next.reads = Set(preset.read_operations); next.writes = Set(preset.write_operations) }
      if let paths = requested.paths { next.paths = paths }
    }
    next.untilRevoked = current.untilRevoked; next.expiry = current.expiry
    let arenaRead = defaultsToArenaRead && requestedConfiguration?.locksPermissions != true
    if arenaRead { next.arenaIDs = NativeGrantSelection.arenaCoverage(next, available: inbox?.permissions.arenaIDs ?? []) }
    ruleDrafts.append(RuleDraft(choice: next, scopeMode: requestedConfiguration?.locksScope == true ? "paths" : "choose",
      arenaReadEnabled: arenaRead)); selectRule(ruleDrafts.count - 1)
  }
  func removeRule() {
    guard ruleDrafts.count > 1 else { return }
    ruleDrafts.remove(at: ruleIndex); ruleIndex = min(ruleIndex, ruleDrafts.count - 1)
    let old = choice; choice = ruleDrafts[ruleIndex].choice
    choice.untilRevoked = old.untilRevoked; choice.expiry = old.expiry
    futureArenaMode = ruleDrafts[ruleIndex].futureArenaMode; scopeMode = ruleDrafts[ruleIndex].scopeMode; arenaReadEnabled = ruleDrafts[ruleIndex].arenaReadEnabled; exactIDText = ruleDrafts[ruleIndex].exactIDText
    editedPermissions()
  }
  var permissionRules: [NativeGrantChoice] {
    if hierarchyMode { return (try? hierarchyRules()) ?? [] }
    return advancedRules
  }
  private var advancedRules: [NativeGrantChoice] {
    ruleDrafts.enumerated().map { index, draft in
      var result = index == ruleIndex ? choice : draft.choice
      result.untilRevoked = choice.untilRevoked; result.expiry = choice.expiry
      return result
    }
  }
  func hierarchyRules() throws -> [NativeGrantChoice] {
    guard let inbox else { throw NativeGrantError.invalid }
    return try hierarchy.rules(permissions: inbox.permissions, validity: choice)
  }
  func useAdvancedRules() {
    guard hierarchyMode else { return }
    do {
      let rules = try hierarchyRules()
      ruleDrafts = rules.isEmpty ? [RuleDraft(choice: choice)] : rules.map { RuleDraft(choice: $0, scopeMode: "paths", arenaReadEnabled: !$0.arenaIDs.isEmpty) }
      ruleIndex = 0; choice = ruleDrafts[0].choice; scopeMode = ruleDrafts[0].scopeMode
      arenaReadEnabled = ruleDrafts[0].arenaReadEnabled; futureArenaMode = false; exactIDText = [:]
      hierarchyMode = false; editedPermissions()
    } catch { self.error = NativeCredentialDiagnostic.message(error) }
  }
  func setHierarchy(_ row: WorkScopeOption, access: NativeHierarchyPermissions.Access, enabled: Bool) {
    do {
      var candidate = hierarchy
      try candidate.set(row.resource_path, access, enabled: enabled)
      guard let inbox, let selected else { throw NativeGrantError.invalid }
      let rules = try candidate.rules(permissions: inbox.permissions, validity: choice)
      if !rules.isEmpty {
        _ = try NativeGrantSelection.makeRules(ceiling: inbox.ceiling, ceilingDigest: inbox.digest,
          recipient: selected, rules: rules, scopes: inbox.scopes, now: Int(Date().timeIntervalSince1970))
      }
      hierarchy = candidate; hierarchyError = nil; editedPermissions()
    } catch {
      hierarchyError = "This combination exceeds the grant’s supported limits or permitted scope. Your earlier selections are preserved. Narrow the selected branches or actions."
    }
  }
  func hierarchyAvailable(_ row: WorkScopeOption, access: NativeHierarchyPermissions.Access) -> Bool {
    guard let inbox, let selected else { return false }
    if access == .write && inbox.activation["write"] as? Bool == false { return false }
    if inbox.activation["mixed"] as? Bool == false &&
      (access == .read ? !hierarchy.writePaths.isEmpty : !hierarchy.readPaths.isEmpty) { return false }
    do {
      var single = NativeHierarchyPermissions(); try single.set(row.resource_path, access, enabled: true)
      _ = try NativeGrantSelection.makeRules(ceiling: inbox.ceiling, ceilingDigest: inbox.digest,
        recipient: selected, rules: single.rules(permissions: inbox.permissions, validity: choice), scopes: inbox.scopes, now: Int(Date().timeIntervalSince1970))
      return true
    } catch { return false }
  }
  func ruleSummary(_ index: Int) -> String {
    let rule = index == ruleIndex ? choice : ruleDrafts[index].choice
    return "Rule \(index + 1) · \(rule.reads.count + (rule.arenaIDs.isEmpty && !rule.allArenas ? 0 : 1)) read · \(rule.writes.count) write · " +
      (rule.wholeGraph ? "all permitted" : rule.exactResources != nil ? "exact IDs" : "\(rule.paths.count) branches")
  }
  func setKind(_ kind: String, enabled: Bool) {
    if enabled { choice.kinds.insert(kind); if choice.exactResources != nil { choice.exactResources?[kind] = [] } }
    else { choice.kinds.remove(kind); choice.exactResources?.removeValue(forKey: kind); exactIDText.removeValue(forKey: kind) }
    updateArenaCoverage(); editedPermissions()
  }
  func setExactIDs(_ kind: String, text: String) {
    exactIDText[kind] = text
    choice.exactResources?[kind] = Set(text.split { $0 == "," || $0.isWhitespace }.map(String.init))
    updateArenaCoverage(); editedPermissions()
  }
  var coveredArenaIDs: Set<String> {
    NativeGrantSelection.arenaCoverage(choice, available: inbox?.permissions.arenaIDs ?? [])
  }
  private var defaultsToArenaRead: Bool {
    guard let inbox, inbox.activation["read"] as? Bool != false else { return false }
    return inbox.permissions.allArenas || !inbox.permissions.arenaIDs.isEmpty
  }
  var canReadFutureArenas: Bool { inbox?.permissions.allArenas == true && inbox?.activation["future_arena_reads"] as? Bool == true }
  func setFutureArenaMode(_ enabled: Bool) {
    guard !enabled || canReadFutureArenas && choice.wholeGraph else { return }
    futureArenaMode = enabled; updateArenaCoverage(); editedPermissions()
  }
  private func updateArenaCoverage() {
    choice.allArenas = arenaReadEnabled && futureArenaMode && choice.wholeGraph && canReadFutureArenas
    choice.arenaIDs = arenaReadEnabled && !choice.allArenas ? coveredArenaIDs : []
  }
  func setArenaRead(_ enabled: Bool) {
    arenaReadEnabled = enabled; updateArenaCoverage(); editedPermissions()
  }
  func choose(_ row: WorkScopeOption, selected: Bool) {
    guard requestedConfiguration?.locksScope != true else { return }
    do {
      choice.paths = try WorkScopeSelection.normalized(selected ? choice.paths + [row.resource_path] : choice.paths.filter { $0 != row.resource_path })
      updateArenaCoverage()
      review = nil
    } catch { self.error = "Select at most 16 independent branches." }
  }
  func allocateRequestedPath(_ path: WorkResourcePath, enabled: Bool) {
    guard requestedConfiguration?.paths?.contains(path) == true else { return }
    if enabled { if !choice.paths.contains(path) { choice.paths.append(path) } }
    else { choice.paths.removeAll { $0 == path } }
    updateArenaCoverage(); editedPermissions()
  }
  func inherited(_ row: WorkScopeOption) -> Bool { choice.paths.contains { $0 != row.resource_path && WorkScopeSelection.covers($0, row.resource_path) } }
  func reviewSelection() {
    run { [self] in
      guard let inbox, let selected, let client else { throw NativeGrantError.invalid }
      guard requestConfigurationError == nil else { throw NativeRequestedConfigurationError.unsupported }
      let rules = try hierarchyMode ? hierarchyRules() : advancedRules
      try requestedConfiguration?.validate(rules)
      if rules.contains(where: { $0.allArenas }) && !canReadFutureArenas { throw NativeGrantError.permissions }
      if rules.contains(where: { !$0.writes.isEmpty }) && inbox.activation["write"] as? Bool == false { throw NativeGrantError.permissions }
      if rules.contains(where: { !$0.reads.isEmpty || !$0.arenaIDs.isEmpty || $0.allArenas }) && rules.contains(where: { !$0.writes.isEmpty }) && inbox.activation["mixed"] as? Bool == false { throw NativeGrantError.permissions }
      var selection = try NativeGrantSelection.makeRules(ceiling: inbox.ceiling, ceilingDigest: inbox.digest,
        recipient: selected, rules: rules, scopes: inbox.scopes, preset: ruleDrafts.count == 1 ? presetReference : nil, now: client.now)
      if let existingConfiguration { selection = try existingConfiguration.preservingLimits(selection) }
      try requestedConfiguration?.validateCompiled(selection)
      var action = try selectionAction("review", selection: selection)
      action["action"] = "review"
      try await client.prepare(action); state = client.state
      try accept(await client.confirm())
    }
  }
  private func selectionAction(_ name: String, selection: [String: Any]) throws -> [String: Any] {
    guard let inbox, let selected else { throw NativeGrantError.invalid }
    var action: [String: Any] = ["action": name, "request_id": selected.id, "request_digest_sha256": selected.digest,
      "expected_version": selected.version, "selection": selection]
    let writing = selection["write"] != nil
    if inbox.activation["read"] as? Bool == true {
      guard let schema = inbox.actionSchema(writes: writing) else { throw NativeGrantError.invalid }
      action["schema"] = schema
      action["previous_assignment_digest"] = selected.raw[writing && selection["read"] == nil ? "previous_write_assignment_digest" : "previous_assignment_digest"] ?? NSNull()
      if writing && selection["read"] != nil { action["previous_write_assignment_digest"] = selected.raw["previous_write_assignment_digest"] ?? NSNull() }
    }
    return action
  }
  func approveSelection() {
    run { [self] in
      guard let review, let selection = review["selection"] as? [String: Any], let client else { throw NativeGrantError.invalid }
      var action = try selectionAction("approve", selection: selection)
      action["review_id"] = review["review_id"]
      try await client.prepare(action); state = client.state
      try accept(await client.confirm())
    }
  }
  func decline() {
    run { [self] in
      guard let selected, let client, !declineReason.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { throw NativeGrantError.invalid }
      try await client.prepare(["action": "deny", "request_id": selected.id, "request_digest_sha256": selected.digest,
        "expected_version": selected.version, "reason": String(declineReason.prefix(512))]); state = client.state
      try accept(await client.confirm())
    }
  }
  func resume() {
    run { [self] in
      guard let client else { throw NativeGrantError.invalid }
      let originalName = client.action?["action"] as? String
      if client.state == .unknown { try await client.prepareRecovery() }
      else if client.state == .prepared { try await client.refreshPrepared() }
      state = client.state
      let result = try await client.confirm()
      if originalName == "upgrade_arena_policy", result["applied"] as? Bool == true {
        try accept(await client.loadInbox())
      } else { try accept(result) }
    }
  }
  func cancelPrepared() {
    run { [self] in guard let client else { throw NativeGrantError.invalid }; try await client.cancelPrepared(); status = "Unsigned action cancelled. No grant decision was submitted." }
  }
  func revoke(_ grant: [String: Any], reason: String) {
    run { [self] in
      guard let inbox, let client, !reason.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { throw NativeGrantError.invalid }
      let writing = ["write", "read_write"].contains(grant["access_mode"] as? String ?? "")
      guard let schema = inbox.actionSchema(writes: writing),
        let requestID = grant["request_id"], GrantJSON.hex(requestID, 32),
        let requestDigest = grant["request_digest_sha256"], GrantJSON.hex(requestDigest, 64),
        let version = GrantJSON.integer(grant["version"]), version > 0,
        let assignment = grant["assignment_digest"], GrantJSON.hex(assignment, 64),
        let subject = grant["subject_public_key"], GrantJSON.hex(subject, 64),
        let installation = grant["installation_id"], GrantJSON.hex(installation, 32)
      else { throw NativeGrantError.invalid }
      var action: [String: Any] = ["action": "revoke", "schema": schema, "reason": String(reason.prefix(512)),
        "request_id": requestID, "request_digest_sha256": requestDigest,
        "expected_version": version, "previous_assignment_digest": assignment,
        "target_public_key": subject, "target_installation_id": installation]
      if grant["access_mode"] as? String == "read_write" { action["previous_write_assignment_digest"] = grant["write_assignment_digest"] }
      try await client.prepare(action); state = client.state; try accept(await client.confirm())
    }
  }
  private func accept(_ result: [String: Any]) throws {
    if result["status"] as? String == "unknown", result["result"] is NSNull {
      // The client accepts this only for an exact status check of an inbox or
      // permission preview. Preserve the user's draft; never auto-submit it.
      review = nil
      status = "The previous read-only result is unavailable. Refresh request context or review your selection again. This did not approve or change a grant."
      resultNotice = status
    } else if result["inbox"] != nil {
      inbox = try NativeOperatorInbox(result, resource: bridge.resource); selected = nil; review = nil; existingConfiguration = nil
      status = "Inbox loaded. Select a request to configure its credential."; resultNotice = nil
    } else if result["selection"] != nil {
      // Recovery of a review can return before its inbox was loaded after relaunch.
      // Show its exact snapshot; final approval requires reloading current context.
      review = result; status = "Selection verified by the server. Review the exact credential before approval."
    } else {
      let status = result["status"] as? String ?? ""
      switch status {
      case "active" where result["member_grants_changed"] as? Bool == false:
        self.status = "DevGraph authorization data updated. Existing member grants are unchanged. Reload the inbox to configure credentials."
      case "active": self.status = result["configured_existing_grant"] as? Bool == true ? "Grant updated. The approved changes are now active." : "Grant activated. The recipient can obtain and reuse access while it remains valid."
      case "not_applied": self.status = "The original owner upgrade was closed without applying. Reload the inbox before preparing a new review."
      case "created": self.status = "Arena created. Reload the inbox to share it through an explicit recipient credential."
      case "revoked": self.status = "Grant revoked. Further access under it is denied."
      case "denied": self.status = "Request declined. No access was granted."
      default: self.status = "Decision recorded. Server activation is still required; no active credential is claimed."
      }
      resultNotice = self.status
      selected = nil; review = nil; inbox = nil; existingConfiguration = nil
    }
  }
}

/// Verify the selected access point before constructing a credential editor.
/// A retained legacy action continues on its original transport and receiver.
struct TransferOperatorView: View {
  let resource: RegisteredResource
  let repository: any WalletSession
  @ObservedObject var walletModel: TransferModel
  @State private var resolved: RegisteredResource?
  @State private var resolutionGeneration = 0
  @State private var error: String?
  @Environment(\.dismiss) private var dismiss
  var body: some View {
    Group {
      if let resolved {
        ResolvedTransferOperatorView(resource: resolved, repository: repository, walletModel: walletModel) {
          self.resolved = nil; error = nil; resolutionGeneration += 1
        }
      }
      else {
        VStack(spacing: 20) {
          if let error { Text(error).foregroundStyle(.red) }
          else { ProgressView("Verifying service connection") }
          Button("Close") { dismiss() }
        }.padding(32).frame(minWidth: 700, minHeight: 420)
      }
    }.task(id: resource.id + ":" + String(resolutionGeneration)) {
      do {
        let root = try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
        let journal = try OperatorJournal(directory: root.appendingPathComponent("ZenithTransfer/OperatorActions"), origin: resource.id)
        if try journal.load() != nil {
          resolved = try RegisteredResource(configuration: resource.configuration.withServiceAccessPoint(nil))
          return
        }
        let config = resource.configuration
        let transport = try config.network == .tailscale ? HostTailscaleConnection().transport() : PrivateTransport(workServer: config)
        let updated = try await config.resolveService(transport: transport)
        guard !Task.isCancelled else { transport.cancel(); return }
        resolved = try RegisteredResource(configuration: updated)
      } catch {
        guard !Task.isCancelled else { return }
        self.error = "Could not verify the service connection. Saved settings and original actions are preserved."
      }
    }
  }
}

struct ResolvedTransferOperatorView: View {
  @StateObject private var bridge: TransferOperatorBridge
  @StateObject private var editor: NativeCredentialModel
  @ObservedObject private var walletModel: TransferModel
  @ObservedObject private var library: TransferPresetLibrary
  @State private var unlocking = false
  @State private var creatingPreset = false
  @Environment(\.dismiss) private var dismiss
  private let onRecoveredLegacyAction: () -> Void
  private var embedded = false
  private var serviceName: String?
  private var onBack: (() -> Void)?
  init(resource: RegisteredResource, repository: any WalletSession, walletModel: TransferModel,
       onRecoveredLegacyAction: @escaping () -> Void = {}) {
    self.onRecoveredLegacyAction = onRecoveredLegacyAction
    self.walletModel = walletModel; library = walletModel.presetLibrary
    let bridge = TransferOperatorBridge(resource: resource, repository: repository)
    _bridge = StateObject(wrappedValue: bridge); _editor = StateObject(wrappedValue: NativeCredentialModel(bridge: bridge))
  }
  init(bridge: TransferOperatorBridge, editor: NativeCredentialModel, walletModel: TransferModel,
       serviceName: String, onBack: @escaping () -> Void) {
    _bridge = StateObject(wrappedValue: bridge); _editor = StateObject(wrappedValue: editor)
    self.walletModel = walletModel; library = walletModel.presetLibrary
    self.embedded = true; self.serviceName = serviceName; self.onBack = onBack
    self.onRecoveredLegacyAction = {}
  }
  var unlocked: Bool { walletModel.walletUnlocked }
  var editing: Bool { !editor.busy && editor.state == .idle }
  var body: some View {
    VStack(spacing: 0) {
      HStack {
        VStack(alignment: .leading, spacing: 4) {
          Text("Credentials & requests").font(.title2.bold())
          Text(serviceName ?? (bridge.resource.configuration.name + " · " + bridge.resource.id)).font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
        }
        Spacer()
        Button(unlocked ? "Wallet" : "Unlock Wallet") { unlocking = true }
        if embedded { Button("Back to all requests & grants") { editor.discardConfiguration(); onBack?() }.disabled(editor.busy || editor.state != .idle) }
        else { Button("Close") { bridge.cancel(); dismiss() } }
      }.padding(20)
      Divider()
      ScrollView {
        VStack(alignment: .leading, spacing: 20) {
          if let failure = bridge.failure { Text(failure).foregroundStyle(.red) }
          Label(bridge.transportLabel, systemImage: "desktopcomputer").font(.caption).foregroundStyle(.secondary)
          Label(editor.status, systemImage: "key.horizontal").font(.callout)
          if let error = editor.error { Text(error).foregroundStyle(.red).textSelection(.enabled) }
          if !unlocked { Text("Unlock the Transfer Wallet to authenticate to this resource. Owner setup and credential creation are separate flows.").foregroundStyle(.secondary) }
          HStack {
            Button(embedded ? "Refresh request context in Wallet" : "Review inbox in Wallet") { editor.loadInbox() }.buttonStyle(TransferPrimaryButtonStyle()).disabled(!unlocked || !editing)
            if editor.busy { ProgressView().controlSize(.small) }
          }
          if editor.state != .idle {
            pendingAction
          } else if let inbox = editor.inbox {
            if let info = inbox.raw["owner_arena_upgrade"] as? [String:Any], info["create_arenas"] as? Bool == true {
              NativeArenaCreationView(editor: editor, unlocked: unlocked)
            }
            if !embedded { requestList(inbox) }
            if let selected = editor.selected { credentialEditor(selected, inbox: inbox) }
            else { activeGrants(inbox) }
          }
        }.padding(24).frame(maxWidth: 940, alignment: .leading).frame(maxWidth: .infinity)
      }
    }.frame(minWidth: 980, minHeight: 720)
      .onChange(of: bridge.legacyRecoveryCompleted) { completed in
        if completed && !embedded { bridge.cancel(); onRecoveredLegacyAction() }
      }
      .onChange(of: walletModel.walletUnlocked) { value in if !value { bridge.resolve(false) } }
      .onChange(of: editor.choice) { _ in if editor.state == .idle { editor.review = nil } }
      .sheet(isPresented: $unlocking) {
        VStack(spacing: 0) {
          HStack { Text("Castalia Wallet").font(.headline); Spacer(); Button("Return to credentials") { unlocking = false } }.padding()
          Divider(); TransferWalletView(model: walletModel)
        }.frame(width: 720, height: 660)
      }
      .sheet(isPresented: $creatingPreset) { TransferPresetEditor(library: library, source: nil, duplicate: false) }
      .sheet(item: $bridge.consent, onDismiss: { bridge.resolve(false) }) { consent in
        VStack(alignment: .leading, spacing: 16) {
          Text(bridge.confirmationTitle).font(.title2.bold())
          if let explanation = bridge.confirmationExplanation { Text(explanation).font(.callout) }
          Text("\(consent.receiver)\nIssuer: \(consent.issuer)").textSelection(.enabled)
          Text("Review this exact action. Wallet approval expires at \(consent.expiresAt.formatted()).")
          ScrollView { Text(bridge.disclosure).font(.system(.body, design: .monospaced)).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading) }
          HStack {
            Button("Cancel") { bridge.resolve(false) }; Spacer()
            Button("Approve in Castalia Wallet") { bridge.resolve(true) }.buttonStyle(TransferPrimaryButtonStyle())
          }
        }.padding(24).frame(width: 760, height: 620)
      }
      .onDisappear { if !embedded { bridge.cancel() } }
  }
  private var pendingAction: some View {
    VStack(alignment: .leading, spacing: 12) {
      Text(editor.state == .unknown ? "Recover the original result" : "Prepared \(editor.preparedName) action").font(.headline)
      Text(editor.state == .unknown ? "The original decision may have reached the server. Check its status; no grant will be submitted again automatically." : "This exact action is retained. Resuming refreshes its approval without replacing its action ID or selection.")
      HStack {
        Button(editor.state == .unknown ? "Check original result in Wallet" : "Resume exact action in Wallet") { editor.resume() }
          .buttonStyle(TransferPrimaryButtonStyle()).disabled(!unlocked || editor.busy)
        if editor.state == .prepared && !editor.isRecovery { Button("Cancel unsigned action") { editor.cancelPrepared() }.disabled(editor.busy) }
      }
    }.padding(18).background(Color.primary.opacity(0.04)).cornerRadius(12)
  }
  private func requestList(_ inbox: NativeOperatorInbox) -> some View {
    VStack(alignment: .leading, spacing: 12) {
      Text("Pending requests · \(inbox.total)").font(.headline)
      if inbox.requests.isEmpty { Text("No requests are waiting for review.").foregroundStyle(.secondary) }
      ForEach(inbox.requests) { item in
        Button { editor.select(item) } label: {
          VStack(alignment: .leading, spacing: 4) {
            Text("Wallet " + item.subject.prefix(12) + "…").font(.headline)
            Text("Installation " + item.installation.prefix(12) + "… · Request " + item.id.prefix(12) + "…").font(.caption).foregroundStyle(.secondary)
          }.padding(12).frame(maxWidth: .infinity, alignment: .leading)
            .background(editor.selected?.id == item.id ? Color.accentColor.opacity(0.1) : Color.primary.opacity(0.035)).cornerRadius(8)
        }.buttonStyle(.plain).disabled(!editing)
      }
      if let next = inbox.next { Button("Next request page") { editor.loadInbox(after: next) }.disabled(!editing || !unlocked) }
    }
  }
  private func credentialEditor(_ selected: NativeGrantRecipient, inbox: NativeOperatorInbox) -> some View {
    VStack(alignment: .leading, spacing: 20) {
      Divider()
      Text(editor.review == nil ? "Configure access" : "Review the exact grant").font(.title2.bold())
      if let existing = editor.existingConfiguration {
        Label("Existing grant · draft changes", systemImage:"pencil")
        Text("Current access stays in place until final Wallet approval. This editor changes permissions within the existing read and write components; revocation is separate.").font(.callout)
        DisclosureGroup("Current permissions · unchanged") { NativeGrantReview(selection:existing.selection, scopes:inbox.scopes) }
        Button("Discard changes") { editor.discardConfiguration() }.disabled(!editing)
      }
      Text("Recipient Wallet: " + selected.subject).font(.caption.monospaced()).textSelection(.enabled)
      Text("Read installation: " + selected.installation).font(.caption.monospaced()).textSelection(.enabled)
      DisclosureGroup("Servers & origin restrictions") {
        Text("Request authority: " + bridge.resource.configuration.authorityOrigin).textSelection(.enabled)
        Text(bridge.resource.configuration.serviceID == nil
          ? "This retained request uses the original origin-bound protocol. Its signed receiver restriction is preserved. Management still uses local secS RPC."
          : "This request uses the canonical service authority. Its verified access points share this authority; the selected network route does not create another service.")
          .font(.callout).foregroundStyle(.secondary)
        Text("Origin restrictions cannot be widened by changing a server URL. The exact credential review below shows the enforced receiver and scope.")
          .font(.caption).foregroundStyle(.secondary)
      }
      Label("Onward delegation: Not allowed", systemImage: "lock.shield")
      Text("This credential is for the approved Wallet. It cannot issue child credentials or grant access to another Wallet.").font(.caption).foregroundStyle(.secondary)
      if let message = editor.requestConfigurationError {
        Text(message).foregroundStyle(.red)
        Text("Decline this request or ask the requester to send a revised request. Its original fields are preserved.").font(.callout)
      } else if let review = editor.review, let selection = review["selection"] as? [String: Any] {
        if selection["read"] == nil { Text("This changes write access only. Any existing read grant stays unchanged.").font(.callout) }
        if selection["write"] == nil { Text("This changes read access only. Any existing write grant stays unchanged.").font(.callout) }
        NativeGrantReview(selection: selection, scopes: inbox.scopes)
        HStack {
          Button("Edit selection") { editor.review = nil }
          Spacer()
          Button(editor.existingConfiguration == nil ? "Accept request in Wallet" : "Approve changes in Wallet") { editor.approveSelection() }.buttonStyle(TransferPrimaryButtonStyle()).disabled(!unlocked || !editing)
        }
      } else {
        if editor.requestedConfiguration?.hasRequestedFields == true {
          Label("Requested fields are fixed. Complete the remaining choices below.", systemImage: "lock").font(.callout)
        }
        if editor.hierarchyMode {
          NativeHierarchyPermissionView(editor: editor, inbox: inbox, serviceName: bridge.resource.configuration.name)
          Button("Advanced rules and other write actions") { editor.useAdvancedRules() }
            .font(.callout)
        } else {
        if editor.scopeMode == "choose", editor.requestedConfiguration?.hasRequestedFields != true,
          editor.permissionRules.allSatisfy({ $0.reads.isEmpty && $0.writes.isEmpty && $0.arenaIDs.isEmpty && !$0.allArenas }),
          inbox.catalog != nil {
          Button("Quick Read / Edit selection by hierarchy") { editor.beginHierarchySelection() }
        }
        Text("Permission rules").font(.headline)
        Text("Each rule pairs its own scope with its actions. For example: read Arena A in one rule, edit Project B in another. No matching rule means no access. A selected parent includes its descendants; unchecked children are not exclusions.").font(.callout).foregroundStyle(.secondary)
        ForEach(Array(editor.ruleDrafts.enumerated()), id: \.element.id) { index, _ in
          Button { editor.selectRule(index) } label: {
            HStack { Image(systemName: index == editor.ruleIndex ? "checkmark.circle.fill" : "circle"); Text(editor.ruleSummary(index)); Spacer() }
          }.buttonStyle(.bordered)
        }
        HStack {
          Button("Add permission rule") { editor.addRule() }.disabled(editor.ruleDrafts.count >= 16)
          Button("Remove this rule") { editor.removeRule() }.disabled(editor.ruleDrafts.count <= 1)
        }
        Text("Editing rule \(editor.ruleIndex + 1)").font(.headline)
        presetPicker(inbox)
        if let paths = editor.requestedConfiguration?.paths {
          Label("Requested scope · allocation for this rule", systemImage: "lock").font(.headline)
          Text("Allocate these requested branches to rules. The complete selection must retain every requested branch.").font(.caption)
          ForEach(paths, id: \.self) { path in
            Toggle(WorkScopeSelection.label(path, scopes: inbox.scopes), isOn: Binding(get: { editor.choice.paths.contains(path) }, set: { enabled in
              editor.allocateRequestedPath(path, enabled:enabled)
            }))
          }
          DisclosureGroup("Choose object kinds · not specified by the request") { resourceKinds(inbox) }
        } else { scopeChoices(inbox) }
        permissionChoices(inbox)
        }
        validityChoices(inbox)
        Button("Review exact selection in Wallet") { editor.reviewSelection() }.buttonStyle(TransferPrimaryButtonStyle())
          .disabled(!unlocked || !editing || editor.permissionRules.allSatisfy { $0.reads.isEmpty && $0.writes.isEmpty && $0.arenaIDs.isEmpty && !$0.allArenas })
          .disabled(editor.choice.arenaIDs.count > 256)
      }
      if editor.existingConfiguration == nil { DisclosureGroup("Decline request") {
        TextField("Reason", text: $editor.declineReason)
        Button("Review decline in Wallet") { editor.decline() }.disabled(!unlocked || !editing || editor.declineReason.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
      } }
    }.disabled(!editing)
  }
  private func presetPicker(_ inbox: NativeOperatorInbox) -> some View {
    HStack {
      Picker("Permission preset", selection: Binding(get: { editor.presetID }, set: { editor.applyPreset($0, library: library) })) {
        Text("Custom permissions").tag("custom")
        if let catalog = inbox.catalog {
          Section("Server presets") { ForEach(catalog.presets) { Text($0.name + " · r\($0.version)").tag("server:" + $0.id) } }
        }
        Section("Local recipes") { ForEach(library.available) { Text($0.name + " · r\($0.revision)").tag("local:" + $0.id) } }
      }
      .disabled(editor.requestedConfiguration?.locksPermissions == true)
      Button("Create preset") { creatingPreset = true }
    }
  }
  private func permissionChoices(_ inbox: NativeOperatorInbox) -> some View {
    VStack(alignment: .leading, spacing: 12) {
      if let notice = editor.recipeNotice { Text(notice).font(.callout).foregroundStyle(.secondary) }
      TransferPermissionEditor(
        reads: Binding(get: { editor.choice.reads }, set: {
          guard editor.requestedConfiguration?.locksPermissions != true else { return }
          editor.choice.reads = $0; editor.editedPermissions()
        }),
        writes: Binding(get: { editor.choice.writes }, set: {
          guard editor.requestedConfiguration?.locksPermissions != true else { return }
          editor.choice.writes = $0; editor.editedPermissions()
        }),
        arenaRead: Binding(get: { editor.arenaReadEnabled }, set: {
          guard editor.requestedConfiguration?.locksPermissions != true else { return }
          editor.setArenaRead($0)
        }),
        availableReads: inbox.permissions.reads,
        availableWrites: Set(inbox.permissions.writes),
        allowsArenaRead: editor.arenaReadEnabled || editor.futureArenaMode || !editor.coveredArenaIDs.isEmpty,
        arenaExplanation: editor.futureArenaMode
          ? "All current and future Arena records. This grants no Work access or administration."
          : "Applies only to the Arena coverage shown in Scope. Listing and reading details are combined. At most 256 Arena records can be selected.",
        writesEnabled: inbox.activation["write"] as? Bool != false,
        hierarchyScope: editor.scopeMode == "paths",
        locked: editor.requestedConfiguration?.locksPermissions == true)
      if editor.scopeMode == "paths" {
        Text("Hierarchy rules cover canonical Work descendants and exact Arena records. Proposal, Todo and provenance resources need a separate rule with exact IDs or explicit all-permitted coverage. Actions touching several resources require authority for every one.").font(.caption).foregroundStyle(.secondary)
      }
      if inbox.activation["mixed"] as? Bool == false { Text("This server requires reads and writes to be approved separately.").font(.caption).foregroundStyle(.secondary) }
    }
  }
  private func scopeChoices(_ inbox: NativeOperatorInbox) -> some View {
    VStack(alignment: .leading, spacing: 12) {
      Text("Scope").font(.headline)
      Text("Choose coverage for this rule only. Its read and write actions apply to this scope; other rules keep their own scopes.").font(.callout).foregroundStyle(.secondary)
      Picker("Scope", selection: Binding(get: { editor.scopeMode }, set: { editor.changeScope($0) })) {
        Text("Choose coverage…").tag("choose")
        Text("Selected hierarchy branches").tag("paths")
        Text("Exact resource IDs").tag("exact")
        Text("All").tag("global")
      }
      if editor.scopeMode == "paths" {
        Text("Select several Arenas, Initiatives or Projects. Selecting a container includes its current and future descendants at access time. Moved-out work loses access.").font(.callout).foregroundStyle(.secondary)
        if inbox.catalog == nil { Text("The server could not supply a verified hierarchy. Reload the inbox; no global scope has been selected automatically.").foregroundStyle(.red) }
        else if inbox.scopes.isEmpty { Text("The server has published no selectable branches.").foregroundStyle(.secondary) }
        else {
          Label(bridge.resource.configuration.name, systemImage: "server.rack").font(.headline)
          ForEach(WorkScopeSelection.tree(inbox.scopes)) { scopeRow($0, depth: 0) }
          Text("\(editor.choice.paths.count) selected branches · includes descendants").font(.caption).foregroundStyle(.secondary)
        }
      } else if editor.scopeMode == "exact" {
        Text("Choose resource kinds").font(.headline)
        resourceKinds(inbox)
        Text("Enter IDs for each checked resource kind, separated by commas. Empty IDs never mean all resources. Use this for Arena creation, proposals, decisions and review evidence that cannot inherit a Work hierarchy.").font(.callout).foregroundStyle(.secondary)
        ForEach(editor.choice.kinds.sorted(), id: \.self) { kind in
          TextField(kind + " IDs", text: Binding(get: { editor.exactIDText[kind] ?? "" }, set: { editor.setExactIDs(kind, text: $0) }))
        }
      } else if editor.scopeMode == "global" {
        Text("This explicitly selects all resources available under the server’s rules, including future matching work. The exact review retains any server-imposed limits.").font(.callout).foregroundStyle(.secondary)
      }
      if editor.scopeMode != "choose", !editor.futureArenaMode, !inbox.permissions.arenaIDs.isEmpty {
        DisclosureGroup("Arena record coverage · \(editor.coveredArenaIDs.count)") {
          ForEach(editor.coveredArenaIDs.sorted(), id: \.self) { id in
            Text(inbox.scopes.first { $0.resource == "Arena/" + id }?.title ?? id)
          }
          Text("Arena records are readable only when their read permission is checked below. Selecting a Project may include its containing Arena’s record, without granting access to sibling Work. Arena record IDs are explicit; future Arena records require a new grant selection.")
            .font(.caption).foregroundStyle(.secondary)
          if editor.coveredArenaIDs.isEmpty { Text("These branches contain no verified Arena anchor. No Arena records will be granted.").font(.caption) }
        }
      }
      if editor.scopeMode != "exact" { DisclosureGroup("Limit object kinds") { resourceKinds(inbox) } }
    }
  }
  private func resourceKinds(_ inbox: NativeOperatorInbox) -> some View {
    LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], alignment: .leading) {
      ForEach(inbox.permissions.kinds, id: \.self) { kind in
        Toggle(kind, isOn: Binding(get: { editor.choice.kinds.contains(kind) }, set: { editor.setKind(kind, enabled: $0) }))
      }
    }
  }
  private func scopeRow(_ row: WorkScopeTreeNode, depth: Int) -> AnyView {
    let inherited = editor.inherited(row.option)
    return AnyView(VStack(alignment: .leading, spacing: 10) {
      HStack {
        if row.children != nil {
          Button { if editor.expanded.contains(row.id) { editor.expanded.remove(row.id) } else { editor.expanded.insert(row.id) } } label: { Image(systemName: editor.expanded.contains(row.id) ? "chevron.down" : "chevron.right").frame(width: 14) }
            .buttonStyle(.plain).accessibilityLabel("Show children of " + row.option.title)
        } else { Color.clear.frame(width: 14, height: 14) }
        Toggle(isOn: Binding(get: { inherited || editor.choice.paths.contains(row.option.resource_path) }, set: { editor.choose(row.option, selected: $0) })) {
          VStack(alignment: .leading, spacing: 3) {
            Text(row.option.title).font(.body)
            Text(row.option.kind + (inherited ? " · Included by selected parent" : " · Includes descendants")).font(.caption).foregroundStyle(.secondary)
          }
        }.disabled(inherited)
      }.padding(.leading, CGFloat(depth * 22))
      if editor.expanded.contains(row.id), let children = row.children { ForEach(children) { scopeRow($0, depth: depth + 1) } }
    })
  }
  private func validityChoices(_ inbox: NativeOperatorInbox) -> some View {
    VStack(alignment: .leading, spacing: 12) {
      Text("Validity · all rules").font(.headline)
      Toggle("Until revoked", isOn: $editor.choice.untilRevoked).disabled(inbox.permissions.validity.notAfter != nil)
      if !editor.choice.untilRevoked { DatePicker("Grant expires", selection: $editor.choice.expiry, in: Date()...) }
      Text("The recipient may obtain fresh read credentials while this grant is valid. Short credential expiry does not require another operator decision.").font(.caption).foregroundStyle(.secondary)
    }
  }
  private func activeGrants(_ inbox: NativeOperatorInbox) -> some View {
    VStack(alignment: .leading, spacing: 12) {
      if !inbox.activeGrants.isEmpty { Text("Active grants").font(.headline) }
      ForEach(Array(inbox.activeGrants.enumerated()), id: \.offset) { _, grant in
        NativeActiveGrantRow(grant: grant, disabled: !editing || !unlocked, configure: { editor.configure(grant) }) { reason in editor.revoke(grant, reason: reason) }
      }
    }
  }
}

struct NativeArenaCreationView: View {
  @ObservedObject var editor: NativeCredentialModel
  let unlocked: Bool
  @State private var arenaID = ""
  @State private var title = ""
  @State private var description = ""
  var body: some View {
    DisclosureGroup("Create Arena") {
      VStack(alignment: .leading, spacing: 12) {
        TextField("Arena name", text: $title)
        TextField("Stable ID, for example product-research", text: $arenaID)
        TextField("Description", text: $description)
        Text("Your owner Wallet signs this exact creation. It creates no member credential and grants no one access.").font(.caption).foregroundStyle(.secondary)
        Button("Review Arena creation in Wallet") { editor.createArena(id: arenaID, title: title, description: description) }
          .buttonStyle(TransferPrimaryButtonStyle()).disabled(!unlocked || editor.busy || editor.state != .idle || arenaID.isEmpty || title.isEmpty)
      }.padding(.vertical, 8)
    }
  }
}

struct NativeActiveGrantRow: View {
  let grant: [String: Any]
  let disabled: Bool
  var configure: (() -> Void)? = nil
  let revoke: (String) -> Void
  @State private var reason = ""
  var body: some View {
    VStack(alignment: .leading, spacing: 10) {
      Text("Wallet " + (grant["subject_public_key"] as? String ?? "Unknown")).font(.caption.monospaced()).textSelection(.enabled)
      Text("Access: " + (grant["access_mode"] as? String ?? "read"))
      if let validity = grant["validity"] as? [String: Any] { Text(validity["mode"] as? String == "until_revoked" ? "Until revoked" : "Expires " + Date(timeIntervalSince1970: Double(GrantJSON.integer(validity["not_after"]) ?? 0)).formatted()) }
      if let configure {
        Button("Configure") { configure() }.disabled(disabled)
        Text("Edit a draft; access changes only after Wallet approval.").font(.caption).foregroundStyle(.secondary)
      }
      TextField("Reason for revocation", text: $reason)
      Button("Review revocation in Wallet") { revoke(reason) }.disabled(disabled || reason.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
    }.padding(16).background(Color.primary.opacity(0.035)).cornerRadius(10)
  }
}

struct NativeGrantReview: View {
  let selection: [String: Any]
  let scopes: [WorkScopeOption]
  var body: some View {
    VStack(alignment: .leading, spacing: 18) {
      ForEach(["read", "write"], id: \.self) { mode in
        if let draft = selection[mode] as? [String: Any] {
          Text(mode == "read" ? "Read access · this Wallet and installation" : "Write access · this Wallet across admitted installations").font(.headline)
          if let validity = draft["validity"] as? [String: Any] {
            Text(validity["mode"] as? String == "until_revoked" ? "Until revoked" : "Expires " + Date(timeIntervalSince1970: Double(GrantJSON.integer(validity["not_after"]) ?? 0)).formatted())
          } else if let end = GrantJSON.integer(draft["not_after"]) { Text("Expires " + Date(timeIntervalSince1970: Double(end)).formatted()) }
          let grants = draft[mode == "read" ? "read_grants" : "write_grants"] as? [[String: Any]] ?? []
          ForEach(Array(grants.enumerated()), id: \.offset) { _, grant in
            VStack(alignment: .leading, spacing: 8) {
              if grant["scope"] as? String == "devgraph.arena.read" { Text(grant["all_arenas"] as? Bool == true ? "List and read all current and future Arena records" : "List and read selected Arena records").font(.headline) }
              if let ops = grant["operations"] as? [String] { Text("Read: " + ops.joined(separator: ", ")) }
              if let op = grant["operation"] as? String { Text(DevGraphPermissionCatalog.writes.first { $0.id == op }?.title ?? op) }
              if let paths = try? NativeGrantSelection.paths(grant), !paths.isEmpty {
                ForEach(paths, id: \.self) { Text(WorkScopeSelection.label($0, scopes: scopes)).font(.callout) }
                Text("Current and future descendants at access time; moved-out resources lose access.").font(.caption).foregroundStyle(.secondary)
              } else if grant["scope"] as? String != "devgraph.arena.read" {
                Text("All matching resources permitted by the server’s filters below.").font(.callout)
              }
              if let kinds = grant["work_kinds"] as? [String] { Text("Object kinds: " + kinds.joined(separator: ", ")) }
              if let ids = grant["work_ids"] as? [String] { Text("Only objects: " + ids.joined(separator: ", ")).font(.caption) }
              if let areas = grant["arena_ids"] as? [String] { Text((grant["scope"] as? String == "devgraph.arena.read" ? "Only Arena records: " : "Additional Arena filter: ") + areas.joined(separator: ", ")).font(.caption) }
              if let resources = grant["resources"] as? [[String: Any]] {
                ForEach(Array(resources.enumerated()), id: \.offset) { _, row in
                  Text((row["kind"] as? String ?? "") + ": " + ((row["ids"] as? [String])?.joined(separator: ", ") ?? "All matching objects within the selected scope")).font(.caption)
                }
              }
              if mode == "read", grant["scope"] as? String != "devgraph.arena.read" { Text(grant["include_archived"] as? Bool == true ? "Archived work included" : "Archived work excluded").font(.caption).foregroundStyle(.secondary) }
            }.padding(14).frame(maxWidth: .infinity, alignment: .leading).background(Color.primary.opacity(0.035)).cornerRadius(10)
          }
        }
      }
      DisclosureGroup("Full exact grant") { Text(String(decoding: (try? JSONSerialization.data(withJSONObject: selection, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes])) ?? Data(), as: UTF8.self)).font(.caption.monospaced()).textSelection(.enabled) }
    }
  }
}
#endif
