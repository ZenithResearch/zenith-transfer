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
  @Published var presetID = "custom"
  @Published var recipeNotice: String?
  @Published var scopeMode = "choose"
  @Published var expanded: Set<String> = []
  @Published var review: [String: Any]?
  @Published var busy = false
  @Published var error: String?
  @Published var status = "Unlock Wallet, then review this resource’s requests."
  @Published var declineReason = ""
  private var presetReference: [String: Any]?
  init(bridge: TransferOperatorBridge) {
    self.bridge = bridge
    do { client = try NativeOperatorClient(bridge: bridge); state = client!.state }
    catch { self.error = "The original action could not be read safely. Its record is preserved." }
  }
  var preparedName: String { client?.action?["action"] as? String ?? "action" }
  var isRecovery: Bool { client?.action?["action"] as? String == "status" }
  var expiry: Date? { GrantJSON.integer(client?.challenge?["expires_at"]).map { Date(timeIntervalSince1970: Double($0)) } }
  func run(_ operation: @escaping () async throws -> Void) {
    guard !busy else { return }; busy = true; error = nil
    Task {
      defer { state = client?.state ?? .idle; busy = false }
      do { try await operation() }
      catch {
        if let e = error as? NativeGrantError { self.error = e.errorDescription }
        else if let e = error as? WalletFailure { self.error = e.errorDescription }
        else if let e = error as? LocalAdminRPCError { self.error = e.errorDescription }
        else if let e = error as? NativeOperatorServerError { self.error = e.errorDescription }
        else { self.error = "Could not finish this step. Check the Wallet and saved server connection." }
      }
    }
  }
  func loadInbox(after: String? = nil) {
    run { [self] in
      guard let client else { throw NativeGrantError.invalid }
      var action: [String: Any] = ["action": "inbox"]
      if let after { action["after_id"] = after }
      try await client.prepare(action); state = client.state
      let result = try await client.confirm(); try accept(result)
    }
  }
  func select(_ item: NativeGrantRecipient) {
    guard !busy, state == .idle, let inbox else { return }
    selected = item; review = nil; presetID = "custom"; presetReference = nil; recipeNotice = nil
    choice = NativeGrantChoice(); scopeMode = "choose"; expanded = []
    choice.kinds = Set(inbox.permissions.kinds).intersection(["Initiative", "Project", "Issue", "Task", "Todo", "Proposal"])
    choice.untilRevoked = inbox.permissions.validity.notAfter == nil
    if let end = inbox.permissions.validity.notAfter { choice.expiry = Date(timeIntervalSince1970: Double(end)) }
    declineReason = ""
    status = "Choose the permissions and resources for this credential. No access has been granted."
  }
  func applyPreset(_ id: String, library: TransferPresetLibrary) {
    guard let inbox else { return }
    presetID = id; presetReference = nil; review = nil
    let reads: [String], writes: [String]
    choice.arenaIDs = []
    if id.hasPrefix("server:"), let recipe = inbox.catalog?.presets.first(where: { "server:" + $0.id == id }) {
      reads = recipe.read_operations; writes = recipe.write_operations
      presetReference = ["id": recipe.id, "version": recipe.version, "catalog_digest_sha256": inbox.catalog!.catalog_digest_sha256]
    } else if let recipe = library.available.first(where: { "local:" + $0.id == id }) {
      reads = recipe.readOperations; writes = recipe.writeOperations.map { "devgraph.work." + $0 + ".v2" }
    } else { recipeNotice = nil; return }
    choice.reads = Set(reads).intersection(inbox.permissions.reads)
    let supported = Set(OwnerPermissionPreset.allOperations.map { "devgraph.work." + $0 + ".v2" })
    choice.writes = Set(writes).intersection(inbox.permissions.writes).intersection(supported)
    if inbox.activation["write"] as? Bool == false { choice.writes = [] }
    if !choice.paths.isEmpty { choice.writes.remove("devgraph.work.create.v2") }
    let omitted = Set(reads).subtracting(choice.reads).count + Set(writes).subtracting(choice.writes).count
    recipeNotice = (library.available.first { "local:" + $0.id == id }?.arenaRead == true ? "Select the Arena records below. " : "") + (omitted > 0 ? "\(omitted) recipe permissions are unavailable for this server or path. Only the checked permissions will be reviewed." : "This recipe selects actions only. Choose resource coverage separately.")
  }
  func editedPermissions() { review = nil; presetID = "custom"; presetReference = nil; recipeNotice = nil }
  func changeScope(_ value: String) {
    scopeMode = value; choice.wholeGraph = value == "global"
    if value != "paths" { choice.paths = [] }; review = nil
  }
  func choose(_ row: WorkScopeOption, selected: Bool) {
    do {
      choice.paths = try WorkScopeSelection.normalized(selected ? choice.paths + [row.resource_path] : choice.paths.filter { $0 != row.resource_path })
      if !choice.paths.isEmpty, choice.writes.remove("devgraph.work.create.v2") != nil {
        recipeNotice = "Creating unattached work is excluded from path grants. The selected existing resources can still be edited."
      }
      review = nil
    } catch { self.error = "Select at most 16 independent branches." }
  }
  func inherited(_ row: WorkScopeOption) -> Bool { choice.paths.contains { $0 != row.resource_path && WorkScopeSelection.covers($0, row.resource_path) } }
  func reviewSelection() {
    run { [self] in
      guard let inbox, let selected, let client else { throw NativeGrantError.invalid }
      if !choice.writes.isEmpty && inbox.activation["write"] as? Bool == false { throw NativeGrantError.permissions }
      if !choice.reads.isEmpty && !choice.writes.isEmpty && inbox.activation["mixed"] as? Bool == false { throw NativeGrantError.permissions }
      let selection = try NativeGrantSelection.make(ceiling: inbox.ceiling, ceilingDigest: inbox.digest,
        recipient: selected, choice: choice, scopes: inbox.scopes, preset: presetReference, now: client.now)
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
      if client.state == .unknown { try await client.prepareRecovery() }
      else if client.state == .prepared { try await client.refreshPrepared() }
      state = client.state
      try accept(await client.confirm())
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
    if result["inbox"] != nil {
      inbox = try NativeOperatorInbox(result, resource: bridge.resource); selected = nil; review = nil
      status = "Inbox loaded. Select a request to configure its credential."
    } else if result["selection"] != nil {
      // Recovery of a review can return before its inbox was loaded after relaunch.
      // Show its exact snapshot; final approval requires reloading current context.
      review = result; status = "Selection verified by the server. Review the exact credential before approval."
    } else {
      let status = result["status"] as? String ?? ""
      switch status {
      case "active": self.status = "Grant activated. The recipient can obtain and reuse access while it remains valid."
      case "revoked": self.status = "Grant revoked. Further access under it is denied."
      case "denied": self.status = "Request declined. No access was granted."
      default: self.status = "Decision recorded. Server activation is still required; no active credential is claimed."
      }
      selected = nil; review = nil; inbox = nil
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
  init(resource: RegisteredResource, repository: any WalletSession, walletModel: TransferModel,
       onRecoveredLegacyAction: @escaping () -> Void = {}) {
    self.onRecoveredLegacyAction = onRecoveredLegacyAction
    self.walletModel = walletModel; library = walletModel.presetLibrary
    let bridge = TransferOperatorBridge(resource: resource, repository: repository)
    _bridge = StateObject(wrappedValue: bridge); _editor = StateObject(wrappedValue: NativeCredentialModel(bridge: bridge))
  }
  var unlocked: Bool { walletModel.walletUnlocked }
  var editing: Bool { !editor.busy && editor.state == .idle }
  var body: some View {
    VStack(spacing: 0) {
      HStack {
        VStack(alignment: .leading, spacing: 4) {
          Text("Credentials & requests").font(.title2.bold())
          Text(bridge.resource.configuration.name + " · " + bridge.resource.id).font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
        }
        Spacer()
        Button(unlocked ? "Wallet" : "Unlock Wallet") { unlocking = true }
        Button("Close") { bridge.cancel(); dismiss() }
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
            Button("Review inbox in Wallet") { editor.loadInbox() }.buttonStyle(TransferPrimaryButtonStyle()).disabled(!unlocked || !editing)
            if editor.busy { ProgressView().controlSize(.small) }
          }
          if editor.state != .idle {
            pendingAction
          } else if let inbox = editor.inbox {
            requestList(inbox)
            if let selected = editor.selected { credentialEditor(selected, inbox: inbox) }
            else { activeGrants(inbox) }
          }
        }.padding(24).frame(maxWidth: 940, alignment: .leading).frame(maxWidth: .infinity)
      }
    }.frame(minWidth: 980, minHeight: 720)
      .onChange(of: bridge.legacyRecoveryCompleted) { completed in
        if completed { bridge.cancel(); onRecoveredLegacyAction() }
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
          Text("\(consent.receiver)\nIssuer: \(consent.issuer)").textSelection(.enabled)
          Text("Review this exact action. Wallet approval expires at \(consent.expiresAt.formatted()).")
          ScrollView { Text(bridge.disclosure).font(.system(.body, design: .monospaced)).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading) }
          HStack {
            Button("Cancel") { bridge.resolve(false) }; Spacer()
            Button("Approve in Castalia Wallet") { bridge.resolve(true) }.buttonStyle(TransferPrimaryButtonStyle())
          }
        }.padding(24).frame(width: 760, height: 620)
      }
      .onDisappear { bridge.cancel() }
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
      Text(editor.review == nil ? "Configure this credential" : "Review the exact credential").font(.title2.bold())
      Text("Recipient Wallet: " + selected.subject).font(.caption.monospaced()).textSelection(.enabled)
      Text("Read installation: " + selected.installation).font(.caption.monospaced()).textSelection(.enabled)
      Label("Onward delegation: Not allowed", systemImage: "lock.shield")
      Text("This credential is for the approved Wallet. It cannot issue child credentials or grant access to another Wallet.").font(.caption).foregroundStyle(.secondary)
      if let review = editor.review, let selection = review["selection"] as? [String: Any] {
        if selection["read"] == nil { Text("This changes write access only. Any existing read grant stays unchanged.").font(.callout) }
        if selection["write"] == nil { Text("This changes read access only. Any existing write grant stays unchanged.").font(.callout) }
        NativeGrantReview(selection: selection, scopes: inbox.scopes)
        HStack {
          Button("Edit selection") { editor.review = nil }
          Spacer()
          Button("Approve this credential in Wallet") { editor.approveSelection() }.buttonStyle(TransferPrimaryButtonStyle()).disabled(!unlocked || !editing)
        }
      } else {
        presetPicker(inbox)
        permissionChoices(inbox)
        scopeChoices(inbox)
        validityChoices(inbox)
        Button("Review exact selection in Wallet") { editor.reviewSelection() }.buttonStyle(TransferPrimaryButtonStyle())
          .disabled(!unlocked || !editing || editor.scopeMode == "choose" || editor.choice.reads.isEmpty && editor.choice.writes.isEmpty && editor.choice.arenaIDs.isEmpty)
      }
      DisclosureGroup("Decline request") {
        TextField("Reason", text: $editor.declineReason)
        Button("Review decline in Wallet") { editor.decline() }.disabled(!unlocked || !editing || editor.declineReason.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
      }
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
      Button("Create preset") { creatingPreset = true }
    }
  }
  private func permissionChoices(_ inbox: NativeOperatorInbox) -> some View {
    VStack(alignment: .leading, spacing: 12) {
      if let notice = editor.recipeNotice { Text(notice).font(.callout).foregroundStyle(.secondary) }
      Text("Permissions carried by this credential").font(.headline)
      Text("Work read permissions").font(.subheadline.bold())
      ForEach(inbox.permissions.reads, id: \.self) { op in
        Toggle(isOn: binding(op, reads: true)) {
          VStack(alignment: .leading, spacing: 3) {
            Text(WorkReadPermission(rawValue: op)?.title ?? ["children":"Read Work children", "blockers":"Read Work blockers"][op] ?? op)
            if let permission = WorkReadPermission(rawValue: op) {
              Text(permission.explanation).font(.caption).foregroundStyle(.secondary)
            }
          }
        }
      }
      if !inbox.permissions.arenaIDs.isEmpty {
        Text("Arena records").font(.headline)
        Text("List and read only the checked Arena records. Work coverage is selected separately below.").font(.caption).foregroundStyle(.secondary)
        ForEach(inbox.permissions.arenaIDs, id: \.self) { id in
          let label = inbox.scopes.first { $0.resource_path.path.last == "Arena/" + id }?.title ?? id
          Toggle(label, isOn: Binding(get: { editor.choice.arenaIDs.contains(id) }, set: { on in
            if on { editor.choice.arenaIDs.insert(id) } else { editor.choice.arenaIDs.remove(id) }
            editor.editedPermissions()
          }))
        }
      } else {
        Text("Arena records are not enabled by this service’s owner policy. Existing Work scope selections remain available.").font(.caption).foregroundStyle(.secondary)
      }
      Label(WorkReadPermission.arenaAvailability, systemImage: "info.circle")
        .font(.caption).foregroundStyle(.secondary)
      let supported = OwnerPermissionPreset.allOperations.filter { inbox.permissions.writes.contains("devgraph.work." + $0 + ".v2") }
      if !supported.isEmpty {
        Text("Write permissions").font(.headline)
        LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], alignment: .leading, spacing: 12) {
          ForEach(supported, id: \.self) { op in
            Toggle(OwnerPermissionPreset.title(op), isOn: binding("devgraph.work." + op + ".v2", reads: false))
              .disabled(inbox.activation["write"] as? Bool == false || op == "create" && !editor.choice.paths.isEmpty)
          }
        }
      }
      if inbox.activation["mixed"] as? Bool == false { Text("This server requires reads and writes to be approved separately.").font(.caption).foregroundStyle(.secondary) }
      DisclosureGroup("Limit object kinds") {
        ForEach(inbox.permissions.kinds, id: \.self) { kind in
          Toggle(kind, isOn: Binding(get: { editor.choice.kinds.contains(kind) }, set: { on in
            if on { editor.choice.kinds.insert(kind) } else { editor.choice.kinds.remove(kind) }
          }))
        }
      }
    }
  }
  private func binding(_ op: String, reads: Bool) -> Binding<Bool> {
    Binding(get: { reads ? editor.choice.reads.contains(op) : editor.choice.writes.contains(op) }, set: { value in
      if reads { if value { editor.choice.reads.insert(op) } else { editor.choice.reads.remove(op) } }
      else { if value { editor.choice.writes.insert(op) } else { editor.choice.writes.remove(op) } }
      editor.editedPermissions()
    })
  }
  private func scopeChoices(_ inbox: NativeOperatorInbox) -> some View {
    VStack(alignment: .leading, spacing: 12) {
      Text("Resource coverage").font(.headline)
      Picker("Scope", selection: Binding(get: { editor.scopeMode }, set: { editor.changeScope($0) })) {
        Text("Choose coverage…").tag("choose")
        Text("Selected hierarchy branches").tag("paths")
        Text("All resources permitted by this server").tag("global")
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
      } else if editor.scopeMode == "global" {
        Text("This explicitly selects all resources available under the server’s rules, including future matching work. The exact review retains any server-imposed limits.").font(.callout).foregroundStyle(.secondary)
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
      Text("Validity").font(.headline)
      Toggle("Until revoked", isOn: $editor.choice.untilRevoked).disabled(inbox.permissions.validity.notAfter != nil)
      if !editor.choice.untilRevoked { DatePicker("Grant expires", selection: $editor.choice.expiry, in: Date()...) }
      Text("The recipient may obtain fresh read credentials while this grant is valid. Short credential expiry does not require another operator decision.").font(.caption).foregroundStyle(.secondary)
    }
  }
  private func activeGrants(_ inbox: NativeOperatorInbox) -> some View {
    VStack(alignment: .leading, spacing: 12) {
      if !inbox.activeGrants.isEmpty { Text("Active grants").font(.headline) }
      ForEach(Array(inbox.activeGrants.enumerated()), id: \.offset) { _, grant in
        NativeActiveGrantRow(grant: grant, disabled: !editing || !unlocked) { reason in editor.revoke(grant, reason: reason) }
      }
    }
  }
}

private struct NativeActiveGrantRow: View {
  let grant: [String: Any]
  let disabled: Bool
  let revoke: (String) -> Void
  @State private var reason = ""
  var body: some View {
    VStack(alignment: .leading, spacing: 10) {
      Text("Wallet " + (grant["subject_public_key"] as? String ?? "Unknown")).font(.caption.monospaced()).textSelection(.enabled)
      Text("Access: " + (grant["access_mode"] as? String ?? "read"))
      if let validity = grant["validity"] as? [String: Any] { Text(validity["mode"] as? String == "until_revoked" ? "Until revoked" : "Expires " + Date(timeIntervalSince1970: Double(GrantJSON.integer(validity["not_after"]) ?? 0)).formatted()) }
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
              if grant["scope"] as? String == "devgraph.arena.read" { Text("List and read Arena records").font(.headline) }
              if let ops = grant["operations"] as? [String] { Text("Read: " + ops.joined(separator: ", ")) }
              if let op = grant["operation"] as? String { Text(OwnerPermissionPreset.title(op.replacingOccurrences(of: "devgraph.work.", with: "").replacingOccurrences(of: ".v2", with: ""))) }
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
