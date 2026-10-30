#if os(macOS)
import Combine
import SwiftUI
import ZenithKit

@MainActor final class ServiceInboxEndpoint: ObservableObject, Identifiable {
  let bridge: TransferOperatorBridge
  let editor: NativeCredentialModel
  nonisolated let id: String
  var origins: [String]
  @Published var snapshot = ServiceInboxSnapshot()
  @Published var loaded = false
  @Published var error: String?
  private var observers: [AnyCancellable] = []
  private enum InboxPage { case first, after(String) }
  private var retainedInboxPage: InboxPage?
  private var completedInbox: NativeOperatorInbox?
  private var loadingThroughEndpoint = false
  init(resource: RegisteredResource, repository: any WalletSession,
       journalDirectory: URL? = nil,
       exchange: ((String, Data) async throws -> PrivateHTTPResponse)? = nil) {
    id = resource.configuration.authorityOrigin
    origins = [resource.id]
    bridge = TransferOperatorBridge(resource: resource, repository: repository,
      journalDirectory: journalDirectory, requireLocal: true, rpcExchange: exchange)
    editor = NativeCredentialModel(bridge: bridge)
    observers.append(editor.objectWillChange.sink { [weak self] _ in self?.objectWillChange.send() })
    captureRetainedInboxPage()
    observers.append(bridge.objectWillChange.sink { [weak self] _ in
      self?.captureRetainedInboxPage()
      self?.objectWillChange.send()
    })
    observers.append(editor.$inbox.dropFirst().sink { [weak self] value in
      guard let self else { return }
      guard let value else {
        self.completedInbox = nil; self.snapshot = ServiceInboxSnapshot(); self.loaded = false
        return
      }
      guard !self.loadingThroughEndpoint else { return }
      self.completedInbox = value
      self.reconcileCompletedInbox(state: self.editor.state)
    })
    observers.append(editor.$state.dropFirst().sink { [weak self] state in
      self?.reconcileCompletedInbox(state: state)
    })
  }
  private func captureRetainedInboxPage() {
    guard let data = try? bridge.retainedNativeAction(),
      let record = try? GrantJSON.object(data), let action = record["action"] as? [String:Any]
    else { return }
    guard action["action"] as? String == "inbox" else { retainedInboxPage = nil; return }
    if let value = action["after_id"] {
      guard let cursor = value as? String, GrantJSON.hex(cursor,32) else { retainedInboxPage = nil; return }
      retainedInboxPage = .after(cursor)
    } else { retainedInboxPage = .first }
  }
  private func reconcileCompletedInbox(state: NativeOperatorClient.State) {
    // The child validates its result before publishing inbox, then returns idle.
    // Do not reinterpret a prepared/unknown mutation or send another read here.
    guard !loadingThroughEndpoint, state == .idle, let inbox = completedInbox else { return }
    completedInbox = nil
    defer { retainedInboxPage = nil }
    let append: Bool
    switch retainedInboxPage {
    case .first: append = false
    case .after(let cursor) where snapshot.next == cursor: append = true
    default:
      loaded = false
      error = "The original page was checked. Review the inbox again to load all pages."
      return
    }
    do {
      var next = snapshot
      try next.accept(inbox, authority: id, append: append)
      snapshot = next; loaded = true; error = nil
    } catch {
      loaded = false
      self.error = NativeCredentialDiagnostic.message(error)
    }
  }
  func load(after: String? = nil) async {
    error = nil
    do {
      guard editor.state == .idle else {
        throw editor.state == .prepared && !editor.isRecovery ? NativeGrantError.notSent : NativeGrantError.recovery
      }
      loadingThroughEndpoint = true
      completedInbox = nil
      retainedInboxPage = after.map { .after($0) } ?? .first
      defer { loadingThroughEndpoint = false }
      try await editor.loadServiceInbox(after: after)
      guard let inbox = editor.inbox else { throw NativeGrantError.invalid }
      try snapshot.accept(inbox, authority: id, append: after != nil)
      loaded = true
      retainedInboxPage = nil
    } catch {
      // Never present an old successful snapshot as a complete current inbox.
      self.error = NativeCredentialDiagnostic.message(error)
      loaded = false
    }
  }
}

@MainActor final class TransferServiceInboxModel: ObservableObject {
  let service: TransferLogicalService
  @Published var endpoints: [ServiceInboxEndpoint] = []
  @Published var failures: [String: String] = [:]
  @Published var preparing = false
  @Published var loading = false
  @Published var active: ServiceInboxEndpoint?
  private var observers: [AnyCancellable] = []
  init(service: TransferLogicalService) { self.service = service }
  var requests: [ServiceInboxRow] { endpoints.flatMap { $0.snapshot.requests }.sorted { $0.id < $1.id } }
  var grants: [ServiceInboxRow] { endpoints.flatMap { $0.snapshot.grants }.sorted { $0.id < $1.id } }
  var complete: Bool { !preparing && failures.isEmpty && !endpoints.isEmpty && endpoints.allSatisfy { $0.loaded && $0.snapshot.next == nil && $0.snapshot.requests.count == $0.snapshot.total && $0.editor.state == .idle } }
  var busy: Bool { preparing || loading || endpoints.contains { $0.editor.busy } }
  func endpoint(for row: ServiceInboxRow) -> ServiceInboxEndpoint? { endpoints.first { $0.id == row.authority } }
  func prepare(repository: any WalletSession) async {
    guard endpoints.isEmpty, !preparing else { return }
    preparing = true; defer { preparing = false }
    guard service.hasConsistentAuthority else {
      failures[service.id] = "The discovered interfaces disagree about their issuer identity. Refresh or repair their public profiles before managing this graph."
      return
    }
    let root: URL
    do { root = try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true).appendingPathComponent("ZenithTransfer/OperatorActions") }
    catch { failures[service.id] = "Original action storage is unavailable."; return }
    var candidates: [ServiceInboxRoutePlan.Candidate] = []
    for server in service.walletServers {
      do {
        guard let base = server.connection else { throw LocalAdminRPCError.changed }
        // Validate the protected fixed local binding before reading or signing.
        // No HTTP/Tailscale client exists on this management path.
        let rpc = try LocalAdminRPC.discover(configuration: base)
        guard rpc.resourceID == service.graphID, rpc.instanceID == server.id else { throw LocalAdminRPCError.changed }
        let journal = try OperatorJournal(directory: root, origin: base.origin)
        let retained = try journal.load() != nil
        let legacy = try base.withServiceAccessPoint(nil)
        let configuration = retained ? legacy : try await base.resolveForLocalManagement()
        candidates.append(.init(configuration: legacy, retained: retained))
        if configuration.serviceID != nil { candidates.append(.init(configuration: configuration, retained: false)) }

      } catch {
        failures[server.endpoint] = "Local management could not verify this server. Its requests are not yet included; no network fallback was used."
      }
    }
    do {
      for route in try ServiceInboxRoutePlan.make(candidates) {
        let value = ServiceInboxEndpoint(resource: try RegisteredResource(configuration: route.configuration), repository: repository)
        value.origins = route.origins
        endpoints.append(value)
        observers.append(value.objectWillChange.sink { [weak self] _ in self?.objectWillChange.send() })
      }
    } catch {
      failures[service.id] = "The local routes disagree about canonical authority. Their original records are preserved."
    }

  }
  func refresh() async {
    guard !busy else { return }; loading = true; defer { loading = false; active = nil }
    for endpoint in endpoints {
      active = endpoint
      await endpoint.load()
    }
  }
  func more(_ endpoint: ServiceInboxEndpoint) async {
    guard !busy, let after = endpoint.snapshot.next else { return }
    loading = true; active = endpoint
    defer { loading = false; active = nil }
    await endpoint.load(after: after)
  }
  func close() { endpoints.forEach { $0.bridge.cancel() } }
}

struct TransferServiceInboxView: View {
  @StateObject private var model: TransferServiceInboxModel
  @ObservedObject private var walletModel: TransferModel
  private let repository: any WalletSession
  @State private var selected: ServiceInboxEndpoint?
  @State private var unlocking = false
  @State private var tab = "requests"
  @Environment(\.dismiss) private var dismiss
  init(service: TransferLogicalService, repository: any WalletSession, walletModel: TransferModel) {
    _model = StateObject(wrappedValue: TransferServiceInboxModel(service: service))
    self.repository = repository; self.walletModel = walletModel
  }
  var body: some View {
    VStack(spacing: 0) {
      if let selected {
        ResolvedTransferOperatorView(bridge: selected.bridge, editor: selected.editor, walletModel: walletModel,
          serviceName: model.service.name) { self.selected = nil }
      } else { inbox }
    }
    .frame(minWidth: 980, minHeight: 720)
    .task { await model.prepare(repository: repository) }
    .onDisappear { model.close() }
    .onChange(of: walletModel.walletUnlocked) { unlocked in
      if !unlocked { model.endpoints.forEach { $0.bridge.resolve(false) } }
    }
  }
  private var inbox: some View {
    VStack(spacing: 0) {
      HStack {
        VStack(alignment: .leading, spacing: 4) {
          Text(model.service.name).font(.title2.bold())
          Label("One service · All requests & grants · Local secS management", systemImage: "desktopcomputer").font(.caption).foregroundStyle(.secondary)
        }
        Spacer()
        Button(walletModel.walletUnlocked ? "Wallet" : "Unlock Wallet") { unlocking = true }
        Button("Close") { model.close(); dismiss() }.disabled(model.busy)
      }.padding(20)
      Divider()
      ScrollView {
        VStack(alignment: .leading, spacing: 18) {
          HStack {
            Button("Review all requests & grants in Wallet") { Task { await model.refresh() } }
              .buttonStyle(TransferPrimaryButtonStyle()).disabled(model.busy || model.endpoints.isEmpty || !walletModel.walletUnlocked)
            if model.busy { ProgressView().controlSize(.small) }
          }
          if !walletModel.walletUnlocked { Text("Unlock Wallet to authenticate. Requests and grants already loaded stay readable.").foregroundStyle(.secondary) }
          if model.complete { Label("All registered management stores loaded", systemImage: "checkmark.circle").foregroundStyle(.secondary) }
          else { Text("Inbox coverage is not complete until every registered server has been checked. Unavailable servers, additional pages and retained actions are shown below.").font(.callout).foregroundStyle(.secondary) }
          ForEach(model.failures.keys.sorted(), id: \.self) { key in
            Text(key + "\n" + (model.failures[key] ?? "")).foregroundStyle(.red).textSelection(.enabled)
          }
          ForEach(model.endpoints) { endpoint in endpointStatus(endpoint) }
          Picker("View", selection: $tab) {
            Text("Requests (\(model.requests.count))").tag("requests")
            Text("Grants (\(model.grants.count))").tag("grants")
            Text("Servers (\(model.service.servers.count))").tag("servers")
          }.pickerStyle(.segmented)
          if tab == "requests" { requests }
          else if tab == "grants" { grants }
          else {
            if let owner = model.endpoints.first(where: { $0.loaded && ($0.editor.inbox?.raw["owner_arena_upgrade"] as? [String:Any])?["create_arenas"] as? Bool == true }) {
              NativeArenaCreationView(editor: owner.editor, unlocked: walletModel.walletUnlocked)
            }
            TransferServiceServersView(service: model.service)
          }
        }.padding(24).frame(maxWidth: 940, alignment: .leading).frame(maxWidth: .infinity)
      }
    }
    .sheet(isPresented: $unlocking) {
      VStack {
        HStack { Text("Castalia Wallet").font(.headline); Spacer(); Button("Return to inbox") { unlocking = false } }.padding()
        TransferWalletView(model: walletModel)
      }.frame(width: 720, height: 660)
    }
    .overlay {
      if let endpoint = model.endpoints.first(where: { $0.bridge.consent != nil }) {
        ZStack {
          Color.black.opacity(0.25).ignoresSafeArea()
          ServiceInboxConsentView(bridge: endpoint.bridge)
            .background(.regularMaterial).cornerRadius(16).shadow(radius: 18)
        }
      }
    }

  }
  @ViewBuilder private func endpointStatus(_ endpoint: ServiceInboxEndpoint) -> some View {
    if let notice = endpoint.editor.resultNotice { Text(notice).font(.callout) }
    if let error = endpoint.editor.error { Text(error).foregroundStyle(.red) }
    if let failure = endpoint.bridge.failure { Text(failure).foregroundStyle(.red) }
    if let error = endpoint.error { Text(endpoint.id + "\n" + error).foregroundStyle(.red).textSelection(.enabled) }
    if endpoint.editor.state != .idle {
      Button((endpoint.editor.state == .prepared && !endpoint.editor.isRecovery ? "Resume retained action · " : "Recover retained action · ") + endpoint.id) { selected = endpoint }.disabled(model.busy)
    }
    if endpoint.snapshot.next != nil {
      Button("Load more requests · " + endpoint.id) { Task { await model.more(endpoint) } }.disabled(model.busy || !walletModel.walletUnlocked)
    }
  }
  private var requests: some View {
    VStack(alignment: .leading, spacing: 12) {
      if model.requests.isEmpty { Text(model.complete ? "No pending requests." : "Review the inbox to load pending requests.").foregroundStyle(.secondary) }
      ForEach(model.requests) { row in
        Button {
          guard let endpoint = model.endpoint(for: row), let request = try? NativeGrantRecipient(row.raw) else { return }
          endpoint.editor.select(request); selected = endpoint
        } label: {
          VStack(alignment: .leading, spacing: 5) {
            Text("Wallet " + row.subject.prefix(12) + "…").font(.headline)
            Text("Request " + (row.raw["request_id"] as? String ?? "").prefix(12) + "… · Configure permissions, scope and origin details").font(.caption).foregroundStyle(.secondary)
          }.padding(14).frame(maxWidth: .infinity, alignment: .leading).background(Color.primary.opacity(0.04)).cornerRadius(10)
        }.buttonStyle(.plain).disabled(model.busy || model.endpoint(for: row)?.editor.state != .idle || model.endpoint(for: row)?.loaded != true)
      }
    }
  }
  private var grants: some View {
    VStack(alignment: .leading, spacing: 12) {
      if model.grants.isEmpty { Text(model.complete ? "No active grants." : "Review the inbox to load active grants.").foregroundStyle(.secondary) }
      ForEach(model.grants) { row in
        VStack(alignment: .leading, spacing: 10) {
          DisclosureGroup("Servers & origin restrictions") {
            Text("Authority: " + row.authority).textSelection(.enabled)
            Text("Access points: " + (model.endpoint(for: row)?.origins.joined(separator: ", ") ?? "")).textSelection(.enabled)
            Text("The retained grant’s signed scope and receiver restrictions remain enforced.").font(.caption).foregroundStyle(.secondary)
          }
          NativeActiveGrantRow(grant: row.raw, disabled: model.busy || !walletModel.walletUnlocked || model.endpoint(for: row)?.editor.state != .idle || model.endpoint(for: row)?.loaded != true, configure: {
            guard let endpoint = model.endpoint(for:row) else { return }
            endpoint.editor.configure(row.raw)
            if endpoint.editor.existingConfiguration != nil { selected = endpoint }
          }) { reason in
            model.endpoint(for: row)?.editor.revoke(row.raw, reason: reason)
          }
        }
      }
    }
  }
}

struct TransferServiceServersView: View {
  let service: TransferLogicalService
  @State private var publication: LocalService?
  var body: some View {
    VStack(alignment: .leading, spacing: 14) {
      Text("Servers & access points").font(.headline)
      Text("These interfaces belong to one DevGraph. Network publishing changes reachability; Wallet credentials determine access.").foregroundStyle(.secondary)
      ForEach(service.servers) { server in
        VStack(alignment: .leading, spacing: 8) {
          Label(server.interface == .walletAPI ? "Wallet & graph access API" : "Private graph API", systemImage: "server.rack").font(.headline)
          Text(server.endpoint).textSelection(.enabled)
          if let config = server.connection {
            Text("Issuer: " + config.issuer).font(.caption).textSelection(.enabled)
            Button("Sharing & network…") { publication = server }
          }
        }.padding(14).frame(maxWidth: .infinity, alignment: .leading).background(Color.primary.opacity(0.04)).cornerRadius(10)
      }
      DisclosureGroup("Service identity") { Text("Graph ID: " + service.graphID).font(.caption.monospaced()).textSelection(.enabled) }
    }.sheet(item: $publication) { TransferPublicationView(service: $0).id($0.id) }
  }
}

private struct ServiceInboxConsentView: View {
  @ObservedObject var bridge: TransferOperatorBridge
  var body: some View {
    VStack(alignment: .leading, spacing: 16) {
      Text(bridge.confirmationTitle).font(.title2.bold())
      Text("Local secS RPC · Review the exact action below. Reading requests does not authorize a grant or revocation.").font(.callout)
      if let consent = bridge.consent { Text(consent.receiver + "\nIssuer: " + consent.issuer).textSelection(.enabled) }
      ScrollView { Text(bridge.disclosure).font(.system(.body, design: .monospaced)).textSelection(.enabled) }
      HStack { Button("Cancel") { bridge.resolve(false) }; Spacer(); Button("Approve in Castalia Wallet") { bridge.resolve(true) }.buttonStyle(TransferPrimaryButtonStyle()) }
    }.padding(24).frame(width: 760, height: 620)
  }
}
#endif
