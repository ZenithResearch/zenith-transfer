#if os(macOS)
import AppKit
import SwiftUI
import ZenithKit
import CastaliaCustody

@MainActor final class TransferModel: ObservableObject {
  @Published var wallet: WalletState? {
    didSet {
      let time=clock()
      unlockTimer.observe(unlocked:wallet?.unlocked == true,now:time.0,uptime:time.1)
      if wallet?.configured == false {
        rememberedPublicKey=nil;defaults.removeObject(forKey:Self.identityHintKey)
      } else if wallet?.unlocked == true,let key=wallet?.publicKey,
        key.range(of:"^[a-f0-9]{64}$",options:.regularExpression) != nil {
        rememberedPublicKey=key;defaults.set(key,forKey:Self.identityHintKey)
      }
    }
  }
  @Published var unlockDuration:TransferUnlockDuration {
    didSet { defaults.set(unlockDuration.rawValue,forKey:TransferUnlockDuration.settingKey);expire() }
  }
  @Published private(set) var locking=false
  @Published private var unlockTimer=TransferUnlockTimer()
  // Display hint only. Never used for signing, owner admission or authorization.
  private static let identityHintKey="Transfer.wallet.lastUnlockedPublicIdentity.v1"
  @Published private var rememberedPublicKey:String?
  var displayPublicKey:String? { wallet?.publicKey ?? rememberedPublicKey }
  var walletUnlocked:Bool { wallet?.unlocked == true && !locking }
  var unlockDeadline:Date? { unlockTimer.deadline(unlockDuration) }
  @Published var resources: [RegisteredResource] = []
  @Published var localResources: [LocalResource] = []
  @Published var localServices: [LocalService] = []
  @Published var localHealth: [String:LocalServiceHealth] = [:]
  @Published var discovering = false
  @Published var discoveryNotice: String?
  @Published var error: String?
  @Published var busy = false
  @Published private(set) var identityAccounts: [IdentityAccount] = []
  private let identityRegistry: IdentityAccountRegistry?
  let fileCatalog = TransferFileCatalog()
  let presetLibrary = TransferPresetLibrary()
  let repository: (any WalletSession)?
  private let registry: ResourceRegistry?
  private let defaults:UserDefaults
  private let clock:()->(Date,TimeInterval)
  private var generation = 0
  private var sessionReviewDirectory: URL?
  lazy var sessionReviews = TransferSessionReviewController(walletModel: self, directory: sessionReviewDirectory, defaults: defaults)

  init(directory:URL?=nil,defaults:UserDefaults = .standard,
    clock:@escaping ()->(Date,TimeInterval) = { (Date(),ProcessInfo.processInfo.systemUptime) }) {
    self.defaults=defaults;self.clock=clock
    unlockDuration=TransferUnlockDuration.load(defaults)
    if let key=defaults.string(forKey:Self.identityHintKey),key.range(of:"^[a-f0-9]{64}$",options:.regularExpression) != nil { rememberedPublicKey=key }
    var loadedRepository: (any WalletSession)?
    var loadedRegistry: ResourceRegistry?
    var loadedIdentities: IdentityAccountRegistry?
    do {
      let base = try directory ?? FileManager.default.url(for: .applicationSupportDirectory,
        in: .userDomainMask, appropriateFor: nil, create: true)
        .appendingPathComponent("ZenithTransfer", isDirectory: true)
      loadedRepository = try WalletRepository(directory: base.appendingPathComponent("Wallet"))
      loadedRegistry = try ResourceRegistry(directory: base.appendingPathComponent("Resources"))
      loadedIdentities = try IdentityAccountRegistry(directory: base.appendingPathComponent("Identities"))
      sessionReviewDirectory = base.appendingPathComponent("SessionReviews", isDirectory: true)
    } catch { self.error = "Transfer storage is unavailable." }
    repository = loadedRegistry == nil ? nil : loadedRepository
    registry = loadedRegistry
    identityRegistry = loadedIdentities
  }
  func discoverLocalResources() async {
    guard !discovering else { return }
    discovering = true
    let (result,services) = await Task.detached { (LocalResourceDiscovery.scan(),LocalServiceDiscovery.scan()) }.value
    localResources = result.resources;localServices=services.services;localHealth=[:]
    discoveryNotice = result.unavailable || services.unavailable ? "A local discovery registry could not be read safely." :
      (result.rejected + services.rejected > 0 ? "Some unsupported or invalid service records were skipped." : nil)
    let entries=localServices.map { ("service:"+$0.id,$0.endpoint,$0.connection,$0.interface == .walletAPI ? $0.resource_id : nil,$0.interface == .walletAPI ? $0.id : nil) }
      + localResources.map { ("resource:"+$0.id,$0.endpoint,$0.connection,nil as String?,nil as String?) }
    // Bound concurrency; these probes send public metadata requests only.
    for start in stride(from:0,to:entries.count,by:8) {
      let batch=Array(entries[start..<min(start+8,entries.count)])
      let checked=await withTaskGroup(of:(String,LocalServiceHealth).self,returning:[String:LocalServiceHealth].self) { group in
        for entry in batch { group.addTask { (entry.0,await LocalServiceProbe.check(endpoint:entry.1,connection:entry.2,resourceID:entry.3,instanceID:entry.4)) } }
        var values:[String:LocalServiceHealth]=[:]
        for await (id,health) in group { values[id]=health };return values
      }
      localHealth.merge(checked) { _,new in new }
    }
    discovering = false
  }
  func refresh() async {
    let expected=generation
    do {
      resources = try registry?.load() ?? []
      let state=try await repository?.state()
      guard expected == generation,!locking else { return }
      wallet=state;expire()
      try reloadIdentityAccounts()
    } catch { self.error = "Could not read saved settings. Existing files have been preserved." }
  }
  func reloadIdentityAccounts() throws {
    identityAccounts = try displayPublicKey.map { try identityRegistry?.load(wallet: $0) ?? [] } ?? []
  }
  func saveIdentityAccount(_ value: IdentityAccount?, replacing expected: IdentityAccount?) throws {
    guard walletUnlocked, let owner = wallet?.publicKey,
      (value?.walletPublicKey ?? expected?.walletPublicKey) == owner, let identityRegistry
    else { throw WalletFailure.locked }
    try identityRegistry.saveApplicationRecord(value, replacing: expected)
    try reloadIdentityAccounts()
  }
  func register(_ value: RegisteredResource, replacing expected: RegisteredResource?) {
    do {
      guard let registry else { throw WorkServerSetupError.storage }
      try registry.save(value, replacing: expected)
      resources = try registry.load()
    } catch { self.error = "The resource changed or could not be saved. Reload it before trying again." }
  }
  func remove(_ value: RegisteredResource) {
    do {
      guard let registry else { throw WorkServerSetupError.storage }
      try registry.save(nil, replacing: value); resources = try registry.load()
    } catch { self.error = "The resource could not be removed. Its server grants are unchanged." }
  }
  func perform<T>(onFailure: ((String) -> Void)? = nil,
    _ action: @escaping (any WalletSession) async throws -> T,
    success: @escaping (T) -> Void = { _ in }) {
    expire()
    guard !busy, !locking, let repository else { return }
    busy = true; error = nil
    let expected = generation
    Task {
      do {
        let value = try await action(repository)
        let state = try await repository.state()
        guard generation == expected else { busy = false; return }
        wallet=state
        // Account metadata failure must not misreport a completed custody action.
        if (try? reloadIdentityAccounts()) == nil { identityAccounts = [] }
        expire()
        guard generation == expected else { busy=false;return }
        busy = false; success(value)
      } catch {
        let state = try? await repository.state(); busy = false
        guard generation == expected else { return }
        wallet=state
        // WalletFailure exposes a closed, password-free set of messages. Never
        // display arbitrary native/system error text or interpolate input.
        let message = (error as? WalletFailure)?.errorDescription
          ?? "Wallet could not complete this step. No password or key has been logged."
        if let onFailure { onFailure(message) } else { self.error = message }
      }
    }
  }
  func lock() {
    guard !locking else { return }
    locking=true
    generation += 1
    repository?.invalidatePendingWork()
    unlockTimer.clear()
    Task { await repository?.lock(); wallet = try? await repository?.state();locking=false }
  }
  func userActivity() {
    expire()
    guard walletUnlocked else { return }
    let time=clock()
    unlockTimer.activity(unlockDuration,now:time.0,uptime:time.1)
  }
  func expire() {
    let time=clock()
    if unlockTimer.expired(unlockDuration,now:time.0,uptime:time.1) { lock() }
  }
}

struct TransferConsole: View {
  @ObservedObject var model:TransferModel
  @State private var section = "resources"
  private let clock = Timer.publish(every: 5, on: .main, in: .common).autoconnect()
  var body: some View {
    HStack(spacing: 0) {
      VStack(alignment: .leading, spacing: 16) {
        Text("Zenith Transfer").font(.title2.bold()).padding(.bottom, 12)
        nav("Resources & requests", "square.stack.3d.up", "resources")
        nav("Credential presets", "slider.horizontal.3", "presets")
        nav("Wallet", "wallet.pass", "wallet")
        nav("Settings", "gearshape", "settings")
        nav("Transfer files", "qrcode", "files")
        Spacer()
        Text(model.walletUnlocked ? "Transfer Wallet unlocked" : "Transfer Wallet locked")
          .font(.caption).foregroundStyle(.secondary)
        if model.walletUnlocked { Button("Lock Wallet") { model.lock() } }
      }.padding(20).frame(width: 210).frame(maxHeight: .infinity)
        .background(Color(nsColor: .controlBackgroundColor))
      Divider()
      Group {
        switch section {
        case "presets": TransferPresetsView(library: model.presetLibrary)
        case "wallet": TransferWalletWorkspace(model: model, openAccess: { section = "resources" })
        case "settings": TransferSettingsView(model: model, openResources: { section = "resources" })
        case "files": TransferWindow(catalogModel: model.fileCatalog)
        default: TransferResourcesView(model: model)
        }
      }.frame(maxWidth: .infinity, maxHeight: .infinity)
    }.walletUserActivity { model.userActivity() }
      .task { model.sessionReviews.resumeConfiguredBridge(); await model.refresh(); await model.discoverLocalResources() }
      .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
        model.expire()
        Task { await model.discoverLocalResources() }
      }
      .onReceive(clock) { _ in model.expire() }
      .onReceive(NotificationCenter.default.publisher(for: NSApplication.willTerminateNotification)) { _ in model.sessionReviews.stop(); model.lock() }
      .alert("Needs attention", isPresented: Binding(get: { model.error != nil },
        set: { if !$0 { model.error = nil } })) { Button("OK") { model.error = nil } }
        message: { Text(model.error ?? "") }
  }
  private func nav(_ title: String, _ image: String, _ value: String) -> some View {
    Button { section = value } label: {
      Label(title, systemImage: image).frame(maxWidth: .infinity, alignment: .leading)
        .padding(10).background(section == value ? Color.accentColor.opacity(0.12) : .clear)
        .cornerRadius(8)
    }.buttonStyle(.plain)
  }
}

private struct TransferResourcesView: View {
  @ObservedObject var model: TransferModel
  @State private var selected: TransferConnectionSelection?
  @State private var proposed: RegisteredResource?
  @State private var replacing: RegisteredResource?
  @State private var removing: RegisteredResource?
  @State private var connectionScreen: TransferConnectionScreen?
  @State private var ownerService: LocalService?
  @State private var publicationService: LocalService?
  @State private var address = ""
  private var current: RegisteredResource? { selected?.savedResource(in: model.resources) }
  private var currentLocal: LocalResource? { selected?.localResource(in: model.localResources) }
  private var currentService: LocalService? { selected?.service(in:model.localServices) }
  private var serviceGroups: [TransferLogicalService] { TransferLogicalService.groups(model.localServices) }
  private var currentGroup: TransferLogicalService? {
    guard case .graph(let id) = selected else { return nil }
    return serviceGroups.first { $0.id == id }
  }
  private var separateSavedConnections: [RegisteredResource] {
    model.resources.filter { resource in !serviceGroups.contains { $0.contains(resource) } }
  }
  private var remainingResources: [LocalResource] {
    model.localResources.filter { resource in !model.localServices.contains { $0.resource_id==resource.id && $0.endpoint==resource.endpoint } }
  }

  var body: some View {
    VStack(alignment: .leading, spacing: 16) {
      HStack {
        VStack(alignment: .leading, spacing: 5) {
          Text("Resources & requests").font(.largeTitle.bold())
          Text("Choose a service to review its access requests and grants.").foregroundStyle(.secondary)
        }
        Spacer()
        Button(model.discovering ? "Checking this Mac…" : "Refresh local services") {
          Task { await model.discoverLocalResources() }
        }.disabled(model.discovering)
        Button("Import connection file") { importProfile() }
      }
      HStack {
        TextField("https://your-devgraph-server", text: $address)
        Button("Look up server") { discover() }.disabled(model.busy || address.isEmpty)
      }
      Text("Lookup reads public DevGraph settings. Review the issuer and address before registration.")
        .font(.caption).foregroundStyle(.secondary)
      Divider()
      HStack(alignment: .top, spacing: 24) {
        ScrollView {
          VStack(alignment: .leading, spacing: 10) {
            Text("Services on this Mac").font(.headline)
            ForEach(serviceGroups) { service in
              Button { selected = .graph(service.id) } label: {
                VStack(alignment:.leading,spacing:4) {
                  Label(service.name,systemImage:"square.stack.3d.up").font(.headline)
                  Text("DevGraph · \(service.servers.count) access points").font(.caption).foregroundStyle(.secondary)
                  Text("One inbox · Local management").font(.caption).foregroundStyle(.secondary)
                }.frame(maxWidth:.infinity,alignment:.leading).padding(12)
                  .background(selected == .graph(service.id) ? Color.accentColor.opacity(0.12) : Color.primary.opacity(0.04)).cornerRadius(10)
              }.buttonStyle(.plain)
            }
            if !remainingResources.isEmpty { Text("Configured resources").font(.headline) }
            if model.localResources.isEmpty && model.localServices.isEmpty {
              Text(model.discovering ? "Checking the resource registry…" : "No local services registered").foregroundStyle(.secondary)
            }
            ForEach(remainingResources) { resource in
              Button { selected = .local(resource.id) } label: {
                VStack(alignment: .leading, spacing: 4) {
                  Label(resource.name, systemImage: "desktopcomputer").font(.headline)
                  Text(resource.endpoint).font(.caption).foregroundStyle(.secondary)
                  Text(model.localHealth["resource:"+resource.id]?.label ?? "Checking this endpoint…")
                    .font(.caption).foregroundStyle(.secondary)
                }.frame(maxWidth: .infinity, alignment: .leading).padding(12)
                  .background(selected == .local(resource.id) ? Color.accentColor.opacity(0.12) : Color.primary.opacity(0.04))
                  .cornerRadius(10)
              }.buttonStyle(.plain)
            }
            if let notice = model.discoveryNotice { Text(notice).font(.caption).foregroundStyle(.secondary) }
            Divider().padding(.vertical, 8)
            Text("Saved connections").font(.headline)
            if separateSavedConnections.isEmpty { Text("No other saved connections").foregroundStyle(.secondary) }
            ForEach(separateSavedConnections) { resource in
              Button { selected = .saved(resource.id) } label: {
                VStack(alignment: .leading, spacing: 4) {
                  Label(resource.configuration.name, systemImage: "server.rack").font(.headline)
                  Text(resource.id).font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
                }.frame(maxWidth: .infinity, alignment: .leading).padding(12)
                  .background(selected == .saved(resource.id) ? Color.accentColor.opacity(0.12) : Color.primary.opacity(0.04))
                  .cornerRadius(10)
              }.buttonStyle(.plain)
            }
          }
        }.frame(width: 260)
        Divider()
        ScrollView {
          if let group = currentGroup {
            VStack(alignment: .leading, spacing: 18) {
              Text(group.name).font(.title.bold())
              Text("One DevGraph service").font(.headline)
              Text("Review every request and active grant in one inbox. Choose each recipient’s permissions and hierarchy scopes there; servers and origin restrictions are inside the service.")
              Label("Management stays on this Mac through signed secS RPC", systemImage: "desktopcomputer").foregroundStyle(.secondary)
              if !group.hasConsistentAuthority && !group.walletServers.isEmpty {
                Text("These servers disagree about the issuer identity. Repair their profiles before managing access.").foregroundStyle(.red)
              } else if group.walletServers.contains(where: { model.localHealth["service:" + $0.id]?.walletAdministration == true }) {
                Button("Manage credentials") { connectionScreen = .logical(group) }
                  .buttonStyle(TransferPrimaryButtonStyle()).disabled(model.repository == nil)
              } else if let unclaimed = group.walletServers.first(where: { model.localHealth["service:" + $0.id]?.ownerRegistrationRequired == true }) {
                Button("Set up owner Wallet") { ownerService = unclaimed }.buttonStyle(TransferPrimaryButtonStyle())
              } else {
                Text("Local Wallet administration is not available yet. Refresh the registered services or launch this graph’s Wallet service.").foregroundStyle(.secondary)
              }
              Divider()
              TransferServiceServersView(service: group)
            }.frame(maxWidth: .infinity, alignment: .leading)
          } else if let current {
            VStack(alignment: .leading, spacing: 16) {
              Text(current.configuration.name).font(.title.bold())
              Label("DevGraph · access management", systemImage: "person.badge.key")
              Text("Review requests, choose permissions and resource paths, then approve grants with your Transfer Wallet.")
              Text("A selected container includes the resources beneath it at the time of access. Global access remains limited by the server's operator policy.")
                .foregroundStyle(.secondary)
              Button("Manage access in Transfer") { connectionScreen = .access(current) }
                .buttonStyle(TransferPrimaryButtonStyle())
                .disabled(model.repository == nil)
              if !model.walletUnlocked {
                Text("You can unlock your Wallet inside access management. Set up your Wallet first if you haven’t imported one yet.").foregroundStyle(.secondary)
              }
              Text("Only a Wallet authorized by this service can manage its grants. Transfer signs your reviewed decisions and sends them directly to this server.")
                .font(.callout).foregroundStyle(.secondary)
              DisclosureGroup("Connection and issuer") { connection(current.configuration) }
              Text("Existing grants can be inspected and revoked in the inbox. Changing an existing grant without a new member request is still planned.")
                .font(.callout).foregroundStyle(.secondary)
              Divider()
              Button("Remove from this Mac", role: .destructive) { removing = current }
              Text("Removing a registration does not stop the service or revoke anyone's access.")
                .font(.caption).foregroundStyle(.secondary)
            }.frame(maxWidth: .infinity, alignment: .leading)
          } else if let service=currentService {
            VStack(alignment:.leading,spacing:16) {
              Text(service.title).font(.title.bold())
              Text(service.endpoint).textSelection(.enabled)
              Text(model.localHealth["service:"+service.id]?.label ?? "Checking this endpoint…").font(.headline)
              if model.localHealth["service:"+service.id]?.ownerRegistrationRequired == true {
                Text("Set up your Wallet as this DevGraph’s owner to start managing access.").font(.title3)
                Text("Unlock your Wallet, review administrator access, then register it. After setup, you can review requests and choose each credential’s permissions and resource paths here in Transfer.").foregroundStyle(.secondary)
                Button("Set up owner Wallet") { ownerService = service }.buttonStyle(TransferPrimaryButtonStyle())
                Label("One-time setup · This Mac only", systemImage: "desktopcomputer").font(.callout).foregroundStyle(.secondary)
              } else if let configuration=service.connection,model.localHealth["service:"+service.id]?.walletAdministration == true {
                if (try? LocalAdminRPC.discover(configuration: configuration)) != nil {
                  Label("Local secS RPC · Signed Wallet commands", systemImage: "desktopcomputer").foregroundStyle(.secondary)
                  Button("Manage credentials") {
                    guard let value=selected?.accessResource(in:model.localServices,health:model.localHealth) else { model.error="This service changed. Refresh and select it again.";return }
                    connectionScreen = .access(value)
                  }.buttonStyle(TransferPrimaryButtonStyle())
                  Text("Manage this DevGraph directly on this Mac. Its HTTPS service runs independently for remote clients.").foregroundStyle(.secondary)
                } else {
                  Button("Review this Wallet connection") {
                    guard let value=selected?.accessResource(in:model.localServices,health:model.localHealth) else { model.error="This service changed. Refresh and select it again.";return }
                    propose(value)
                  }.buttonStyle(TransferPrimaryButtonStyle())
                }
                connection(configuration)
              } else {
                Text(service.interface == .privateAPI ? "This is the private API. It does not offer Wallet credential administration. Select a running Wallet API to provision credentials." : "Wallet administration is not verified at this endpoint. Refresh after starting the service or correcting its connection profile.")
                  .foregroundStyle(.secondary)
              }
              DisclosureGroup("Service details") {
                Text("Service ID: "+service.id).font(.caption.monospaced()).textSelection(.enabled)
                Text("Graph ID: "+service.resource_id).font(.caption.monospaced()).textSelection(.enabled)
                Text("This selection keeps this exact service, issuer and certificate. Other interfaces of the same graph are separate selections.").font(.caption).foregroundStyle(.secondary)
              }
              Divider()
              Button("Sharing & network…", systemImage:"network") { publicationService=service }
              Text("Review private Tailnet and public Funnel publishing for this exact local service. Network access does not grant credential permissions.").font(.caption).foregroundStyle(.secondary)
              Text("Discovery checks public metadata only. Your Wallet identity and signed approvals are sent after you review and select a Wallet connection.").font(.caption).foregroundStyle(.secondary)
            }.frame(maxWidth:.infinity,alignment:.leading)
          } else if let local = currentLocal {
            VStack(alignment: .leading, spacing: 16) {
              Text(local.name).font(.title.bold())
              Label("DevGraph · configured resource", systemImage: "desktopcomputer")
              Text(local.endpoint).textSelection(.enabled)
              Text("Resource ID: \(local.id)").font(.caption.monospaced()).textSelection(.enabled)
              Text("Discovered in ~/.zenith/resources/v1. This is public configuration, not proof that the service is running or that your Wallet owns it.")
                .foregroundStyle(.secondary)
              Text(model.localHealth["resource:"+local.id]?.label ?? "Checking this endpoint…").font(.headline)
              if let configuration = local.connection,model.localHealth["resource:"+local.id]?.walletAdministration == true {
                Button("Review connection") { do { propose(try RegisteredResource(configuration: configuration)) }
                  catch { model.error = "This service needs valid public connection settings." } }
                  .buttonStyle(TransferPrimaryButtonStyle())
                connection(configuration)
              } else {
                Text("Wallet administration unavailable on this connection").font(.headline)
                Text("This entry identifies the configured API. It does not launch or substitute another endpoint. Once a Wallet service is launched for this graph, select its separate entry under Services on this Mac.")
                  .foregroundStyle(.secondary)
              }
              Text("Registration does not grant operator access or change certificate trust. The server checks your Wallet when you review requests.")
                .font(.callout).foregroundStyle(.secondary)
            }.frame(maxWidth: .infinity, alignment: .leading)
          } else {
            VStack(alignment: .leading, spacing: 16) {
              Text("Your resource console").font(.title.bold())
              Text("Choose a service discovered on this Mac, import a public connection file, or look up an HTTPS DevGraph address. Review its public settings before saving a connection.")
              Text("DevGraph is the first supported resource. A port or a running Hub service alone does not establish ownership or provide a credential-management interface.")
                .foregroundStyle(.secondary)
              Text("Use your Transfer Wallet to manage requests and grants for a registered service. Each service checks its own operator permissions.")
                .font(.callout).foregroundStyle(.secondary)
            }.frame(maxWidth: .infinity, alignment: .leading)
          }
        }
      }.frame(maxHeight: .infinity)
    }.padding(24)
      .sheet(item: $publicationService) { service in
        TransferPublicationView(service:service).id(service.id)
      }
      .sheet(item: $ownerService) { service in
        TransferServiceOwnerView(service: service, walletModel: model).id(service.id)
      }
      .sheet(item: $connectionScreen) { screen in
        Group {
          switch screen {
          case .logical(let service):
            if let repository = model.repository { TransferServiceInboxView(service: service, repository: repository, walletModel: model) }
          case .access(let resource):
            if let repository = model.repository { TransferOperatorView(resource: resource, repository: repository, walletModel: model) }
          }
        }.id(screen.id)
      }
      .sheet(item: $proposed) { value in
        VStack(alignment: .leading, spacing: 16) {
          Text("Register this resource?").font(.title2.bold())
          Text("Confirm these public settings against your server administrator's information. Registration saves the connection; the server still checks your Wallet’s authority.")
          ScrollView {
            if let replacing {
              Text("Replace saved connection settings").font(.headline)
              connection(replacing.configuration)
              Divider()
              Text("New settings").font(.headline)
            }
            connection(value.configuration)
          }
          HStack {
            Button("Cancel") { proposed = nil }
            Spacer()
            Button("Register resource") {
              model.register(value, replacing: replacing)
              selected = .saved(value.id); proposed = nil
            }.buttonStyle(TransferPrimaryButtonStyle())
          }
        }.padding(24).frame(width: 600, height: 500)
      }
      .confirmationDialog("Remove this resource registration?", isPresented: Binding(
        get: { removing != nil }, set: { if !$0 { removing = nil } })) {
        Button("Remove registration", role: .destructive) {
          if let removing { model.remove(removing) }; removing = nil
        }
      } message: { Text("Server grants and Wallet credentials remain unchanged.") }
  }
  private func connection(_ config: WorkAccessConfiguration) -> some View {
    VStack(alignment: .leading, spacing: 8) {
      Text(config.name).font(.headline)
      Text("Server: \(config.origin)")
      Text("Issuer: \(config.issuer)")
      Text("Key ID: \(config.authority.key_id)")
      Text("Public key: \(config.authority.public_key)").font(.caption.monospaced())
      Text("Network: \(config.network?.rawValue ?? "HTTPS")")
      if let fingerprint = config.tls_certificate_sha256 {
        Text("Certificate SHA-256: \(fingerprint)").font(.caption.monospaced())
        Text("This certificate pin applies only to this saved Transfer connection.")
          .font(.caption).foregroundStyle(.secondary)
      }
    }.textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading).padding(.vertical, 8)
  }
  private func importProfile() {
    let panel = NSOpenPanel(); panel.allowedContentTypes = [.json]; panel.canChooseDirectories = false
    guard panel.runModal() == .OK, let url = panel.url else { return }
    let scoped = url.startAccessingSecurityScopedResource()
    defer { if scoped { url.stopAccessingSecurityScopedResource() } }
    do { propose(try RegisteredResource(configuration: WorkServerSettings.readFile(url))) }
    catch { model.error = "Choose a public DevGraph connection file. Wallet files and credentials cannot be registered as resources." }
  }
  private func discover() {
    guard !model.busy else { return }; model.busy = true
    Task {
      defer { model.busy = false }
      do {
        let result = try await WorkServerDiscovery.discover(address)
        propose(try RegisteredResource(configuration: result))
      } catch { model.error = "Could not look up this HTTPS server. For a private LAN certificate, import its administrator-supplied connection file instead." }
    }
  }
  private func propose(_ value: RegisteredResource) {
    replacing = model.resources.first { $0.id == value.id }; proposed = value
  }
}
#endif
