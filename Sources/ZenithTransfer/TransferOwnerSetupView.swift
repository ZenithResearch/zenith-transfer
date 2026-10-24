#if os(macOS)
import SwiftUI
import ZenithKit

@MainActor final class OwnerSetupModel: ObservableObject {
  let resource: LocalResource
  @Published var inspection: OwnerSetupInspection?
  @Published var error: String?
  let target: OwnerRegistrationTarget
  var endpoint: String { target.endpoint }
  @Published var publishHierarchy = false
  @Published var review: OwnerSetupPlan?
  @Published var installation: OwnerInstallationReview?
  @Published var installedConnection: WorkAccessConfiguration?
  @Published var installationBusy = false
  @Published var activationAttempted = false
  @Published var installationStatus: String?
  private let installer = OwnerInstallationCoordinator()
  func prepareInstallation(repository: (any WalletSession)?) async {
    guard !installationBusy else { return }; installationBusy = true; defer { installationBusy = false }
    do {
      guard let plan = saved, let repository else { throw OwnerSetupError.walletLocked }
      try target.check(plan)
      let wallet = try await repository.state()
      guard wallet.unlocked, wallet.publicKey == plan.ownerPublicKey else { throw OwnerSetupError.walletLocked }
      installation = try await installer.prepare(plan)
    } catch { self.error = "Production preparation did not complete. The retained run must be inspected before another attempt; no retry was started." }
  }
  func activateInstallation(repository: (any WalletSession)?) async {
    guard !installationBusy else { return }; installationBusy = true; defer { installationBusy = false }
    do {
      guard let plan = saved, let installation, let repository else { throw OwnerSetupError.walletLocked }
      try target.check(plan)
      let wallet = try await repository.state()
      guard wallet.unlocked, wallet.publicKey == plan.ownerPublicKey else { throw OwnerSetupError.walletLocked }
      activationAttempted = true
      installedConnection = try await installer.activate(plan, review: installation)
    } catch { self.error = "Activation did not finish with a verified result. Preserve this run and inspect its status; do not retry or replace the setup." }
  }
  func inspectInstallation() async {
    guard !installationBusy, let plan = saved ?? expected else { return }
    installationBusy = true; defer { installationBusy = false }
    do {
      let state = try await installer.status(plan)
      installation = state.review; activationAttempted = state.activationAttempted || state.activationRecorded
      installationStatus = state.activationRecorded
        ? "An activation receipt is recorded. Reload the local resource connection and verify its live inbox."
        : (state.activationAttempted ? "Activation started. Preserve this run for reconciliation; no retry is enabled." : "No activation was dispatched. Prepared files are preserved.")
      if state.prepared { saved = plan }
    } catch { self.error = "Could not inspect the retained setup safely. Existing files and authority are unchanged by this inspection." }
  }
  @Published var saved: OwnerSetupPlan?
  private let inspector = OwnerSetupInspector()
  private let store: OwnerSetupStore?
  private var expected: OwnerSetupPlan?
  init(resource: LocalResource) {
    self.resource = resource; target = OwnerRegistrationTarget(resource: resource)
    let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
    store = try? OwnerSetupStore(directory: base.appendingPathComponent("ZenithTransfer/OwnerSetups"))
  }
  func refresh() async {
    review = nil; saved = nil; inspection = nil
    do {
      inspection = try await inspector.inspect(resource)
      expected = try store?.load(resourceID: resource.id)
      if let old = expected {
        // Preserve prior plans as evidence; never restore their different URL
        // into the connection selected by the user.
        try target.check(old)
        publishHierarchy = old.publishHierarchy
        // Retained plans are immutable evidence, never authority or a reason to
        // silently carry member-style permission selectors into owner setup.
      }
      // Ownership does not require selecting a member scope or fetching the hierarchy.
    } catch { self.error = (error as? LocalizedError)?.errorDescription ?? "The configured local DevGraph could not be read." }
  }
  func prepare(wallet: WalletState?) {
    do {
      guard wallet?.unlocked == true, let publicKey = wallet?.publicKey else { throw OwnerSetupError.walletLocked }
      guard let inspection else { throw OwnerSetupError.unavailable }
      guard !target.needsInstalledWalletSupport else { throw OwnerSetupError.selectedConnectionUpgradeRequired }
      review = try OwnerSetupPlan.ownerBootstrap(resource: resource, inspection: inspection,
        ownerPublicKey: publicKey, walletEndpoint: endpoint, now: UInt64(Date().timeIntervalSince1970),
        publishHierarchy: publishHierarchy)
    } catch { self.error = (error as? LocalizedError)?.errorDescription ?? "Review the owner setup settings." }
  }
  func save(repository: (any WalletSession)?) async {
    do {
      guard let plan = review, let repository else { throw OwnerSetupError.walletLocked }
      try target.check(plan)
      let wallet = try await repository.state()
      guard wallet.unlocked, wallet.publicKey == plan.ownerPublicKey else { throw OwnerSetupError.walletLocked }
      let current = try await inspector.inspect(resource)
      guard current.registrationSHA256 == plan.registrationSHA256,
        current.configurationSHA256 == plan.configurationSHA256, let store else { throw OwnerSetupError.changed }
      let currentWallet = try await repository.state()
      guard currentWallet.unlocked, currentWallet.publicKey == plan.ownerPublicKey, review == plan else { throw OwnerSetupError.walletLocked }
      try store.save(plan, replacing: expected); expected = plan; saved = plan; review = nil
    } catch { self.error = (error as? LocalizedError)?.errorDescription ?? "The setup could not be saved. Existing files are preserved." }
  }
}

struct TransferOwnerSetupView: View {
  @StateObject private var setup: OwnerSetupModel
  @ObservedObject var walletModel: TransferModel
  @State private var unlocking = false
  @State private var confirmingActivation = false
  @State private var credentials: RegisteredResource?
  @Environment(\.dismiss) private var dismiss
  init(resource: LocalResource, walletModel: TransferModel) {
    self.walletModel = walletModel; _setup = StateObject(wrappedValue: OwnerSetupModel(resource: resource))
  }
  var body: some View {
    VStack(spacing: 0) {
      HStack {
        VStack(alignment: .leading, spacing: 4) {
          Text("Connect your DevGraph to Transfer").font(.title2.bold())
          Text(setup.resource.name + " · " + setup.resource.endpoint).foregroundStyle(.secondary)
        }
        Spacer()
        Button(walletModel.walletUnlocked ? "Wallet" : "Unlock Wallet") { unlocking = true }
        Button("Close setup") { dismiss() }
      }.padding(20)
      Divider()
      ScrollView {
        VStack(alignment: .leading, spacing: 24) {
          if let connection = setup.installedConnection {
            Label("Production Wallet endpoint is active", systemImage: "checkmark.shield.fill").font(.title2.bold())
            Text(connection.origin).textSelection(.enabled)
            Text("No member credentials were issued by setup. Open the real inbox with this Wallet to confirm owner authentication, then configure an individual credential’s actions, scope and validity.")
            Button("Open Credentials & requests") {
              do { credentials = try RegisteredResource(configuration: connection) }
              catch { setup.error = "The activated connection could not be decoded safely." }
            }.buttonStyle(TransferPrimaryButtonStyle())
          } else if let saved = setup.saved {
            Label("Owner setup plan saved", systemImage: "checkmark.circle.fill").font(.title2.bold())
            Text("Your choices are saved for this DevGraph. They have not been installed: no owner authority, member grant or HTTPS listener is active from this plan.")
            summary(saved)
            if let installation = setup.installation {
              Divider()
              Text("Review production installation").font(.title2.bold())
              Text("Owner Wallet: " + installation.ownerPublicKey).font(.caption.monospaced()).textSelection(.enabled)
              Text("Endpoint: " + installation.endpoint).textSelection(.enabled)
              Text("Certificate SHA-256: " + installation.certificateSHA256).font(.caption.monospaced()).textSelection(.enabled)
              Text("Native policy \(installation.previousNativeVersion) → \(installation.nativeVersion). Preserve \(installation.preservedRules) existing rules and the same verifier key. No member grants, Work changes or database restart.")
              Text("Available credential operations").font(.headline)
              Text("Service signing key expires \(Date(timeIntervalSince1970: TimeInterval(installation.nativeKeyDeadline)).formatted()). Its maintenance deadline is separate from member grant validity.").font(.caption).foregroundStyle(.secondary)
              Text("New member native admission happens only with your final credential approval. No member is admitted during owner setup.").font(.caption)
              Text(installation.operations.map { OwnerPermissionPreset.title($0.replacingOccurrences(of: "devgraph.work.", with: "").replacingOccurrences(of: ".v2", with: "")) }.joined(separator: " · "))
              Text("This starts a private LAN HTTPS service and saves its exact certificate pin. Global certificate trust stays unchanged. Individual access is still chosen in the custom credential editor. Onward delegation is disabled.").font(.callout)
              Button("Activate this production setup") { confirmingActivation = true }
                .buttonStyle(TransferPrimaryButtonStyle()).disabled(setup.installationBusy || setup.activationAttempted || !walletModel.walletUnlocked)
            } else {
              Text("Prepare the exact installation next. Preparation stages public review and new service-owned TLS/read keys; it starts no listener and installs no authority.").foregroundStyle(.secondary)
              Text("Member admission").font(.headline)
              Text("Each recipient is admitted when you approve their exact credential; no recipient keys are needed for setup.").font(.caption).foregroundStyle(.secondary)
              Text("The production review lists the available operations. Each exact credential decision supplies its own recipient and scope.").font(.caption).foregroundStyle(.secondary)
              Button("Prepare production setup") { Task { await setup.prepareInstallation(repository: walletModel.repository) } }
                .buttonStyle(TransferPrimaryButtonStyle()).disabled(setup.installationBusy || !walletModel.walletUnlocked)
            }
            if setup.installationBusy { ProgressView("Checking production setup…") }
            if let status = setup.installationStatus { Text(status).font(.callout).foregroundStyle(.secondary) }
            Button("Inspect retained setup status") { Task { await setup.inspectInstallation() } }.disabled(setup.installationBusy)
            Button("Continue editing") { setup.saved = nil; setup.installation = nil }.disabled(setup.installationBusy || setup.activationAttempted)
          } else if let plan = setup.review {
            Text("Review owner registration").font(.title2.bold())
            summary(plan)
            Text("This saves a setup plan on this Mac. It does not activate credentials, start a listener or change your production graph.").foregroundStyle(.secondary)
            HStack {
              Button("Edit settings") { setup.review = nil }
              Spacer()
              Button("Save setup plan") { Task { await setup.save(repository: walletModel.repository) } }
                .buttonStyle(TransferPrimaryButtonStyle()).disabled(!walletModel.walletUnlocked)
            }
          } else {
            section("1. Your graph and owner Wallet") {
              Label(setup.inspection?.healthy == true ? "Configured DevGraph verified" : "Checking local DevGraph…", systemImage: setup.inspection == nil ? "clock" : "checkmark.shield")
              Text("This setup targets your configured graph. Saved test connections stay separate.").foregroundStyle(.secondary)
              if let key = walletModel.wallet?.publicKey {
                Text("Owner Wallet").font(.headline)
                Text(key).font(.caption.monospaced()).textSelection(.enabled)
              }
              Text(walletModel.walletUnlocked ? "Use this Wallet to administer access after the setup is approved." : "Unlock your Transfer Wallet here to bind the reviewed setup to its identity.").foregroundStyle(.secondary)
              Text("The owner’s administration role is separate from member Work access.").font(.callout)
            }
            section("2. Owner administration") {
              Label("Administrator for this DevGraph", systemImage: "person.badge.key.fill")
              Text("Register this Wallet as the owner using this Mac’s private local setup. It can review requests, issue scoped credentials and revoke access across this graph.")
              Text("There is no credential to select for yourself. Choose each recipient’s permissions, preset, scope and duration later in Credentials & requests.").foregroundStyle(.secondary)
              Text("Wallet signatures authenticate administration. This setup creates no member grant and does not enable onward delegation.").font(.callout)
              VStack(alignment: .leading, spacing: 8) {
                Text("Selected connection").font(.headline)
                Text(setup.target.name + " · " + setup.target.endpoint).textSelection(.enabled)
                Text("Owner registration uses the connection you selected in Resources & requests.").font(.caption).foregroundStyle(.secondary)
                if setup.target.needsInstalledWalletSupport {
                  Label("This connection needs the DevGraph Wallet administration upgrade before registration can continue.", systemImage: "info.circle")
                    .font(.callout)
                  Text("The existing server is a private HTTP API. Transfer will keep this target and will not choose a different address or start another listener for you.").font(.caption).foregroundStyle(.secondary)
                }
              }
              Toggle("Publish scope names for access requests", isOn: $setup.publishHierarchy)
                .disabled(setup.target.needsInstalledWalletSupport)
              Text("Scope names remain private unless enabled. Work details always require a grant.").font(.caption).foregroundStyle(.secondary)
            }
          }
        }.padding(24).frame(maxWidth: 860, alignment: .leading).frame(maxWidth: .infinity)
      }
      if setup.saved == nil && setup.review == nil {
        Divider()
        HStack {
          Button("Reload local graph") { Task { await setup.refresh() } }
          Spacer()
          Text("No authority changes until activation").font(.caption).foregroundStyle(.secondary)
          Button("Review owner registration") { setup.prepare(wallet: walletModel.wallet) }
            .buttonStyle(TransferPrimaryButtonStyle()).disabled(setup.inspection == nil || setup.target.needsInstalledWalletSupport)
        }.padding(16)
      }
    }.frame(minWidth: 900, minHeight: 700)
      .task { await setup.refresh() }
      .onChange(of: walletModel.walletUnlocked) { _ in setup.review = nil }
      .onChange(of: setup.installedConnection) { value in
        guard let value, let resource = try? RegisteredResource(configuration: value) else { return }
        walletModel.register(resource, replacing: walletModel.resources.first { $0.id == resource.id })
        Task { await walletModel.discoverLocalResources() }
      }
      .confirmationDialog("Activate this reviewed production setup?", isPresented: $confirmingActivation, titleVisibility: .visible) {
        Button("Activate production setup") { Task { await setup.activateInstallation(repository: walletModel.repository) } }
        Button("Cancel", role: .cancel) {}
      } message: { Text("This applies the displayed owner/native admission and starts the displayed HTTPS endpoint. Your existing graph, agent rules and signing key are preserved. No member credential is issued.") }
      .sheet(item: $credentials) { resource in
        if let repository = walletModel.repository { TransferOperatorView(resource: resource, repository: repository, walletModel: walletModel) }
      }
      .sheet(isPresented: $unlocking) {
        VStack(spacing: 0) {
          HStack { Text("Castalia Wallet").font(.headline); Spacer(); Button("Return to owner setup") { unlocking = false } }.padding()
          Divider(); TransferWalletView(model: walletModel)
        }.frame(width: 720, height: 660)
      }
      .alert("Owner setup needs attention", isPresented: Binding(get: { setup.error != nil }, set: { if !$0 { setup.error = nil } })) { Button("OK") { setup.error = nil } } message: { Text(setup.error ?? "") }
  }
  private func section<Content: View>(_ title: String, @ViewBuilder content: () -> Content) -> some View {
    VStack(alignment: .leading, spacing: 14) { Text(title).font(.headline); content() }
      .padding(20).frame(maxWidth: .infinity, alignment: .leading)
      .background(Color.primary.opacity(0.035)).cornerRadius(12)
  }
  private func summary(_ plan: OwnerSetupPlan) -> some View {
    VStack(alignment: .leading, spacing: 14) {
      Text(plan.resourceName).font(.headline)
      Text("Local graph: \(plan.localEndpoint)\nWallet endpoint: \(plan.walletEndpoint)").textSelection(.enabled)
      Text("Owner Wallet: \(plan.ownerPublicKey)").font(.caption.monospaced()).textSelection(.enabled)
      Text("Owner administration: manage credentials for this graph")
      if plan.scopeMode == "global" && plan.notAfter == nil && plan.writeOperations == OwnerPermissionPreset.allOperations && plan.effectiveReads == CredentialPresetRevision.allReads {
        Text("Default owner role: all supported credential operations, entire graph, until revoked. No member grant is issued to this Wallet.")
      } else {
        Label("This retained plan has a previously selected custom server policy. It has not been expanded to the default owner role.", systemImage: "exclamationmark.triangle")
        Text("Read: " + plan.effectiveReads.joined(separator: ", "))
        Text("Write: " + plan.writeOperations.map(OwnerPermissionPreset.title).joined(separator: ", "))
        Text(plan.scopeMode == "global" ? "Scope: entire graph" : "Scope: " + plan.paths.map { $0.path.joined(separator: " → ") }.joined(separator: "; "))
        Text(plan.notAfter.map { "Maximum expiry: " + Date(timeIntervalSince1970: TimeInterval($0)).formatted() } ?? "Grant ceiling: until revoked")
      }
      Text(plan.publishHierarchy ? "Scope names may be published for requests" : "Scope names stay unpublished")
      DisclosureGroup("Verification details") { Text("Resource: \(plan.resourceID)\nSetup digest: \(plan.digest)").font(.caption.monospaced()).textSelection(.enabled) }
    }.padding(20).frame(maxWidth: .infinity, alignment: .leading).background(Color.primary.opacity(0.035)).cornerRadius(12)
  }
}
#endif
