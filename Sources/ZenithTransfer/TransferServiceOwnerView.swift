#if os(macOS)
import SwiftUI
import ZenithKit

@MainActor final class ServiceOwnerModel: ObservableObject {
  let service: LocalService
  private let coordinator: ServiceOwnerCoordinator?
  @Published var preparation: ServiceOwnerPreparation?
  @Published var consent: ResourceOwnerConsent?
  @Published var ownerRegistered = false
  @Published var activationAttempted = false
  @Published var active = false
  @Published var proofRetained = false
  @Published var blocked = false
  @Published var busy: String?
  @Published var error: String?
  init(service: LocalService) {
    self.service = service; coordinator = try? ServiceOwnerCoordinator(service: service)
  }
  func inspect() async {
    guard busy == nil else { return }; busy = "Checking this service…"; defer { busy = nil }
    do {
      guard let coordinator else { throw OwnerSetupError.invalid }
      let state = try await coordinator.inspect()
      preparation = state.preparation; ownerRegistered = state.ownerRegistered
      activationAttempted = state.activationAttempted; active = state.active; blocked = state.blocked
      proofRetained = try state.preparation.map { try coordinator.retainedProof($0) } ?? false
    } catch { self.error = "Could not verify this service’s local setup. Its address and existing setup files have been preserved. Check that the Wallet service is running, then check setup status." }
  }
  func review(repository: (any WalletSession)?, refresh: Bool = false) async {
    guard busy == nil, !blocked, !proofRetained, !activationAttempted else { return }
    busy = "Preparing your owner registration…"; defer { busy = nil }
    do {
      guard let coordinator, let repository else { throw OwnerSetupError.walletLocked }
      let wallet = try await repository.state()
      guard wallet.unlocked, let key = wallet.publicKey else { throw OwnerSetupError.walletLocked }
      if preparation == nil {
        blocked = true // An interrupted preparation is inspected, never recreated.
        preparation = try await coordinator.prepare(ownerPublicKey: key); blocked = false
      }
      guard let preparation, preparation.plan.ownerPublicKey == key else { throw OwnerSetupError.changed }
      let challenge = try await coordinator.challenge(preparation, refresh: refresh)
      consent = try await repository.prepareResourceOwner(challenge.encoded(), binding: preparation.binding,
        now: UInt64(Date().timeIntervalSince1970))
    } catch {
      self.error = (error as? OwnerSetupError)?.errorDescription ?? "The owner review did not finish. Check setup status before continuing. No registration was submitted."
    }
  }
  func confirm(repository: (any WalletSession)?) async {
    guard busy == nil, let consent else { return }; self.consent = nil
    busy = "Registering your Wallet…"; defer { busy = nil }
    do {
      guard let coordinator, let preparation, let repository,
        consent.challenge.binding == preparation.binding,
        consent.challenge.adminGrant.grantID == preparation.review.digest else { throw OwnerSetupError.changed }
      let proof = try await repository.approveResourceOwner(consent, now: UInt64(Date().timeIntervalSince1970))
      proofRetained = true
      try await coordinator.completeOwner(preparation, proof: proof)
      ownerRegistered = true; activationAttempted = true; busy = "Enabling credential management…"
      _ = try await coordinator.activate(preparation); active = true
    } catch {
      self.error = "Configuration is not yet confirmed. Your original registration is retained. Choose Check setup status to inspect it; don’t start a second registration."
    }
  }
  func finishRegisteredOwner() async {
    guard busy == nil, ownerRegistered, !activationAttempted, let preparation, let coordinator else { return }
    busy = "Enabling credential management…"; activationAttempted = true; defer { busy = nil }
    do { _ = try await coordinator.activate(preparation); active = true }
    catch { self.error = "Activation is not confirmed. Check the retained setup status before continuing; it has not been retried." }
  }
}

struct TransferServiceOwnerView: View {
  @StateObject private var setup: ServiceOwnerModel
  @ObservedObject var walletModel: TransferModel
  @Environment(\.dismiss) private var dismiss
  @State private var unlocking = false
  @State private var credentials: RegisteredResource?
  @State private var finishConfirmation = false
  init(service: LocalService, walletModel: TransferModel) {
    self.walletModel = walletModel; _setup = StateObject(wrappedValue: ServiceOwnerModel(service: service))
  }
  private var unlocked: Bool { walletModel.walletUnlocked }
  var body: some View {
    VStack(spacing: 0) {
      HStack(alignment: .top) {
        VStack(alignment: .leading, spacing: 5) {
          Text(setup.active ? "DevGraph is ready to manage" : "Set up owner Wallet").font(.title2.bold())
          Text(setup.service.name).foregroundStyle(.secondary)
        }
        Spacer()
        Button("Close") { dismiss() }.disabled(setup.busy != nil)
      }.padding(24)
      Divider()
      ScrollView {
        VStack(alignment: .leading, spacing: 24) {
          Label(setup.service.endpoint, systemImage: "desktopcomputer").font(.callout.monospaced()).textSelection(.enabled)
          if setup.active {
            Label("Owner registered", systemImage: "checkmark.shield.fill").font(.title2.bold()).foregroundStyle(Color.accentColor)
            Text("You can now review requests and create credentials for this DevGraph directly in Transfer.")
            Text("Choose each recipient’s permissions, preset, resource paths and duration in the credential editor.").foregroundStyle(.secondary)
            Button("Open Credentials & requests") { openCredentials() }.buttonStyle(TransferPrimaryButtonStyle())
          } else {
            Text("Connect your Wallet once to manage this graph’s access requests and credentials.").font(.title3)
            step(1, "Your Wallet", complete: unlocked || setup.ownerRegistered) {
              if unlocked, let key = walletModel.wallet?.publicKey {
                Label("Wallet unlocked", systemImage: "lock.open").foregroundStyle(Color.accentColor)
                Text(key).font(.caption.monospaced()).textSelection(.enabled)
              } else {
                Text("Unlock the Wallet you want to register as this graph’s owner.").foregroundStyle(.secondary)
                Button(walletModel.repository == nil ? "Set up Wallet" : "Unlock Wallet") { unlocking = true }
                  .buttonStyle(TransferPrimaryButtonStyle())
              }
            }
            step(2, "Register as this graph’s administrator", complete: setup.ownerRegistered) {
              Text("Review requests, issue scoped credentials, and revoke access. Administrator access remains until revoked.")
              Text("You won’t need to choose permissions for yourself. Each recipient’s credential is configured separately.").foregroundStyle(.secondary)
              if setup.ownerRegistered {
                Label("Your signed owner registration is verified", systemImage: "checkmark.shield")
                if !setup.activationAttempted {
                  Button("Finish configuration") { finishConfirmation = true }.buttonStyle(TransferPrimaryButtonStyle())
                }
              } else if setup.proofRetained || setup.blocked || setup.activationAttempted {
                Label("Setup needs a status check", systemImage: "info.circle")
                Text("A previous step was retained. Check its outcome before continuing.").font(.callout).foregroundStyle(.secondary)
              } else {
                Button(setup.preparation == nil ? "Review owner registration" : "Continue owner review") {
                  Task { await setup.review(repository: walletModel.repository) }
                }.buttonStyle(TransferPrimaryButtonStyle()).disabled(!unlocked || setup.busy != nil)
                if setup.preparation != nil {
                  Button("Refresh expired review") { Task { await setup.review(repository: walletModel.repository, refresh: true) } }
                    .disabled(!unlocked || setup.busy != nil)
                }
              }
            }
            step(3, "Manage credentials in Transfer", complete: false) {
              Text("After registration, open this graph’s request inbox and choose exactly what each Wallet can access.").foregroundStyle(.secondary)
            }
          }
          if let busy = setup.busy { ProgressView(busy) }
          DisclosureGroup("Connection and setup details") {
            VStack(alignment: .leading, spacing: 10) {
              Text("This setup uses the selected, running service. Its address, issuer and certificate stay the same.")
              Text("Service ID: " + setup.service.id)
              Text("Graph ID: " + setup.service.resource_id)
              if let pin = setup.service.connection?.tls_certificate_sha256 { Text("Certificate SHA-256: " + pin) }
              Text("The certificate is pinned to this Transfer connection. No system-wide trust is installed.")
              Text("No member Work grant is issued. Onward delegation is disabled. The private API and existing graph data are preserved.")
              if let review = setup.preparation?.review {
                Text("Native policy \(review.previousNativeVersion) → \(review.nativeVersion), preserving \(review.preservedRules) existing rules and the same signing key.")
                Text("Review digest: " + review.digest)
              }
            }.font(.caption).foregroundStyle(.secondary).textSelection(.enabled).padding(.top, 8)
          }
          Button("Check setup status") { Task { await setup.inspect() } }.disabled(setup.busy != nil)
        }.padding(24).frame(maxWidth: 720, alignment: .leading).frame(maxWidth: .infinity)
      }
    }.frame(minWidth: 820, minHeight: 700)
      .task { await setup.inspect() }
      .onChange(of: walletModel.walletUnlocked) { ready in
        if ready == true { unlocking = false } else { setup.consent = nil }
      }
      .onChange(of: setup.active) { active in
        guard active, let configuration = setup.service.connection,
          let resource = try? RegisteredResource(configuration: configuration) else { return }
        walletModel.register(resource, replacing: walletModel.resources.first { $0.id == resource.id })
        Task { await walletModel.discoverLocalResources() }
      }
      .sheet(isPresented: $unlocking) {
        VStack(spacing: 0) {
          HStack { Text("Your owner Wallet").font(.headline); Spacer(); Button("Back to setup") { unlocking = false } }.padding()
          Divider(); TransferWalletView(model: walletModel)
        }.frame(width: 720, height: 660)
      }
      .sheet(item: $setup.consent) { consent in
        VStack(alignment: .leading, spacing: 18) {
          Text("Register this Wallet as owner?").font(.title2.bold())
          Text(setup.service.name).font(.headline)
          Text(setup.service.endpoint).textSelection(.enabled)
          Text("Administrator · Until revoked").font(.headline)
          Text("This Wallet can review requests, issue scoped credentials and revoke access for this graph.")
          Text(consent.challenge.adminGrant.holderPublicKey).font(.caption.monospaced()).textSelection(.enabled)
          Text("Your Wallet signs this registration. Transfer then enables administration on this same service. No member Work grant is created; onward delegation is disabled.").foregroundStyle(.secondary)
          Text("Review expires " + Date(timeIntervalSince1970: TimeInterval(consent.challenge.expiresAt)).formatted(date: .omitted, time: .standard)).font(.caption).foregroundStyle(.secondary)
          HStack {
            Button("Back") { setup.consent = nil }
            Spacer()
            Button("Register owner & finish setup") { Task { await setup.confirm(repository: walletModel.repository) } }
              .buttonStyle(TransferPrimaryButtonStyle()).disabled(!unlocked)
          }
        }.padding(24).frame(width: 680)
      }
      .sheet(item: $credentials) { resource in
        if let repository = walletModel.repository { TransferOperatorView(resource: resource, repository: repository, walletModel: walletModel) }
      }
      .confirmationDialog("Finish this owner’s reviewed configuration?", isPresented: $finishConfirmation, titleVisibility: .visible) {
        Button("Finish configuration") { Task { await setup.finishRegisteredOwner() } }
        Button("Cancel", role: .cancel) {}
      }
      .alert("Owner setup needs attention", isPresented: Binding(get: { setup.error != nil }, set: { if !$0 { setup.error = nil } })) {
        Button("OK") { setup.error = nil }
      } message: { Text(setup.error ?? "") }
  }
  private func openCredentials() {
    guard let configuration = setup.service.connection else { return }
    credentials = try? RegisteredResource(configuration: configuration)
  }
  private func step<Content: View>(_ number: Int, _ title: String, complete: Bool, @ViewBuilder content: () -> Content) -> some View {
    HStack(alignment: .top, spacing: 14) {
      Image(systemName: complete ? "checkmark.circle.fill" : "\(number).circle")
        .font(.title2).foregroundStyle(complete ? Color.accentColor : .secondary)
      VStack(alignment: .leading, spacing: 12) { Text(title).font(.headline); content() }
        .frame(maxWidth: .infinity, alignment: .leading)
    }.padding(20).frame(maxWidth: .infinity, alignment: .leading)
      .background(Color.primary.opacity(0.035)).cornerRadius(12)
  }
}
#endif
