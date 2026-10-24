#if os(macOS)
import SwiftUI
import ZenithKit

@MainActor final class WalletAdminUpgradeModel: ObservableObject {
  let resource: LocalResource
  let target: OwnerRegistrationTarget
  @Published var inspection: OwnerSetupInspection?
  @Published var proposal: WalletAdminUpgradeProposal?
  @Published var plan: OwnerSetupPlan?
  @Published var review: OwnerInstallationReview?
  @Published var consent: ResourceOwnerConsent?
  @Published var connection: WorkAccessConfiguration?
  @Published var busy = false
  @Published var ownerRegistered = false
  @Published var proofRetained = false
  @Published var activationAttempted = false
  @Published var preparationBlocked = false
  @Published var status: String?
  @Published var error: String?
  private let installer = OwnerInstallationCoordinator()
  private let inspector = OwnerSetupInspector()
  private let store: OwnerSetupStore?
  init(resource: LocalResource) {
    self.resource=resource;target=OwnerRegistrationTarget(resource:resource)
    store=try? OwnerSetupStore(directory:OwnerInstallationCoordinator.planDirectory())
  }
  func refresh() async {
    guard !busy else { return };busy=true;defer { busy=false }
    do {
      inspection=try await inspector.inspect(resource)
      if let retained=try store?.load(resourceID:resource.id) {
        try target.check(retained);plan=retained
        try await inspectRetained(retained)
      } else { proposal=try await installer.propose(target) }
    } catch { self.error="Could not inspect the selected DevGraph’s Wallet admin upgrade. Its data and existing authority are preserved." }
  }
  private func inspectRetained(_ plan: OwnerSetupPlan) async throws {
    let value=try await installer.status(plan)
    review=value.review;activationAttempted=value.activationAttempted || value.activationRecorded
    preparationBlocked = !value.prepared && !value.phases.isEmpty
    if let review {
      proofRetained = try installer.retainedOwnerProof(plan,review:review) != nil
      if proofRetained {
        do { try await installer.inspectOwner(plan,review:review);ownerRegistered=true }
        catch { status="The original owner proof is retained. Registration is not confirmed; no new proof or registration will be sent automatically." }
      }
      if value.activationRecorded {
        guard ownerRegistered else { throw OwnerSetupError.changed }
        connection=review.connection
      }
    }
    if preparationBlocked { status="Preparation left retained files. Inspect the existing run before any continuation." }
    else if activationAttempted && connection == nil { status="Activation started without a verified completion. Preserve this run for inspection." }
    else if ownerRegistered && connection == nil { status="Wallet ownership is verified. The reviewed admin upgrade has not been confirmed active." }
  }
  func inspect() async {
    guard !busy,let plan else { return };busy=true;defer { busy=false }
    do { try await inspectRetained(plan) }
    catch { self.error="Could not verify the retained upgrade. No activation or registration was retried." }
  }
  func prepare(repository: (any WalletSession)?) async {
    guard !busy,!preparationBlocked else { return };busy=true;defer { busy=false }
    do {
      guard let repository,let store else { throw OwnerSetupError.walletLocked }
      let wallet=try await repository.state()
      guard wallet.unlocked,let key=wallet.publicKey else { throw OwnerSetupError.walletLocked }
      let current=try await inspector.inspect(resource)
      let prepared: OwnerSetupPlan
      if let plan { try target.check(plan);prepared=plan }
      else {
        guard let proposal else { throw OwnerSetupError.unavailable }
        prepared=try OwnerSetupPlan.walletAdminUpgrade(resource:resource,inspection:current,ownerPublicKey:key,
          proposal:proposal,now:UInt64(Date().timeIntervalSince1970))
        try store.save(prepared,replacing:nil);plan=prepared
      }
      guard key==prepared.ownerPublicKey,current.registrationSHA256==prepared.registrationSHA256,
        current.configurationSHA256==prepared.configurationSHA256 else { throw OwnerSetupError.changed }
      preparationBlocked=true // An uncertain preparation must be inspected first.
      review=try await installer.prepare(prepared);preparationBlocked=false
      status="Upgrade prepared. Review the graph, owner, local connection and authority changes below."
    } catch { self.error=(error as? OwnerSetupError)?.errorDescription ?? "Preparation did not complete. Inspect the retained upgrade before continuing." }
  }
  func reviewOwner(repository: (any WalletSession)?, refresh: Bool = false) async {
    guard !busy,!proofRetained,!activationAttempted else { return };busy=true;defer { busy=false }
    do {
      guard let repository,let plan,let review else { throw OwnerSetupError.unavailable }
      let wallet=try await repository.state()
      guard wallet.unlocked,wallet.publicKey==plan.ownerPublicKey else { throw OwnerSetupError.walletLocked }
      let challenge=try await installer.ownerChallenge(plan,review:review,refresh:refresh)
      consent=try await repository.prepareResourceOwner(challenge.encoded(),binding:challenge.binding,
        now:UInt64(Date().timeIntervalSince1970))
    } catch { self.error=(error as? OwnerSetupError)?.errorDescription ?? "The owner review could not be prepared. If its timer expired, explicitly refresh the owner review; no setup deadline is extended." }
  }
  func confirmOwnerAndUpgrade(repository: (any WalletSession)?) async {
    guard !busy,let consent else { return };busy=true;self.consent=nil;defer { busy=false }
    do {
      guard let repository,let plan,let review,consent.challenge.adminGrant.grantID==review.digest else { throw OwnerSetupError.changed }
      let proof=try await repository.approveResourceOwner(consent,now:UInt64(Date().timeIntervalSince1970))
      proofRetained=true
      try await installer.completeOwner(plan,review:review,proof:proof)
      ownerRegistered=true
      activationAttempted=true
      connection=try await installer.activate(plan,review:review)
      status="Wallet admin upgrade verified active for this DevGraph."
    } catch { self.error="The upgrade did not return a verified completion. The setup is retained, and the original proof may have been dispatched. Inspect its status before any continuation." }
  }
  func activateRegisteredOwner() async {
    guard !busy,ownerRegistered,!activationAttempted,let plan,let review else { return }
    busy=true;activationAttempted=true;defer { busy=false }
    do { connection=try await installer.activate(plan,review:review) }
    catch { self.error="Activation is not confirmed. Inspect the retained upgrade; no automatic retry was started." }
  }
}

struct TransferWalletAdminUpgradeView: View {
  @StateObject private var upgrade: WalletAdminUpgradeModel
  @ObservedObject var walletModel: TransferModel
  @State private var unlocking=false
  @State private var credentials: RegisteredResource?
  @State private var activatingRegistered=false
  @Environment(\.dismiss) private var dismiss
  init(resource: LocalResource,walletModel: TransferModel) {
    self.walletModel=walletModel;_upgrade=StateObject(wrappedValue:WalletAdminUpgradeModel(resource:resource))
  }
  var body: some View {
    VStack(spacing:0) {
      HStack {
        VStack(alignment:.leading,spacing:4) {
          Text("Upgrade Wallet administration").font(.title2.bold())
          Text(upgrade.resource.name + " · " + upgrade.resource.endpoint).foregroundStyle(.secondary)
        }
        Spacer()
        Button(walletModel.walletUnlocked ? "Wallet" : "Unlock Wallet") { unlocking=true }
        Button("Close") { dismiss() }
      }.padding(20)
      Divider()
      ScrollView {
        VStack(alignment:.leading,spacing:22) {
          section("Selected DevGraph") {
            Text(upgrade.resource.name).font(.headline)
            Text(upgrade.resource.endpoint).textSelection(.enabled)
            Text("Resource ID: " + upgrade.resource.id).font(.caption.monospaced()).textSelection(.enabled)
            Text("This upgrade uses this graph’s existing data. Its private API and existing agent access remain in place.").foregroundStyle(.secondary)
          }
          if let connection=upgrade.connection {
            section("Wallet administration is active") {
              Label("Owner registration and upgrade verified",systemImage:"checkmark.shield.fill").font(.headline)
              Text(connection.origin).textSelection(.enabled)
              Text("Use your Wallet to review requests and choose each credential’s permissions, scope and validity.")
              Button("Open Credentials & requests") { credentials=try? RegisteredResource(configuration:connection) }
                .buttonStyle(TransferPrimaryButtonStyle())
            }
          } else if let plan=upgrade.plan,let review=upgrade.review {
            section("Review the admin upgrade") {
              Text("Owner Wallet").font(.headline)
              Text(plan.ownerPublicKey).font(.caption.monospaced()).textSelection(.enabled)
              Text("Administrator for this graph · Until revoked")
              Text("This Wallet can review requests, issue scoped credentials and revoke access. Member Work permissions are selected separately.")
              Divider()
              Text("Wallet admin connection · This Mac only").font(.headline)
              Text(review.endpoint).textSelection(.enabled)
              Text("A local HTTPS channel for the selected graph. Its certificate is pinned in Transfer; it is not installed as system-wide trust.").foregroundStyle(.secondary)
              Text("Certificate SHA-256: " + review.certificateSHA256).font(.caption.monospaced()).textSelection(.enabled)
              Text("Native policy \(review.previousNativeVersion) → \(review.nativeVersion); preserve \(review.preservedRules) existing rules and the same signing key. No member grants or database restart.").font(.callout)
              Text("Registering the owner consumes the one-time setup authorization. Onward delegation remains disabled.").font(.callout)
              if upgrade.ownerRegistered {
                Label("Wallet ownership verified",systemImage:"checkmark.shield")
                Button("Apply registered-owner upgrade") { activatingRegistered=true }
                  .buttonStyle(TransferPrimaryButtonStyle()).disabled(upgrade.busy || upgrade.activationAttempted)
              } else {
                Button("Review owner registration and upgrade") { Task { await upgrade.reviewOwner(repository:walletModel.repository) } }
                  .buttonStyle(TransferPrimaryButtonStyle()).disabled(upgrade.busy || upgrade.proofRetained || !walletModel.walletUnlocked)
                Button("Refresh expired owner review") { Task { await upgrade.reviewOwner(repository:walletModel.repository,refresh:true) } }
                  .disabled(upgrade.busy || upgrade.proofRetained || !walletModel.walletUnlocked)
              }
              DisclosureGroup("Upgrade verification details") {
                Text("Review digest: " + review.digest).font(.caption.monospaced()).textSelection(.enabled)
                Text("Service signing key maintenance deadline: " + Date(timeIntervalSince1970:TimeInterval(review.nativeKeyDeadline)).formatted()).font(.caption)
              }
            }
          } else {
            section("Connect your owner Wallet") {
              Text("Register your Wallet as this DevGraph’s administrator, then manage credentials directly in Transfer.")
              if let proposal=upgrade.proposal {
                Text("Proposed local Wallet channel: " + proposal.walletEndpoint).textSelection(.enabled)
                Text("The exact connection and certificate will be shown before activation.").foregroundStyle(.secondary)
              }
              Button("Prepare Wallet admin upgrade") { Task { await upgrade.prepare(repository:walletModel.repository) } }
                .buttonStyle(TransferPrimaryButtonStyle()).disabled(upgrade.busy || upgrade.preparationBlocked || upgrade.inspection == nil || !walletModel.walletUnlocked)
            }
          }
          if upgrade.busy { ProgressView("Checking the Wallet admin upgrade…") }
          if let status=upgrade.status { Text(status).foregroundStyle(.secondary) }
          if upgrade.plan != nil { Button("Inspect retained upgrade status") { Task { await upgrade.inspect() } }.disabled(upgrade.busy) }
        }.padding(24).frame(maxWidth:880,alignment:.leading).frame(maxWidth:.infinity)
      }
    }.frame(minWidth:960,minHeight:720)
      .task { await upgrade.refresh() }
      .onChange(of:walletModel.walletUnlocked) { unlocked in if unlocked != true { upgrade.consent=nil } }
      .onChange(of:upgrade.connection) { value in
        guard let value,let resource=try? RegisteredResource(configuration:value) else { return }
        walletModel.register(resource,replacing:walletModel.resources.first { $0.id == resource.id })
        Task { await walletModel.discoverLocalResources() }
      }
      .sheet(item:$upgrade.consent) { consent in
        VStack(alignment:.leading,spacing:18) {
          Text("Register owner and apply this upgrade?").font(.title2.bold())
          Text(upgrade.resource.name + " · " + consent.challenge.binding.endpoint)
          Text(consent.challenge.adminGrant.holderPublicKey).font(.caption.monospaced()).textSelection(.enabled)
          Text("Administrator until revoked. This applies the exact reviewed local HTTPS channel and native policy upgrade. The setup authorization is consumed once; no member grant is issued.")
          HStack {
            Button("Cancel") { upgrade.consent=nil }
            Spacer()
            Button("Register owner and apply upgrade") { Task { await upgrade.confirmOwnerAndUpgrade(repository:walletModel.repository) } }
              .buttonStyle(TransferPrimaryButtonStyle()).disabled(!walletModel.walletUnlocked)
          }
        }.padding(24).frame(width:720)
      }
      .sheet(isPresented:$unlocking) {
        VStack(spacing:0) {
          HStack { Text("Castalia Wallet").font(.headline);Spacer();Button("Return to admin upgrade") { unlocking=false } }.padding()
          Divider();TransferWalletView(model:walletModel)
        }.frame(width:720,height:660)
      }
      .sheet(item:$credentials) { resource in
        if let repository=walletModel.repository { TransferOperatorView(resource:resource,repository:repository,walletModel:walletModel) }
      }
      .confirmationDialog("Apply the reviewed Wallet admin upgrade?",isPresented:$activatingRegistered,titleVisibility:.visible) {
        Button("Apply reviewed upgrade") { Task { await upgrade.activateRegisteredOwner() } }
        Button("Cancel",role:.cancel) {}
      }
      .alert("Wallet admin upgrade needs attention",isPresented:Binding(get:{upgrade.error != nil},set:{if !$0 {upgrade.error=nil}})) {
        Button("OK") { upgrade.error=nil }
      } message: { Text(upgrade.error ?? "") }
  }
  private func section<Content:View>(_ title:String,@ViewBuilder content:()->Content)->some View {
    VStack(alignment:.leading,spacing:14) { Text(title).font(.headline);content() }
      .padding(20).frame(maxWidth:.infinity,alignment:.leading).background(Color.primary.opacity(0.035)).cornerRadius(12)
  }
}
#endif
