#if os(macOS)
import SwiftUI
import ZenithKit

struct TransferWalletWorkspace: View {
  @ObservedObject var model: TransferModel
  var openAccess: () -> Void = {}
  @State private var path: [WalletDestination] = []
  var body: some View {
    NavigationStack(path: $path) {
      Group {
        if model.wallet?.configured != true || (model.walletUnlocked && model.wallet?.backupVerified != true) {
          TransferWalletView(model: model, section: model.walletUnlocked ? .recovery : .setup)
        } else {
          WalletHomeContent(publicKey: model.displayPublicKey, unlocked: model.walletUnlocked,
            backupVerified: model.wallet?.backupVerified == true, membershipActive: model.wallet?.membershipActive == true,
            accessSummary: "Review access for your registered services", open: { destination in
              path.append(destination)
            }, lock: model.lock)
        }
      }.navigationDestination(for: WalletDestination.self) { destination in
        switch destination {
        case .identities: PortableWalletIdentitiesView(repository: model.repository, unlocked: model.walletUnlocked, legacy: model.identityAccounts, changed: { Task { await model.refresh() } })
        case .membership: WalletMembershipContent(repository: model.repository, unlocked: model.walletUnlocked)
        case .recovery: TransferRecoveryView(model: model)
        case .security: TransferWalletView(model: model, section: .security)
        case .access: ScrollView { WalletGrantsView(repository:model.repository,unlocked:model.walletUnlocked) }
        case .about: ScrollView { VStack { WalletAboutContent(); NavigationLink("How accounts and this Mac fit together") { TransferIdentityModelView() }.padding() } }
        }
      }
    }
  }
}

struct TransferSettingsView: View {
  @ObservedObject var model: TransferModel
  var openResources: () -> Void
  @State private var unlocking = false
  var body: some View {
    NavigationStack {
      List {
        Section("Application settings") {
          NavigationLink("Network") { TransferNetworkSettingsView(model: model, openResources: openResources) }
          NavigationLink("Application accounts") { TransferIdentityAccountsView(model: model, showWallet: { unlocking = true }) }
          NavigationLink("Membership provider") { TransferMembershipView(model: model) }
          NavigationLink("Unlock & security") { TransferWalletView(model: model, section: .security) }
          NavigationLink("How Wallet and application storage differ") { WalletAboutContent() }
          NavigationLink("Accounts and services") { TransferIdentityModelView() }
        }
      }.navigationTitle("Settings")
    }.sheet(isPresented: $unlocking) { TransferWalletSheet(model: model) }
  }
}

struct TransferIdentityAccountsView: View {
  @ObservedObject var model: TransferModel
  let showWallet: () -> Void
  @State private var editing: IdentityAccount?
  @State private var adding = false
  @State private var removing: IdentityAccount?
  @State private var error: String?
  private var accounts: [IdentityAccount] { model.identityAccounts.filter { $0.provider == .tailscale } }
  var body: some View {
    ScrollView {
      VStack(alignment: .leading, spacing: 24) {
        Text("Application accounts").font(.largeTitle.bold())
        Text("Tailscale records are application settings and are not included in Wallet backups. Matrix, Nostr, GitHub and X identities are managed in Wallet.").foregroundStyle(.secondary)
        NavigationLink("Open Wallet identities") {
          PortableWalletIdentitiesView(repository: model.repository, unlocked: model.walletUnlocked,
            legacy: model.identityAccounts, changed: { Task { await model.refresh() } })
        }
        if !model.walletUnlocked {
          HStack {
            Label("Unlock Wallet to manage identities or change Tailscale records", systemImage: "lock")
            Spacer(); Button("Unlock Wallet", action: showWallet)
          }.font(.callout)
        }
        GroupBox("Tailscale · Application settings") {
          VStack(alignment: .leading, spacing: 16) {
            if accounts.isEmpty { Text("No Tailscale account saved").foregroundStyle(.secondary) }
            ForEach(accounts) { account in
              VStack(alignment: .leading, spacing: 8) {
                Text(account.label).font(.headline)
                Text(account.identifier).textSelection(.enabled)
                Text(account.server).font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
                HStack {
                  Button("Edit account") { editing = account }
                  Button("Remove account…", role: .destructive) { removing = account }
                }.disabled(!model.walletUnlocked)
              }
            }
            Button("Add Tailscale account") { adding = true }.disabled(!model.walletUnlocked)
            Text("Public details only. Saving does not connect this Mac to Tailscale or store an API secret. Node keys and enrollment stay with Tailscale.").font(.footnote).foregroundStyle(.secondary)
          }.padding(8).frame(maxWidth: .infinity, alignment: .leading)
        }
        LegacyWalletIdentityRecordsView(records: model.identityAccounts)
        Text("DevGraph permissions are managed separately in Resources & requests. An account record does not grant access or establish graph ownership.").font(.callout).foregroundStyle(.secondary)
      }.frame(maxWidth: 740, alignment: .leading).frame(maxWidth: .infinity).padding(24)
    }
      .task { do { try model.reloadIdentityAccounts() } catch { self.error = "Saved accounts could not be loaded safely." } }
      .sheet(isPresented: $adding) { TransferIdentityEditor(model: model, original: nil) }
      .sheet(item: $editing) { account in TransferIdentityEditor(model: model, original: account) }
      .alert("Remove this Tailscale record?", isPresented: Binding(get: { removing != nil }, set: { if !$0 { removing = nil } })) {
        Button("Cancel", role: .cancel) { removing = nil }
        Button("Remove account", role: .destructive) {
          do { try model.saveIdentityAccount(nil, replacing: removing); removing = nil }
          catch { self.error = error.localizedDescription }
        }
      } message: { Text("This removes only the local public record. It does not sign out, revoke credentials or change the host’s network connection.") }
      .alert("Account needs attention", isPresented: Binding(get: { error != nil }, set: { if !$0 { error = nil } })) {
        Button("OK") { error = nil }
      } message: { Text(error ?? "") }
  }
}

private struct TransferIdentityEditor: View {
  @ObservedObject var model: TransferModel
  private let provider = IdentityProvider.tailscale
  let original: IdentityAccount?
  @Environment(\.dismiss) private var dismiss
  @State private var label = ""
  @State private var identifier = ""
  @State private var server = ""
  @State private var owner: String?
  @State private var error: String?
  var body: some View {
    VStack(alignment: .leading, spacing: 18) {
      Text(original == nil ? "Add \(provider.title) account" : "Edit \(provider.title) account").font(.title2.bold())
      Text("Public details only. Saving does not authenticate this account.").foregroundStyle(.secondary)
      Form {
        TextField("Display name", text: $label)
        TextField(provider == .matrix ? "Matrix ID (@name:server)" : provider == .nostr ? "Public key (64 lowercase hex characters)" : "Account name", text: $identifier)
        TextField(provider == .matrix ? "Homeserver (https://…)" : provider == .nostr ? "Optional relay (wss://…)" : "Tailnet DNS name (name.ts.net)", text: $server)
      }
      if !model.walletUnlocked { Label("Unlock Wallet to save changes", systemImage: "lock") }
      if let error { Text(error).font(.callout).foregroundStyle(.red) }
      HStack {
        Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
        Spacer()
        Button("Save account") {
          do {
            guard let owner, owner == model.wallet?.publicKey else { throw WalletFailure.locked }
            let account = try IdentityAccount(id: original?.id ?? UUID(), walletPublicKey: owner, provider: provider, label: label, identifier: identifier, server: server)
            try model.saveIdentityAccount(account, replacing: original); dismiss()
          } catch { self.error = (error as? IdentityAccountError)?.errorDescription ?? "Unlock the same Wallet and try again. Existing accounts were preserved." }
        }.buttonStyle(TransferPrimaryButtonStyle()).disabled(!model.walletUnlocked || label.isEmpty || identifier.isEmpty)
      }
    }.padding(24).frame(width: 580)
      .onAppear { owner = model.wallet?.publicKey; label = original?.label ?? ""; identifier = original?.identifier ?? ""; server = original?.server ?? "" }
  }
}

private struct TransferIdentityModelView: View {
  var body: some View {
    ScrollView {
      VStack(alignment: .leading, spacing: 20) {
        Text("How it fits").font(.largeTitle.bold())
        GroupBox("Castalia Wallet") { modelRow("Local custody and signing", "Contains backed-up identity and Wallet data; signs only through the existing approval flow.") }
        Image(systemName: "arrow.down").foregroundStyle(.secondary)
        GroupBox("Wallet identities & accounts") { modelRow("Matrix · Nostr · GitHub · X", "Portable public descriptors are edited in Wallet and included in Castaway backups. Legacy application records are read-only; Tailscale stays in application settings.") }
        GroupBox("Protected authentication — provider adapters") { modelRow("Sessions, signing connections, scoped API authorization", "Future adapters keep secrets in protected storage. They do not place tokens or private keys in public account records.") }
        Divider()
        GroupBox("Resource permissions") { modelRow("Wallet → DevGraph grant → allowed operations", "Each graph verifies its own owner and credential grants, including their selected Arena/path scope.") }
        GroupBox("Host networking") { modelRow("Transfer → owner-authorized host adapter → Serve / Funnel", "The persistent Tailscale node owns its node keys. Publication activation remains a separate implementation; closing Transfer does not stop Tailscale.") }
      }.padding(24).frame(maxWidth: 740, alignment: .leading)
    }.frame(maxWidth: .infinity, alignment: .leading)
  }
  private func modelRow(_ title: String, _ detail: String) -> some View {
    VStack(alignment: .leading, spacing: 8) { Text(title).font(.headline); Text(detail).foregroundStyle(.secondary) }.padding(8).frame(maxWidth: .infinity, alignment: .leading)
  }
}
#endif
