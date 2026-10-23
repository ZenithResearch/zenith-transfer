#if os(macOS)
import SwiftUI
import ZenithKit

struct TransferWalletWorkspace: View {
  @ObservedObject var model: TransferModel
  @State private var page = "accounts"
  var body: some View {
    VStack(alignment: .leading, spacing: 0) {
      Picker("Wallet workspace", selection: $page) {
        Text("Identities & accounts").tag("accounts")
        Text("Wallet & security").tag("security")
        Text("How it fits").tag("model")
      }.pickerStyle(.segmented).padding([.horizontal, .top], 24).padding(.bottom, 12)
      switch page {
      case "security": TransferWalletView(model: model)
      case "model": TransferIdentityModelView()
      default: TransferIdentityAccountsView(model: model, showWallet: { page = "security" })
      }
    }
  }
}

private struct TransferIdentityAccountsView: View {
  @ObservedObject var model: TransferModel
  let showWallet: () -> Void
  @State private var provider = IdentityProvider.tailscale
  @State private var selected: UUID?
  @State private var editing: IdentityAccount?
  @State private var adding = false
  @State private var removing: IdentityAccount?
  @State private var error: String?
  @State private var host: PublicationSnapshot?
  @State private var checking = false
  @State private var hostError: String?
  private var accounts: [IdentityAccount] { model.identityAccounts.filter { $0.provider == provider } }
  private var current: IdentityAccount? { accounts.first { $0.id == selected } ?? accounts.first }
  var body: some View {
    VStack(alignment: .leading, spacing: 20) {
      HStack(alignment: .top) {
        VStack(alignment: .leading, spacing: 6) {
          Text("Identities & accounts").font(.largeTitle.bold())
          Text("Your public account details, separate from protected authentication and resource permissions.").foregroundStyle(.secondary)
        }
        Spacer()
        Button("Add account") { adding = true }.disabled(!model.walletUnlocked)
      }
      if model.displayPublicKey == nil {
        Label("Set up your Castalia Wallet first", systemImage: "wallet.pass").font(.headline)
        Button("Open Wallet setup", action: showWallet).buttonStyle(TransferPrimaryButtonStyle())
      } else {
        if !model.walletUnlocked {
          HStack { Label("Wallet locked · Saved account details remain readable", systemImage: "lock"); Spacer(); Button("Unlock Wallet", action: showWallet) }.font(.callout)
        }
        HStack(alignment: .top, spacing: 24) {
          VStack(spacing: 6) {
            ForEach(IdentityProvider.allCases) { item in
              Button { provider = item; selected = nil } label: {
                Label(item.title, systemImage: item.symbol).frame(maxWidth: .infinity, alignment: .leading).padding(12)
                  .background(provider == item ? Color.accentColor.opacity(0.12) : Color.clear).cornerRadius(9)
              }.buttonStyle(.plain).accessibilityAddTraits(provider == item ? .isSelected : [])
            }
          }.frame(width: 160)
          Divider()
          ScrollView {
            VStack(alignment: .leading, spacing: 18) {
              HStack { Text(provider.title).font(.title2.bold()); Spacer(); Text("Public account records").font(.caption).foregroundStyle(.secondary) }
              if accounts.count > 1 {
                Picker("Account", selection: Binding(get: { current?.id }, set: { selected = $0 })) {
                  ForEach(accounts) { Text($0.label).tag(Optional($0.id)) }
                }
              }
              if let account = current {
                GroupBox("Public identity") {
                  VStack(alignment: .leading, spacing: 12) {
                    LabeledContent("Name", value: account.label)
                    LabeledContent(provider == .nostr ? "Public key (hex)" : "Account", value: account.identifier)
                    if !account.server.isEmpty { LabeledContent(serverLabel, value: account.server) }
                  }.textSelection(.enabled).padding(8).frame(maxWidth: .infinity, alignment: .leading)
                }
                HStack {
                  Button("Edit account") { editing = account }.disabled(!model.walletUnlocked)
                  Button("Remove account…", role: .destructive) { removing = account }.disabled(!model.walletUnlocked)
                }
              } else {
                GroupBox {
                  VStack(alignment: .leading, spacing: 10) {
                    Text("No \(provider.title) account saved").font(.headline)
                    Text("Add a public identifier and server to organize this Wallet’s accounts. Authentication is a separate step.").foregroundStyle(.secondary)
                    Button("Add \(provider.title) account") { adding = true }.disabled(!model.walletUnlocked)
                  }.padding(8).frame(maxWidth: .infinity, alignment: .leading)
                }
              }
              GroupBox("Protected authentication") {
                VStack(alignment: .leading, spacing: 10) {
                  Label("Not connected", systemImage: "lock").font(.headline)
                  Text(authenticationExplanation).foregroundStyle(.secondary)
                  Text("Passwords, private keys and access tokens do not belong in these account details.").font(.caption).foregroundStyle(.secondary)
                }.padding(8).frame(maxWidth: .infinity, alignment: .leading)
              }
              if provider == .tailscale { tailscaleHost }
              else {
                GroupBox("Where this identity is used") {
                  Text(provider == .matrix ? "Matrix accounts can support chat and request notifications. Signing in and message delivery are not enabled by saving this record." : "Nostr identities can support membership requests. A provider login or signing adapter is not yet connected to this account record.")
                    .foregroundStyle(.secondary).padding(8).frame(maxWidth: .infinity, alignment: .leading)
                }
              }
              Divider()
              Text("DevGraph permissions are managed separately in Resources & requests. An account record does not grant access, establish graph ownership or enable onward delegation.").font(.callout).foregroundStyle(.secondary)
            }.frame(maxWidth: .infinity, alignment: .leading)
          }
        }
      }
    }.padding(24)
      .task { do { try model.reloadIdentityAccounts() } catch { self.error = "Saved accounts could not be loaded safely." } }
      .sheet(isPresented: $adding) { TransferIdentityEditor(model: model, provider: provider, original: nil) }
      .sheet(item: $editing) { account in TransferIdentityEditor(model: model, provider: account.provider, original: account) }
      .alert("Remove this account record?", isPresented: Binding(get: { removing != nil }, set: { if !$0 { removing = nil } })) {
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
  private var serverLabel: String { switch provider { case .matrix: return "Homeserver"; case .nostr: return "Relay"; case .tailscale: return "Tailnet" } }
  private var authenticationExplanation: String {
    switch provider {
    case .matrix: return "A Matrix session will use protected storage through a provider adapter. Saving an account does not authenticate to the homeserver."
    case .nostr: return "Nostr needs a separately protected key or connected signer. This record contains only its public key; it does not sign events."
    case .tailscale: return "Account/API authorization is separate from this Mac’s Tailscale node. No API secret is stored or requested here."
    }
  }
  private var tailscaleHost: some View {
    GroupBox("This Mac’s Tailscale service") {
      VStack(alignment: .leading, spacing: 10) {
        if let host {
          Label(host.running ? "Host connected" : "Host disconnected", systemImage: host.running ? "checkmark.circle" : "network.slash")
          Text(host.dnsName).font(.callout.monospaced()).textSelection(.enabled)
          Text("Configured HTTPS ports: " + (host.occupiedPorts.isEmpty ? "None" : host.occupiedPorts.sorted().map(String.init).joined(separator: ", "))).font(.caption)
          Text("Public Funnel ports: " + (host.publicPorts.isEmpty ? "None" : host.publicPorts.sorted().map(String.init).joined(separator: ", "))).font(.caption)
        }
        Text("Node keys and the persistent connection stay with Tailscale. This observation does not verify a saved account or authorize DevGraph access.").font(.callout).foregroundStyle(.secondary)
        Button(checking ? "Reading host status…" : "Refresh host status") {
          checking = true; hostError = nil
          Task {
            do { host = try await TailscalePublicationInspector.inspect() }
            catch { host = nil; hostError = "Tailscale status is unavailable. Open Tailscale on this Mac and try again." }
            checking = false
          }
        }.disabled(checking)
        if let hostError { Text(hostError).font(.caption).foregroundStyle(.secondary) }
        Text("To review sharing for a service, select it in Resources & requests → Sharing & network.").font(.caption).foregroundStyle(.secondary)
      }.padding(8).frame(maxWidth: .infinity, alignment: .leading)
    }
  }
}

private struct TransferIdentityEditor: View {
  @ObservedObject var model: TransferModel
  let provider: IdentityProvider
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
        GroupBox("Castalia Wallet") { modelRow("Local custody and signing", "Organizes public account records; signs only through the existing approval flow.") }
        Image(systemName: "arrow.down").foregroundStyle(.secondary)
        GroupBox("Identities & accounts") { modelRow("Matrix · Nostr · Tailscale", "Public identifier + provider/server. Account records are not authentication proofs.") }
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
