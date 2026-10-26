import SwiftUI
#if os(macOS)
import AppKit
#else
import UIKit
#endif

/// Shared native Wallet home. Adapters supply observed status and navigation;
/// this component neither loads custody nor makes authenticated requests.
public struct WalletHomeContent: View {
  let publicKey: String?
  let unlocked: Bool
  let backupVerified: Bool
  let membershipActive: Bool
  let accessSummary: String
  let open: (WalletDestination) -> Void
  let lock: () -> Void
  public init(publicKey: String?, unlocked: Bool, backupVerified: Bool, membershipActive: Bool,
    accessSummary: String, open: @escaping (WalletDestination) -> Void, lock: @escaping () -> Void) {
    self.publicKey = publicKey; self.unlocked = unlocked; self.backupVerified = backupVerified
    self.membershipActive = membershipActive; self.accessSummary = accessSummary; self.open = open; self.lock = lock
  }
  public var body: some View {
    ScrollView {
      VStack(alignment: .leading, spacing: 24) {
        VStack(alignment: .leading, spacing: 8) {
          Text("Wallet").font(.largeTitle.bold())
          Label(unlocked ? "Wallet unlocked" : "Wallet locked", systemImage: unlocked ? "lock.open" : "lock")
            .foregroundStyle(.secondary)
          Text("Your backed-up identity, memberships and recovery.").foregroundStyle(.secondary)
        }
        VStack(spacing: 0) {
          ForEach(Array(WalletDestination.walletCases.enumerated()), id: \.element) { index, destination in
            if index > 0 { Divider().padding(.leading, 52) }
            Button { open(destination) } label: {
              HStack(spacing: 14) {
                Image(systemName: destination.symbol).font(.title3).foregroundStyle(.tint).frame(width: 24)
                VStack(alignment: .leading, spacing: 4) {
                  Text(destination.title).font(.headline).foregroundStyle(.primary)
                  Text(status(destination)).font(.subheadline).foregroundStyle(.secondary)
                }.frame(maxWidth: .infinity, alignment: .leading)
                Image(systemName: "chevron.right").font(.footnote.weight(.semibold)).foregroundStyle(.secondary)
              }.padding(16).contentShape(Rectangle())
            }.buttonStyle(.plain).accessibilityIdentifier("wallet." + destination.rawValue)
          }
        }.background(walletSurface, in: RoundedRectangle(cornerRadius: 16))
        DisclosureGroup("Wallet details") {
          VStack(alignment: .leading, spacing: 8) {
            Text(unlocked ? "Wallet public identity" : "Last unlocked public identity").font(.caption).foregroundStyle(.secondary)
            Text(publicKey ?? "Unlock Wallet to view its public identity.").font(.caption.monospaced()).textSelection(.enabled)
            Text("The same recovered Wallet has the same identity across apps. Each app protects its local copy separately.")
              .font(.footnote).foregroundStyle(.secondary)
          }.padding(.top, 8)
        }
        if unlocked { Button(action: lock) { Label("Lock wallet", systemImage: "lock") }.accessibilityIdentifier("wallet.lock") }
        Text("Wallet contains data covered by a Wallet backup. Connections, network settings and service administration live in the application.")
          .font(.footnote).foregroundStyle(.secondary)
      }.frame(maxWidth: 620, alignment: .leading).frame(maxWidth: .infinity).padding(24)
    }
  }
  private func status(_ destination: WalletDestination) -> String {
    switch destination {
    case .identities: return "Recovery identity and portable Wallet records"
    case .membership: return "Membership proofs · Wallet data backup"
    case .recovery: return backupVerified ? "Recovery checked" : "Check your recovery file"
    case .access: return "Reusable permissions · encrypted grant backup"
    case .security: return "Unlock method and automatic lock"
    case .about: return "Identity, connections and permissions"
    }
  }
}

public struct WalletIdentityContent: View {
  let publicKey: String?
  public init(publicKey: String?) { self.publicKey = publicKey }
  public var body: some View {
    ScrollView {
      VStack(alignment: .leading, spacing: 24) {
        Text("Wallet identity").font(.largeTitle.bold())
        Text("Included in your encrypted recovery backup").foregroundStyle(.secondary)
        Text("Castalia public identity").font(.headline)
        Text(publicKey ?? "Unlock Wallet to view its public identity.").font(.caption.monospaced()).textSelection(.enabled)
        Text("Recovering the same Wallet restores this identity. Each app protects its local copy separately.").foregroundStyle(.secondary)
        Text("Application account records and network connections are managed in Settings; they are not part of this backup.").font(.footnote).foregroundStyle(.secondary)
      }.frame(maxWidth: 620, alignment: .leading).frame(maxWidth: .infinity).padding(24)
    }
  }
}

/// Displays only proofs carried by the current Castaway export. Provider setup,
/// active-session selection and network configuration live in Settings.
public struct WalletMembershipContent: View {
  let repository: (any WalletSession)?
  let unlocked: Bool
  @State private var proofs: [PortableSections.Proof] = []
  @State private var unavailable = false
  public init(repository: (any WalletSession)?, unlocked: Bool) { self.repository = repository; self.unlocked = unlocked }
  public var body: some View {
    ScrollView {
      VStack(alignment: .leading, spacing: 24) {
        Text("Membership proofs").font(.largeTitle.bold())
        Text("Included in your encrypted Wallet data backup (.castaway).").foregroundStyle(.secondary)
        if !unlocked { Text("Unlock Wallet to read saved proofs.") }
        else if unavailable { Text("Saved proofs could not be read. No Wallet data was changed.") }
        else if proofs.isEmpty { Text("No membership proofs saved.") }
        ForEach(unlocked ? proofs : []) { proof in
          GroupBox("Membership") {
            VStack(alignment: .leading, spacing: 8) {
              Text("Issuer: " + proof.issuerId)
              Text("Membership: " + proof.membershipId)
              if let scope = proof.scopeId { Text("Scope: " + scope) }
            }.font(.caption.monospaced()).textSelection(.enabled).padding(8).frame(maxWidth: .infinity, alignment: .leading)
          }
        }
        Text("Configure a provider or activate a membership in Settings. Restoring a saved proof does not activate service access.").font(.footnote).foregroundStyle(.secondary)
      }.frame(maxWidth: 620, alignment: .leading).frame(maxWidth: .infinity).padding(24)
    }.task(id: unlocked) {
      proofs = []; unavailable = false
      guard unlocked, let repository else { return }
      let ticket = repository.lifecycleTicket()
      do {
        let saved = try await repository.portableMembershipProofs()
        try Task.checkCancellation(); try repository.checkLifecycle(ticket)
        proofs = saved
      } catch { if !Task.isCancelled { proofs = []; unavailable = unlocked } }
    }.onDisappear { proofs = [] }
  }
}

public struct WalletAboutContent: View {
  public init() {}
  public var body: some View {
    ScrollView {
      VStack(alignment: .leading, spacing: 24) {
        Text("How Wallet works").font(.largeTitle.bold())
        GroupBox("Your identity") { paragraph("Castalia protects your signing keys. Recovering the same Wallet in another app restores the same identity; each app keeps its own encrypted local copy.") }
        GroupBox("What Wallet backs up") { paragraph("The recovery file restores signing identity and derived accounts. The encrypted Castaway data file carries supported profile fields, membership proofs, saved account identities and public account descriptors. Exporting a file and testing its restore are separate from saving locally.") }
        GroupBox("Application state") { paragraph("Network connections, Tailscale device enrollment, saved server addresses, application-only account records and preferences belong to Settings. Work and service administration belong to the application. They are not included in Wallet exports.") }
        GroupBox("Access credentials") { paragraph("Some credentials are saved in the encrypted local Wallet database, but are not included in current portable exports. A complete database backup/restore flow is not yet available in this UI. Service access remains outside the Wallet home until backup coverage is implemented.") }
        GroupBox("While unlocked") { paragraph("Switching screens or apps does not itself lock Wallet. The default locks after one hour of inactivity. Choose 15 minutes, four hours, or until you lock or quit in Unlock & security. Pending signing approvals are still cancelled when their context changes.") }
      }.frame(maxWidth: 620, alignment: .leading).frame(maxWidth: .infinity).padding(24)
    }
  }
  private func paragraph(_ text: String) -> some View { Text(text).foregroundStyle(.secondary).padding(8).frame(maxWidth: .infinity, alignment: .leading) }
}

/// Revealing and copying require distinct explicit actions. No copy happens
/// during reveal, typing, focus, or AutoFill; background hides plaintext.
public struct WalletPasswordEntry: View {
  let title: String
  @Binding var text: String
  let isNew: Bool
  let submit: () -> Void
  @State private var revealed = false
  @Environment(\.scenePhase) private var scene
  public init(title: String, text: Binding<String>, isNew: Bool = false, submit: @escaping () -> Void = {}) {
    self.title = title; self._text = text; self.isNew = isNew; self.submit = submit
  }
  public var body: some View {
    VStack(alignment: .leading, spacing: 8) {
      Text(title).font(.subheadline.weight(.semibold))
      HStack(spacing: 12) {
        passwordField
        Button { revealed.toggle() } label: { Image(systemName: revealed ? "eye.slash" : "eye") }
          .buttonStyle(.plain).accessibilityLabel((revealed ? "Hide " : "Show ") + title)
        if revealed {
          Button { copy() } label: { Image(systemName: "doc.on.doc") }
            .buttonStyle(.plain).disabled(text.isEmpty).accessibilityLabel("Copy " + title)
        }
      }.padding(16).frame(minHeight: 50)
        .background(walletSurface, in: RoundedRectangle(cornerRadius: 12))
        .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color.secondary.opacity(0.3), lineWidth: 0.5))
    }.onChange(of: text.isEmpty) { empty in if empty { revealed = false } }
      .onChange(of: scene) { value in if value != .active { revealed = false } }
      .onDisappear { revealed = false }
  }
  @ViewBuilder private var passwordField: some View {
    #if os(macOS)
    if #available(macOS 14, *) { input.textContentType(isNew ? .newPassword : .password) }
    else { input }
    #else
    input.textContentType(isNew ? .newPassword : .password).textInputAutocapitalization(.never).autocorrectionDisabled()
    #endif
  }
  private var input: some View {
    Group {
      if revealed { TextField(title, text: $text) }
      else { SecureField(title, text: $text) }
    }.textFieldStyle(.plain).onSubmit(submit)
  }
  private func copy() {
    #if os(macOS)
    NSPasteboard.general.clearContents(); NSPasteboard.general.setString(text, forType: .string)
    #else
    UIPasteboard.general.setItems([[UIPasteboard.typeAutomatic: text]], options: [.localOnly: true, .expirationDate: Date().addingTimeInterval(60)])
    #endif
  }
}

private var walletSurface: Color {
  #if os(macOS)
  Color(nsColor: .controlBackgroundColor)
  #else
  Color(uiColor: .secondarySystemBackground)
  #endif
}
