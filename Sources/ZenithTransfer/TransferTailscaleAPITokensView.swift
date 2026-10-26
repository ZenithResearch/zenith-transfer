#if os(macOS)
import AppKit
import SwiftUI
import ZenithKit

struct TransferTailscaleAPITokensView: View {
  @Environment(\.dismiss) private var dismiss
  var store = TailscaleAPITokenStore()
  @State private var profiles: [TailscaleAPITokenProfile] = []
  @State private var editing: TailscaleAPITokenProfile?
  @State private var removing: TailscaleAPITokenProfile?
  @State private var confirmRemoval = false
  @State private var name = ""
  @State private var tailnet = "-"
  @State private var token = ""
  @State private var visible = false
  @State private var problem: String?
  @State private var message: String?

  var body: some View {
    VStack(alignment: .leading, spacing: 18) {
      HStack {
        Text("Tailscale API access tokens").font(.title2.bold())
        Spacer()
        Button("Close") { clearSecret(); dismiss() }.keyboardShortcut(.cancelAction)
      }
      Text("Save API authorization for generating device enrollment keys. These are application network settings, separate from your Wallet.")
      ScrollView {
        VStack(alignment: .leading, spacing: 16) {
          if profiles.isEmpty { Text("No API tokens saved on this Mac.").foregroundStyle(.secondary) }
          ForEach(profiles) { profile in
            GroupBox {
              HStack {
                VStack(alignment: .leading, spacing: 4) {
                  Text(profile.name).font(.headline)
                  Text(profile.tailnet == "-" ? "Token’s default Tailnet" : "Tailnet: " + profile.tailnet).foregroundStyle(.secondary)
                  Label("Token saved in Keychain", systemImage: "lock.fill").font(.caption)
                }
                Spacer()
                Button("Replace") { editing = profile; name = profile.name; tailnet = profile.tailnet; clearSecret(); message = nil; problem = nil }
                Button("Remove…", role: .destructive) { removing = profile; confirmRemoval = true }
              }.padding(6)
            }
          }
          GroupBox(editing == nil ? "Add API token" : "Replace API token") {
            VStack(alignment: .leading, spacing: 10) {
              Text("Label").font(.headline)
              TextField("For example, Personal Tailnet", text: $name)
              Text("Tailnet name or ID").font(.headline)
              TextField("- uses this token’s default Tailnet", text: $tailnet)
              Text("Use - unless you need a specific Tailnet. This is not the token’s label.").font(.footnote).foregroundStyle(.secondary)
              Text("API access token").font(.headline)
              if visible { TextField("tskey-api-…", text: $token).privacySensitive() }
              else { SecureField("tskey-api-…", text: $token).privacySensitive() }
              Toggle("Show entered token", isOn: $visible)
              Text("Saved tokens remain masked and are read only when you confirm key generation. To replace one, enter the new token here.").font(.footnote).foregroundStyle(.secondary)
              HStack {
                Button(editing == nil ? "Save to Keychain" : "Replace in Keychain") { save() }
                  .buttonStyle(TransferPrimaryButtonStyle())
                  .disabled(name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || (try? TailscaleKeyCreator.validatedTailnet(tailnet)) == nil || (try? TailscaleKeyCreator.validatedAPIToken(token)) == nil)
                if editing != nil { Button("Cancel replacement") { reset() } }
              }
            }.padding(6)
          }
          Text("Tokens may carry broad Tailnet administration permissions. Saving does not validate a token with Tailscale or generate a key. Tailscale still controls permissions, expiry and revocation.").font(.footnote).foregroundStyle(.secondary)
          Text("Stored in this Mac’s non-synchronizing login Keychain. Not included in Wallet exports, recovery files or Transfer connection files. macOS may ask you to authorize Keychain access after an app update.").font(.footnote).foregroundStyle(.secondary)
          Link("Create or revoke API tokens in Tailscale", destination: URL(string: "https://login.tailscale.com/admin/settings/keys")!)
        }
      }
      if let message { Text(message).foregroundStyle(.secondary) }
      if let problem { Text(problem).foregroundStyle(.red) }
    }.textFieldStyle(.roundedBorder).padding(24).frame(width: 660, height: 740)
      .onAppear { reload() }
      .onDisappear { clearSecret() }
      .onReceive(NotificationCenter.default.publisher(for: NSApplication.didResignActiveNotification)) { _ in clearSecret() }
      .confirmationDialog("Remove this saved API token?", isPresented: $confirmRemoval, titleVisibility: .visible, presenting: removing) { profile in
        Button("Remove from this Mac", role: .destructive) {
          do {
            try store.remove(profile); if editing?.id == profile.id { reset() }
            removing = nil; reload(); message = "Saved token removed from this Mac. It has not been revoked at Tailscale."
          } catch { problem = TailscaleAPITokenStorageFailure.unavailable.localizedDescription }
        }
        Button("Cancel", role: .cancel) { removing = nil }
      } message: { profile in Text("Remove “\(profile.name)” from Transfer’s Keychain records. This does not revoke the token at Tailscale or disconnect a device.") }
  }
  private func clearSecret() { token = ""; visible = false }
  private func reset() { editing = nil; name = ""; tailnet = "-"; clearSecret() }
  private func reload() {
    do { profiles = try store.profiles(); problem = nil }
    catch { profiles = []; problem = TailscaleAPITokenStorageFailure.unavailable.localizedDescription }
  }
  private func save() {
    do {
      try store.save(name: name, tailnet: tailnet, token: token, replacing: editing)
      reset(); reload(); message = "API token saved to this Mac’s Keychain. It is ready to select in Generate auth key."
    } catch {
      clearSecret(); problem = (error as? TailscaleAPITokenStorageFailure ?? .unavailable).localizedDescription
    }
  }
}
#endif
