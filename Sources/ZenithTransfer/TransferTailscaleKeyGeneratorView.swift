#if os(macOS)
import AppKit
import SwiftUI
import ZenithKit

/// Administrative API action, separate from enrolling this Mac or saving files.
struct TransferTailscaleKeyGeneratorView: View {
  @Environment(\.dismiss) private var dismiss
  var tokenStore = TailscaleAPITokenStore()
  @State private var profiles: [TailscaleAPITokenProfile] = []
  @State private var selectedTokenID: UUID?
  @State private var managingTokens = false
  @State private var tailnet = "-"
  @State private var keyDescription = "Zenith iPad"
  @State private var expiryDays = 1
  @State private var apiToken = ""
  @State private var review = false
  @State private var working = false
  @State private var submitted = false
  @State private var dispatched = false
  @State private var result: GeneratedTailscaleAuthKey?
  @State private var showKey = false
  @State private var message: String?
  @State private var problem: String?
  @State private var generation = 0
  @State private var operation: Task<Void, Never>?
  @State private var creator = TailscaleKeyCreator()

  var body: some View {
    VStack(alignment: .leading, spacing: 18) {
      HStack {
        Text("Generate Tailscale auth key").font(.title2.bold())
        Spacer()
        Button("Close") { clearSensitive(); dismiss() }.keyboardShortcut(.cancelAction)
      }
      ScrollView {
      VStack(alignment: .leading, spacing: 18) {
      if let result {
        Label("Auth key generated", systemImage: "checkmark.circle").font(.headline)
        LabeledContent("Key ID", value: result.id)
        LabeledContent("Enrollment expires", value: result.expires.formatted())
        if showKey {
          TextField("Generated auth key", text: .constant(result.secret)).privacySensitive()
        } else {
          SecureField("Generated auth key", text: .constant(result.secret)).privacySensitive()
        }
        HStack {
          Toggle("Show key", isOn: $showKey)
          Button("Copy key") {
            let clipboard = NSPasteboard.general
            clipboard.clearContents()
            clipboard.setString(result.secret, forType: .string)
            clipboard.setData(Data(), forType: NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType"))
            message = "Key copied. Paste it into Zenith on the receiving device, not into chat."
          }.buttonStyle(TransferPrimaryButtonStyle())
        }
        Text("This one-time key enrolls one device. Use a different key for each installation. No file is required, and Transfer does not enroll any device automatically.").foregroundStyle(.secondary)
        Text("Copy it before leaving this screen. The key is cleared when Transfer leaves the foreground; it cannot be retrieved again from Tailscale.").font(.footnote).foregroundStyle(.secondary)
      } else {
        Text("Create a new enrollment key through Tailscale’s official API, then paste it directly into Zenith on your iPad, iPhone or another Mac.")
        GroupBox("1. Authorize key creation") {
          VStack(alignment: .leading, spacing: 10) {
            Picker("API authorization", selection: $selectedTokenID) {
              Text("Paste token for this request").tag(nil as UUID?)
              ForEach(profiles) { profile in Text(profile.name).tag(Optional(profile.id)) }
            }
            if selectedTokenID == nil {
              Text("API access token").font(.headline)
              SecureField("Tailscale API access token · tskey-api-…", text: $apiToken).privacySensitive()
            } else {
              Label("Saved token · Read from Keychain when you confirm Generate", systemImage: "lock.fill").font(.callout)
            }
            Button("Manage saved API tokens…") { managingTokens = true }
            Text("Tailnet name or ID").font(.headline)
            TextField("Tailnet name or ID · - uses the API token’s default", text: $tailnet)
            Text("Use - for this token’s default Tailnet. Enter a network name or ID here, not an app or token label.").font(.footnote).foregroundStyle(.secondary)
            Text("An enrolled Mac cannot create keys by itself. Use an API access token from your Tailnet administrator. Saved tokens stay in this Mac’s Keychain; pasted tokens are used only for this request. Neither is included in Wallet backups.")
              .font(.footnote).foregroundStyle(.secondary)
            Link("Get an API access token in Tailscale", destination: URL(string: "https://login.tailscale.com/admin/settings/keys")!)
          }.padding(6)
        }
        GroupBox("2. New auth key") {
          VStack(alignment: .leading, spacing: 10) {
            Text("New key description").font(.headline)
            TextField("Description", text: $keyDescription)
            Picker("Enrollment window", selection: $expiryDays) {
              Text("1 day").tag(1); Text("7 days").tag(7); Text("30 days").tag(30); Text("90 days").tag(90)
            }
            Text("One-time use · Non-ephemeral · No tags · Device approval retained")
              .font(.callout)
            Text("Expiry limits when this key can enroll a device; it does not disconnect an already enrolled device.")
              .font(.footnote).foregroundStyle(.secondary)
          }.padding(6)
        }
        Button(working ? "Generating…" : "Review key creation") { review = true }
          .buttonStyle(TransferPrimaryButtonStyle())
          .disabled(submitted || (try? TailscaleKeyCreator.validatedTailnet(tailnet)) == nil || (selectedTokenID == nil && (try? TailscaleKeyCreator.validatedAPIToken(apiToken)) == nil) || keyDescription.isEmpty)
        if working { ProgressView("Requesting one key from Tailscale…") }
        Text("Closing or switching apps clears secrets and cancels the local request. A request already received by Tailscale may still have created a key; check the Keys page before trying again.")
          .font(.footnote).foregroundStyle(.secondary)
      }
      if let message { Text(message).foregroundStyle(.secondary) }
      if let problem { Text(problem).foregroundStyle(.red) }
      Link("Open Tailscale Keys", destination: URL(string: "https://login.tailscale.com/admin/settings/keys")!)
      }
      }
    }.textFieldStyle(.roundedBorder).padding(24).frame(width: 650, height: 760)
      .confirmationDialog("Generate one Tailscale auth key?", isPresented: $review, titleVisibility: .visible) {
        Button("Generate one-time key") { generate() }
        Button("Cancel", role: .cancel) { }
      } message: {
        Text("API authorization: \(profiles.first { $0.id == selectedTokenID }?.name ?? "Token pasted for this request")\nTailnet: \(tailnet == "-" ? "Default Tailnet associated with this API token" : tailnet)\nDescription: \(keyDescription)\nEnrollment window: \(expiryDays) day(s)\nOne-time use, non-ephemeral, no tags, device approval retained. Sends your API token only to api.tailscale.com. No device is enrolled by this action.")
      }
      .interactiveDismissDisabled(working)
      .onAppear { reloadProfiles() }
      .onChange(of: selectedTokenID) { value in
        apiToken = ""
        tailnet = profiles.first { $0.id == value }?.tailnet ?? "-"
      }
      .sheet(isPresented: $managingTokens, onDismiss: { reloadProfiles() }) { TransferTailscaleAPITokensView(store: tokenStore) }
      .onDisappear { clearSensitive() }
      .onReceive(NotificationCenter.default.publisher(for: NSApplication.didResignActiveNotification)) { _ in clearSensitive() }
  }
  private func generate() {
    guard !submitted else { return }
    let token = apiToken, target = tailnet, description = keyDescription, days = expiryDays
    let selected = profiles.first { $0.id == selectedTokenID }
    guard selectedTokenID == nil || selected != nil else { problem = TailscaleAPITokenStorageFailure.missing.localizedDescription; return }
    apiToken = ""; submitted = true; working = true; problem = nil; message = nil
    dispatched = false
    let ticket = generation
    operation = Task { @MainActor in
      do {
        let authorization = try selected.map { try tokenStore.token(for: $0) } ?? token
        guard !Task.isCancelled, generation == ticket else { return }
        dispatched = true
        let key = try await creator.generate(tailnet: target, description: description, expiryDays: days, apiToken: authorization)
        guard !Task.isCancelled, generation == ticket else { return }
        result = key; working = false
      } catch {
        guard !Task.isCancelled, generation == ticket else { return }
        working = false
        if let failure = error as? TailscaleAPITokenStorageFailure {
          problem = failure.localizedDescription; submitted = false; return
        }
        let failure = error as? TailscaleKeyCreationFailure ?? .outcomeUnknown
        problem = failure.localizedDescription
        // An uncertain POST must never be offered as an ordinary Retry.
        if failure != .outcomeUnknown { submitted = false }
      }
    }
  }
  private func reloadProfiles() {
    do {
      profiles = try tokenStore.profiles()
      if selectedTokenID == nil || !profiles.contains(where: { $0.id == selectedTokenID }) {
        selectedTokenID = profiles.first?.id
        tailnet = profiles.first?.tailnet ?? "-"
      }
    } catch { profiles = []; selectedTokenID = nil; problem = TailscaleAPITokenStorageFailure.unavailable.localizedDescription }
  }
  private func clearSensitive() {
    generation += 1; apiToken = ""; review = false; showKey = false
    if working && dispatched {
      problem = TailscaleKeyCreationFailure.outcomeUnknown.localizedDescription
    } else if working {
      submitted = false; message = "Key creation cancelled before submission. No request was sent."
    } else if result != nil {
      message = "Generated key cleared from this screen. If you did not copy it, revoke the key in Tailscale before generating a replacement."
    }
    working = false; result = nil; operation?.cancel(); operation = nil; creator.cancel()
  }
}
#endif
