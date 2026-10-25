#if os(macOS)
import AppKit
import SwiftUI
import ZenithKit

/// Administrative API action, separate from enrolling this Mac or saving files.
struct TransferTailscaleKeyGeneratorView: View {
  @Environment(\.dismiss) private var dismiss
  @State private var tailnet = "-"
  @State private var keyDescription = "Zenith iPad"
  @State private var expiryDays = 1
  @State private var apiToken = ""
  @State private var review = false
  @State private var working = false
  @State private var submitted = false
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
            TextField("Tailnet name or ID · - uses the API token’s default", text: $tailnet)
            SecureField("Tailscale API access token · tskey-api-…", text: $apiToken).privacySensitive()
            Text("An enrolled Mac cannot create keys by itself. Supply an API access token from your Tailnet administrator. It may carry broad administration permissions; Transfer uses it only for this request and does not save it or include it in Wallet backups.")
              .font(.footnote).foregroundStyle(.secondary)
            Link("Get an API access token in Tailscale", destination: URL(string: "https://login.tailscale.com/admin/settings/keys")!)
          }.padding(6)
        }
        GroupBox("2. New auth key") {
          VStack(alignment: .leading, spacing: 10) {
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
          .disabled(submitted || tailnet.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || apiToken.isEmpty || keyDescription.isEmpty)
        if working { ProgressView("Requesting one key from Tailscale…") }
        Text("Closing or switching apps clears secrets and cancels the local request. A request already received by Tailscale may still have created a key; check the Keys page before trying again.")
          .font(.footnote).foregroundStyle(.secondary)
      }
      if let message { Text(message).foregroundStyle(.secondary) }
      if let problem { Text(problem).foregroundStyle(.red) }
      Link("Open Tailscale Keys", destination: URL(string: "https://login.tailscale.com/admin/settings/keys")!)
    }.textFieldStyle(.roundedBorder).padding(24).frame(width: 650)
      .confirmationDialog("Generate one Tailscale auth key?", isPresented: $review, titleVisibility: .visible) {
        Button("Generate one-time key") { generate() }
        Button("Cancel", role: .cancel) { }
      } message: {
        Text("Tailnet: \(tailnet == "-" ? "Default Tailnet associated with this API token" : tailnet)\nDescription: \(keyDescription)\nEnrollment window: \(expiryDays) day(s)\nOne-time use, non-ephemeral, no tags, device approval retained. Sends your API token only to api.tailscale.com. No device is enrolled by this action.")
      }
      .interactiveDismissDisabled(working)
      .onDisappear { clearSensitive() }
      .onReceive(NotificationCenter.default.publisher(for: NSApplication.didResignActiveNotification)) { _ in clearSensitive() }
  }
  private func generate() {
    guard !submitted else { return }
    let token = apiToken, target = tailnet, description = keyDescription, days = expiryDays
    apiToken = ""; submitted = true; working = true; problem = nil; message = nil
    let ticket = generation
    operation = Task { @MainActor in
      do {
        let key = try await creator.generate(tailnet: target, description: description, expiryDays: days, apiToken: token)
        guard !Task.isCancelled, generation == ticket else { return }
        result = key; working = false
      } catch {
        guard !Task.isCancelled, generation == ticket else { return }
        working = false
        let failure = error as? TailscaleKeyCreationFailure ?? .outcomeUnknown
        problem = failure.localizedDescription
        // An uncertain POST must never be offered as an ordinary Retry.
        if failure != .outcomeUnknown { submitted = false }
      }
    }
  }
  private func clearSensitive() {
    generation += 1; apiToken = ""; review = false; showKey = false
    if working {
      problem = TailscaleKeyCreationFailure.outcomeUnknown.localizedDescription
    } else if result != nil {
      message = "Generated key cleared from this screen. If you did not copy it, revoke the key in Tailscale before generating a replacement."
    }
    working = false; result = nil; operation?.cancel(); operation = nil; creator.cancel()
  }
}
#endif
