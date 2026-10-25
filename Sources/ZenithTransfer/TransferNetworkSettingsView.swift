#if os(macOS)
import AppKit
import SwiftUI
import UniformTypeIdentifiers
import ZenithKit

struct TransferNetworkSettingsView: View {
  @ObservedObject var model: TransferModel
  var openResources: () -> Void
  var applicationDirectory: URL? = nil
  var automaticallyDiscover = true
  var tailscale = HostTailscaleConnection()
  @State private var folder: URL?
  @State private var files: [ConnectionFileReview] = []
  @State private var network: PrivateNetworkStatus?
  @State private var host: PublicationSnapshot?
  @State private var checking = false
  @State private var enrolling = false
  @State private var message: String?
  @State private var problem: String?
  @State private var review: NetworkSetupReview?
  @State private var creatingKey = false
  @State private var createdFile: URL?
  @State private var operation: Task<Void, Never>?

  var body: some View {
    ScrollView {
      VStack(alignment: .leading, spacing: 24) {
        Text("Network").font(.largeTitle.bold())
        Text("Choose a connection file or a service found on this Mac. Local setup does not require typing a server address.").foregroundStyle(.secondary)
        tailscaleSection
        devgraphSection
        connectionFolder
        if let message { Label(message, systemImage: "info.circle").foregroundStyle(.secondary) }
        if let problem { Label(problem, systemImage: "exclamationmark.circle").foregroundStyle(.red) }
        Text("Network settings stay on this device. Wallet approval and each service’s access permissions are reviewed separately.").font(.footnote).foregroundStyle(.secondary)
      }.frame(maxWidth: 720, alignment: .leading).frame(maxWidth: .infinity).padding(24)
    }
    .task { if automaticallyDiscover { await refresh() } }
    .onDisappear { operation?.cancel() }
    .sheet(item: $review) { item in reviewSheet(item) }
    .sheet(isPresented: $creatingKey, onDismiss: {
      guard let url = createdFile else { return }; createdFile = nil
      do { try reloadFiles(); offer(try ConnectionFileReview.read(url, as: .tailscale)) }
      catch { problem = "The connection file could not be read. Choose it again." }
    }) {
      TailscaleConnectionFileCreator(directory: folder) { url in
        createdFile = url; creatingKey = false
      }
    }
  }
  private var tailscaleSection: some View {
    GroupBox("1. Tailscale private network") {
      VStack(alignment: .leading, spacing: 12) {
        Label(network?.phase == .connected ? "This Mac is connected" : network?.phase == .awaitingApproval ? "Waiting for device approval" : "Connect this Mac to your private network", systemImage: network?.phase == .connected ? "checkmark.shield" : "network")
        if let name = network?.networkName { Text(name).font(.callout).textSelection(.enabled) }
        if network?.phase == .connected {
          Text("DevGraph and Transfer use this Mac’s existing connection. No new enrollment key is needed. Closing Transfer does not stop Tailscale.").foregroundStyle(.secondary)
        } else {
          Text("Connect using a one-time auth key from your network administrator. Use a separate key for each device; browser sign-in remains available in Tailscale.").foregroundStyle(.secondary)
        }
        ForEach(files.filter { $0.kind == .tailscale }) { file in
          HStack { Label(file.file.lastPathComponent, systemImage: "doc.badge.lock").lineLimit(2); Spacer(); Button("Review file") { offer(file) } }
        }
        HStack {
          Button("Create auth-key file…") { creatingKey = true }.buttonStyle(TransferPrimaryButtonStyle())
          Button("Choose auth-key file…") { choose(.tailscale) }
        }.disabled(enrolling)
        DisclosureGroup("How to get a Tailscale auth-key file") {
          VStack(alignment: .leading, spacing: 8) {
            Text("If someone else manages the network, ask them for a one-time, non-ephemeral Tailscale auth-key file. It is a small text file containing only the enrollment key.")
            Text("If you manage the network: open Tailscale’s Keys page, select Generate auth key, leave Reusable and Ephemeral off, and leave Tags unset for a personal device. Keep device approval enabled if your network uses it. Then choose Create auth-key file here and paste the key into the protected field. Each device needs a different one-time key.")
            Link("Open Tailscale Keys", destination: URL(string: "https://login.tailscale.com/admin/settings/keys")!)
            Text("Choose the saved file, review it, then select Connect this Mac. Your administrator may still need to approve this device. Keep the file private; an expired or already-used key must be replaced by the administrator.")
            Link("Tailscale auth-key instructions", destination: URL(string: "https://tailscale.com/docs/features/access-control/auth-keys")!)
          }.font(.callout).padding(.top, 6)
        }
        HStack {
          Button("Open Tailscale / browser sign-in") { openTailscale() }
          Link("Install Tailscale", destination: URL(string: "https://tailscale.com/download/mac")!)
          Button(checking ? "Checking…" : "Refresh status") { operation = Task { await refresh() } }.disabled(checking || enrolling)
        }
        if network?.phase == .awaitingApproval {
          Link("Open device approvals", destination: URL(string: "https://login.tailscale.com/admin/machines")!)
        }
        if let host {
          DisclosureGroup("Sharing on this Mac") {
            Text("Private HTTPS ports: " + (host.occupiedPorts.isEmpty ? "None" : host.occupiedPorts.sorted().map(String.init).joined(separator: ", ")))
            Text("Public Funnel ports: " + (host.publicPorts.isEmpty ? "None" : host.publicPorts.sorted().map(String.init).joined(separator: ", ")))
            Button("Manage service sharing", action: openResources)
          }.font(.callout)
        }
      }.padding(8).frame(maxWidth: .infinity, alignment: .leading)
    }
  }
  private var devgraphSection: some View {
    GroupBox("2. DevGraph connections") {
      VStack(alignment: .leading, spacing: 12) {
        Text("Services found on this Mac").font(.headline)
        if let notice = model.discoveryNotice { Text(notice).font(.callout).foregroundStyle(.secondary) }
        if model.localServices.isEmpty && model.localResources.isEmpty {
          Text("No local DevGraph service has been published yet. Start DevGraph and publish its local service listing, then refresh. The instructions below explain setup. You can also import a connection file from the server owner.").foregroundStyle(.secondary)
        }
        ForEach(model.localServices) { service in
          VStack(alignment: .leading, spacing: 6) {
            Text(service.title).font(.headline)
            if let config = service.connection { Text(routeLabel(config)).font(.callout).foregroundStyle(.secondary) }
            Text(model.localHealth["service:" + service.id]?.label ?? "Refresh to check availability").font(.caption).foregroundStyle(.secondary)
            if let config = service.connection {
              HStack {
                Button("Review connection") { offer(config) }
                Button(config.network == .local ? "Save for this Mac…" : "Save connection file…") { export(config) }
              }
            } else { Text("Start Wallet access setup in Resources & requests to produce a connection file.").font(.callout).foregroundStyle(.secondary) }
          }.padding(.vertical, 4)
        }
        ForEach(model.localResources.filter { resource in !model.localServices.contains { $0.resource_id == resource.id } }) { resource in
          VStack(alignment: .leading) {
            Text(resource.name).font(.headline)
            if let config = resource.connection { Text(routeLabel(config)).font(.callout).foregroundStyle(.secondary) }
            if let config = resource.connection {
              HStack { Button("Review connection") { offer(config) }; Button(config.network == .local ? "Save for this Mac…" : "Save connection file…") { export(config) } }
            } else { Text("This local instance needs Wallet access setup in Resources & requests.").font(.callout).foregroundStyle(.secondary) }
          }
        }
        ForEach(files.filter { $0.kind == .devgraph }) { file in
          HStack { Label(file.configuration?.name ?? "DevGraph connection", systemImage: "doc.text"); Spacer(); Button("Review file") { offer(file) } }
        }
        Button("Choose DevGraph connection file…") { choose(.devgraph) }
        if !model.resources.isEmpty {
          Text("Saved connections").font(.headline)
          ForEach(model.resources) { resource in Text(resource.configuration.name).font(.callout) }
        }
        Button("Open Resources & requests", action: openResources)
        DisclosureGroup("How to get a DevGraph connection file") {
          VStack(alignment: .leading, spacing: 8) {
            Text("For a new local instance, follow the DevGraph setup guide to install and configure the server. In Terminal run devgraph local resource register once, then devgraph local start. These commands use the local instance’s settings; no server URL or assistant is needed. If it is already running, register it and refresh here.")
            Text("On the Mac running DevGraph, open Transfer → Settings → Network and refresh. Under the discovered Wallet API, choose Save connection file. If only a Private API is listed, open Resources & requests and complete Wallet access setup first.")
            Text("For another Mac or iPhone, choose a Tailnet, LAN or HTTPS connection; a file labeled This Mac only points back to this Mac and cannot connect another device. Send the chosen JSON file using Files, AirDrop or another trusted transfer. Choose DevGraph connection file on the receiving device, review the server and verification settings, then save. Public connection files contain no Wallet password, credential or Tailscale enrollment key.")
            Text("Private Tailnet addresses require joining the network first. A public Funnel address can be used without joining Tailscale. Saving a server does not approve Wallet access.")
            Link("DevGraph setup guide", destination: URL(string: "https://github.com/ZenithResearch/devgraph/blob/main/docs/user/beta.md")!)
          }.font(.callout).padding(.top, 6)
        }
      }.padding(8).frame(maxWidth: .infinity, alignment: .leading)
    }
  }
  private var connectionFolder: some View {
    GroupBox("Saved connection files") {
      VStack(alignment: .leading, spacing: 10) {
        Text("Transfer checks its ConnectionFiles folder when you open Network or refresh. Files are offered for review; they are not applied automatically.").font(.callout)
        if let folder { Text(folder.path).font(.caption.monospaced()).textSelection(.enabled) }
        HStack {
          Button("Open connection files folder") {
            do { try ensureFolder(); if let folder { NSWorkspace.shared.open(folder) } }
            catch { problem = "The connection files folder could not be opened." }
          }
          Button("Refresh files and services") { operation = Task { await refresh() } }.disabled(checking || enrolling)
        }
      }.padding(8).frame(maxWidth: .infinity, alignment: .leading)
    }
  }
  private func routeLabel(_ config: WorkAccessConfiguration) -> String {
    switch config.network {
    case .local: return "This Mac only"
    case .lan: return "Local network · same Wi-Fi"
    case .tailscale: return "Private Tailnet · join Tailscale first"
    case nil: return "HTTPS connection"
    }
  }
  private func ensureFolder() throws {
    let base = try applicationDirectory ?? FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true).appendingPathComponent("ZenithTransfer")
    folder = try NetworkConnectionFiles.directory(applicationDirectory: base)
  }
  private func reloadFiles() throws { try ensureFolder(); files = try NetworkConnectionFiles.scan(folder!) }
  private func refresh() async {
    guard !checking, !enrolling else { return }; checking = true; defer { checking = false }
    problem = nil
    do { try reloadFiles() } catch { problem = "Connection files could not be read. Use Choose connection file, or open the folder and remove unsupported items." }
    do { network = try await tailscale.status() } catch { network = nil }
    host = try? await TailscalePublicationInspector.inspect()
    await model.discoverLocalResources()
  }
  private func openTailscale() {
    let app = URL(fileURLWithPath: "/Applications/Tailscale.app")
    if FileManager.default.fileExists(atPath: app.path) { NSWorkspace.shared.open(app) }
    else { problem = "Install Tailscale using the link, then return here and refresh." }
  }
  private func choose(_ kind: ConnectionFileKind) {
    let panel = NSOpenPanel(); panel.canChooseDirectories = false; panel.allowsMultipleSelection = false
    panel.allowedContentTypes = kind == .devgraph ? [.json] : [.plainText, .data]
    guard panel.runModal() == .OK, let file = panel.url else { return }
    do { offer(try ConnectionFileReview.read(file, as: kind)) }
    catch { problem = kind == .devgraph ? "Choose a public DevGraph connection JSON file from the server owner." : "Choose a text file containing only your Tailscale auth key." }
  }
  private func offer(_ file: ConnectionFileReview) {
    problem = nil; review = NetworkSetupReview(file: file, configuration: file.configuration, expected: file.configuration.flatMap { config in model.resources.first { $0.id == config.origin } })
  }
  private func offer(_ config: WorkAccessConfiguration) {
    problem = nil; review = NetworkSetupReview(file: nil, configuration: config, expected: model.resources.first { $0.id == config.origin })
  }
  private func export(_ config: WorkAccessConfiguration) {
    let panel = NSSavePanel(); panel.allowedContentTypes = [.json]; panel.nameFieldStringValue = config.network == .local ? "DevGraph-this-Mac.json" : "DevGraph-connection.json"; panel.directoryURL = folder
    guard panel.runModal() == .OK, let url = panel.url else { return }
    do { try NetworkConnectionFiles.saveConfiguration(config, to: url); try reloadFiles(); message = "Public connection file saved. Share it with the person connecting to this server." }
    catch { problem = "Could not save the file. Choose a new filename; existing files are preserved." }
  }
  private func reviewSheet(_ item: NetworkSetupReview) -> some View {
    VStack(alignment: .leading, spacing: 16) {
      HStack { Text(item.configuration == nil ? "Connect this Mac to Tailscale" : "Review DevGraph connection").font(.title2.bold()); Spacer(); Button("Close") { cancelReview() }.keyboardShortcut(.cancelAction) }
      if let config = item.configuration {
        Text(config.name).font(.headline)
        LabeledContent("Server", value: config.origin)
        LabeledContent("Network", value: config.network?.rawValue ?? "HTTPS")
        LabeledContent("Issuer", value: config.issuer)
        Text("Verification key: " + config.authority.public_key).font(.caption.monospaced()).textSelection(.enabled)
        if let pin = config.tls_certificate_sha256 { Text("Certificate SHA-256: " + pin).font(.caption.monospaced()).textSelection(.enabled) }
        Text(item.expected == nil ? "Save these public server settings on this Mac. Access permissions remain with the server and Wallet." : "This server is already saved. Review any changed verification settings before replacing them.").foregroundStyle(.secondary)
        Button("Save connection") {
          do {
            let current = try item.file?.selectedConfiguration() ?? config
            let value = try RegisteredResource(configuration: current)
            model.error = nil; model.register(value, replacing: item.expected)
            let failure = model.error; model.error = nil
            if failure == nil { review = nil; message = "Connection saved. Open Resources & requests to use it." }
            else { problem = failure }
          } catch { problem = "The connection file changed or is invalid. Choose it again." }
        }.buttonStyle(TransferPrimaryButtonStyle())
      } else {
        if let file = item.file { Text("File: " + file.file.lastPathComponent).font(.callout).textSelection(.enabled) }
        Text("Use the selected enrollment file to add this Mac to the network that issued it. The key is not displayed or included in Wallet backups.")
        if network?.phase == .connected { Text("This Mac is already connected. Manage network changes in Tailscale.").foregroundStyle(.secondary) }
        if let file = item.file {
          Button(enrolling ? "Connecting…" : "Connect this Mac") {
            enrolling = true; problem = nil
            operation = Task {
              defer { enrolling = false }
              do {
                let result = try await tailscale.connect(using: file)
                guard !Task.isCancelled else { return }
                network = result; review = nil
                message = result.phase == .connected ? "Tailscale connected. Choose your DevGraph connection next." : "Device added; ask your network administrator to approve it, then refresh."
              } catch {
                if !Task.isCancelled {
                  if let failure = error as? HostTailscaleFailure { problem = failure.errorDescription }
                  else if let failure = error as? ConnectionFileFailure { problem = failure.errorDescription }
                  else if let failure = error as? PrivateNetworkError { problem = failure.errorDescription }
                  else { problem = "Could not connect using this file. Reopen Tailscale, refresh, and check the file with your administrator." }
                }
              }
            }
          }.buttonStyle(TransferPrimaryButtonStyle()).disabled(enrolling || network?.phase == .connected)
        }
        Text("Closing stops this attempt. If Tailscale has already added the device, manage its enrollment in Tailscale.").font(.footnote).foregroundStyle(.secondary)
      }
      if let problem { Text(problem).foregroundStyle(.red) }
    }.padding(24).frame(width: 620).onExitCommand { cancelReview() }
  }
  private func cancelReview() { operation?.cancel(); review = nil }
}
private struct NetworkSetupReview: Identifiable {
  let id = UUID()
  let file: ConnectionFileReview?
  let configuration: WorkAccessConfiguration?
  let expected: RegisteredResource?
}
private struct TailscaleConnectionFileCreator: View {
  let directory: URL?
  let saved: (URL) -> Void
  @Environment(\.dismiss) private var dismiss
  @State private var key = ""
  @State private var error: String?
  var body: some View {
    VStack(alignment: .leading, spacing: 16) {
      HStack { Text("Create Tailscale auth-key file").font(.title2.bold()); Spacer(); Button("Close") { key = ""; dismiss() }.keyboardShortcut(.cancelAction) }
      Text("Paste a one-time, non-ephemeral auth key from your Tailscale administrator. Use a separate key for every device. This saves a private text file; it does not connect until you review and choose Connect this Mac.")
      SecureField("Tailscale auth key", text: $key).privacySensitive()
      Button("Save connection file…") {
        let panel = NSSavePanel(); panel.directoryURL = directory; panel.nameFieldStringValue = "Tailscale connection.tailscale-key"
        guard panel.runModal() == .OK, let file = panel.url else { return }
        do { try NetworkConnectionFiles.saveEnrollmentKey(key, to: file); key = ""; saved(file) }
        catch { self.error = "Use a valid Tailscale auth key and a new filename. Existing files are preserved." }
      }.buttonStyle(TransferPrimaryButtonStyle()).disabled(key.isEmpty)
      if let error { Text(error).foregroundStyle(.red) }
      Text("Keep this file private. Source files are not deleted automatically. A one-time key cannot enroll another device after use.").font(.footnote).foregroundStyle(.secondary)
    }.padding(24).frame(width: 600).onDisappear { key = "" }
      .onReceive(NotificationCenter.default.publisher(for: NSApplication.didResignActiveNotification)) { _ in key = "" }
  }
}
#endif
