#if os(macOS)
import AppKit
import SwiftUI
import ZenithKit

struct TransferRecoveryView: View {
  @ObservedObject var model: TransferModel
  var body: some View {
    VStack(spacing: 0) {
      TransferWalletView(model: model, section: .recovery)
      Divider()
      NavigationLink("Import or save a data file") { TransferDataFileView(model: model) }.padding(20)
    }
  }
}

struct TransferDataFileView: View {
  @ObservedObject var model: TransferModel
  @State private var file: Data?
  @State private var fileName: String?
  @State private var password = ""
  @State private var exportPassword = ""
  @State private var preview: RestorePreview?
  @State private var notice: String?
  var body: some View {
    ScrollView {
      VStack(alignment: .leading, spacing: 24) {
        Text("Wallet data").font(.largeTitle.bold())
        Text("A data file contains supported profile fields, membership proofs and derived crypto account descriptors. Local application account records and network settings are not included. It cannot restore your signing identity or connect service access.").foregroundStyle(.secondary)
        if let preview {
          Text("Review import").font(.title2.bold())
          Text(preview.publicKey).font(.caption.monospaced()).textSelection(.enabled)
          if let identities = preview.walletIdentities { WalletIdentityReviewRows(section: identities) }
          Text("Your active membership stays unchanged. Nothing will be published.").foregroundStyle(.secondary)
          Button("Import data") { model.perform({ try await $0.commit(preview) }) { _ in self.preview = nil; file = nil; notice = "Data saved to your wallet." } }
            .buttonStyle(TransferPrimaryButtonStyle()).disabled(!model.walletUnlocked || model.busy)
          Button("Cancel") { self.preview = nil; model.repository?.invalidatePendingWork(); Task { await model.repository?.cancel() } }
        } else {
          Text("Import").font(.headline)
          Button(file == nil ? "Choose data file…" : "Choose another data file…") {
            let panel = NSOpenPanel(); panel.canChooseDirectories = false
            guard panel.runModal() == .OK, let url = panel.url else { return }
            do { file = try EncryptedImportFile.read(url); fileName = url.lastPathComponent; password = "" }
            catch { model.error = "Choose a supported encrypted data file." }
          }
          if let file {
            Text(fileName ?? "Encrypted data file").font(.callout)
            TransferPasswordField(title: "Data file password", text: $password)
            Button("Review data") {
              let secret = password; password = ""
              model.perform({ try await $0.prepareData(file: file, password: secret) }) { preview = $0 }
            }.buttonStyle(TransferPrimaryButtonStyle()).disabled(password.isEmpty || !model.walletUnlocked || model.busy)
          }
          Divider()
          Text("Export").font(.headline)
          TransferPasswordField(title: "New data file password", text: $exportPassword)
          Button("Save data file…") {
            let panel = NSSavePanel(); panel.nameFieldStringValue = "Castalia.castaway"
            guard panel.runModal() == .OK, let url = panel.url else { return }
            let secret = exportPassword; exportPassword = ""
            model.perform({ try await $0.exportData(password: secret) }) { data in
              do { try data.write(to: url, options: .atomic); try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path); notice = "Encrypted data file saved." }
              catch { model.error = "Could not save the encrypted data file." }
            }
          }.buttonStyle(TransferPrimaryButtonStyle()).disabled(!WalletPasswordRules.permitsLocal(exportPassword) || !model.walletUnlocked || model.busy)
        }
        if !model.walletUnlocked { Text("Unlock the same Wallet before importing or exporting.").foregroundStyle(.secondary) }
        if let notice { Text(notice).foregroundStyle(.secondary) }
      }.frame(maxWidth: 560, alignment: .leading).frame(maxWidth: .infinity).padding(24)
    }.onDisappear { password = ""; exportPassword = ""; model.repository?.invalidatePendingWork(); Task { await model.repository?.cancel() } }
      .onReceive(NotificationCenter.default.publisher(for: NSApplication.didResignActiveNotification)) { _ in password = ""; exportPassword = "" }
  }
}

struct TransferMembershipView: View {
  @ObservedObject var model: TransferModel
  @State private var trustApproved = false
  @State private var transport = PrivateTransport()
  @State private var imported: [Data] = []
  private var configuration: MembershipConfiguration? { .bundled() }
  var body: some View {
    Group {
      if let configuration {
        Form {
          Text(model.wallet?.membershipActive == true ? "Membership active" : "Join Zenith").font(.title2.bold())
          LabeledContent("Provider", value: configuration.name)
          Text(configuration.endpoint.host ?? "")
          Text("Your public Wallet ID is shared with this provider. Joining does not connect or change service access.").foregroundStyle(.secondary)
          DisclosureGroup("Provider details") { Text(String(data: (try? configuration.trustData) ?? Data(), encoding: .utf8) ?? "").font(.caption.monospaced()).textSelection(.enabled) }
          if !model.walletUnlocked { NavigationLink("Unlock Wallet") { TransferWalletView(model: model) } }
          else if model.wallet?.backupVerified != true { NavigationLink("Open Recovery") { TransferRecoveryView(model: model) } }
          else if model.wallet?.membershipActive != true {
            if !trustApproved {
              Button("Trust this membership provider") { model.perform({ try await $0.approveTrust(configuration.trustData) }) { _ in trustApproved = true } }
            } else {
              ForEach(Array(imported.enumerated()), id: \.offset) { index, proof in
                Button(imported.count == 1 ? "Use saved membership" : "Use saved membership \(index + 1)") {
                  model.perform({ try await $0.activateMembership(proof, scoped: configuration.scope != nil) })
                }
              }
              Button("Join Zenith") {
                model.perform { repository in
                  let ticket = repository.lifecycleTicket()
                  let body = try await repository.membershipRequest(scope: configuration.scope)
                  var request = URLRequest(url: configuration.endpoint); request.httpMethod = "POST"
                  request.setValue("application/json", forHTTPHeaderField: "Content-Type"); request.httpBody = body
                  let response = try await transport.request(request, maximum: 65_536)
                  try repository.checkLifecycle(ticket)
                  return try await repository.activateMembership(response, scoped: configuration.scope != nil)
                }
              }
            }
          }
        }.padding(24).disabled(model.busy)
          .task {
            trustApproved = (try? await model.repository?.trustMatches(configuration.trustData)) == true
            imported = (try? await model.repository?.importedMemberships(scope: configuration.scope)) ?? []
          }
      } else {
        VStack(alignment: .leading, spacing: 20) {
          Text("Membership").font(.largeTitle.bold())
          Text("Membership setup is needed").font(.headline)
          Text("This build has no approved membership provider. Ask your administrator for a provider configuration.").foregroundStyle(.secondary)
          Text("Membership and service access are separate choices. Restoring a Wallet does not activate a membership.").foregroundStyle(.secondary)
        }.frame(maxWidth: 560, alignment: .leading).frame(maxWidth: .infinity).padding(24)
      }
    }.onChange(of: model.walletUnlocked) { unlocked in if !unlocked { trustApproved = false; transport.cancel() } }
      .onDisappear { transport.cancel(); model.repository?.invalidatePendingWork(); Task { await model.repository?.cancel() } }
  }
}
#endif
