#if os(macOS)
import AppKit
import SwiftUI
import ZenithKit

struct TransferWalletView: View {
  @ObservedObject var model: TransferModel
  @State private var password = ""
  @State private var confirmation = ""
  @State private var filePassword = ""
  @State private var selectedFile: Data?
  @State private var selectedName: String?
  @State private var preview: ImportReview?
  @State private var committing = false
  @State private var mode = "import"
  @State private var backupPassword = ""
  @State private var backupConfirmation = ""
  @State private var notice: String?
  @State private var choosingRecovery = false
  @State private var reuseFilePassword = true
  private var importPassword: String? {
    TransferPasswordRules.importPassword(file: filePassword, local: password, confirmation: confirmation, reuse: reuseFilePassword)
  }

  var body: some View {
    ScrollView {
      VStack(alignment: .leading, spacing: 20) {
        Text("Transfer Wallet").font(.largeTitle.bold())
        Text("Your signing identity in this Mac app. Recovery files are decrypted only by the shared Castalia core.")
          .foregroundStyle(.secondary)
        if let state = model.wallet, state.configured {
          Text(model.walletUnlocked ? "Wallet unlocked" : "Wallet locked").font(.title2.bold())
          if let key=model.displayPublicKey {
            Text(model.walletUnlocked ? "Wallet public identity" : "Last unlocked public identity").font(.caption).foregroundStyle(.secondary)
            Text(key).font(.caption.monospaced()).textSelection(.enabled)
          }
          if model.walletUnlocked {
            Label(state.backupVerified ? "Recovery backup checked" : "Recovery backup needs checking",
              systemImage: state.backupVerified ? "checkmark.shield" : "externaldrive.badge.exclamationmark")
            Button("Lock Wallet") { clear(); model.lock() }
            Divider()
            Text("Recovery backup").font(.headline)
            TransferPasswordField(title: "Backup file password", text: $backupPassword)
            TransferPasswordField(title: "Confirm backup file password", text: $backupConfirmation)
            Text("Use at least 12 characters for a new encrypted backup.").font(.caption).foregroundStyle(.secondary)
            Button("Export encrypted recovery file…") { exportBackup() }
              .disabled(model.busy || !TransferPasswordRules.permitsLocal(backupPassword) || backupPassword != backupConfirmation)
            Button("Check an existing backup…") { verifyBackup() }
              .disabled(model.busy || backupPassword.isEmpty)
            Text("Export saves an encrypted copy. Checking it confirms that the file can restore this Wallet.")
              .font(.callout).foregroundStyle(.secondary)
          } else {
            TransferPasswordField(title: "Wallet unlock password", text: $password, submit: unlock)
            Button("Unlock Wallet") { unlock() }.buttonStyle(.borderedProminent)
              .disabled(model.busy || password.isEmpty)
          }
          Divider()
          Text("Unlock duration").font(.headline)
          Picker("Lock automatically",selection:$model.unlockDuration) {
            ForEach(TransferUnlockDuration.allCases) { Text($0.label).tag($0) }
          }.frame(maxWidth:380)
          Text("Measured from the time you unlock. Switching apps does not lock your Wallet. Reads and background refreshes do not extend the timer.").font(.caption).foregroundStyle(.secondary)
          if model.walletUnlocked,let deadline=model.unlockDeadline {
            Text("Locks at " + deadline.formatted(date:.omitted,time:.shortened)).font(.caption)
          }
        } else if model.wallet != nil {
          Picker("Set up this app's Wallet", selection: $mode) {
            Text("Import recovery file").tag("import")
            Text("Create Wallet").tag("create")
          }.pickerStyle(.segmented).onChange(of: mode) { _ in clear() }
          if mode == "import" {
            Button(selectedName == nil ? "Choose a saved recovery file…" : "Change recovery file…") { choosingRecovery = true }
            if let selectedName {
              Label(selectedName, systemImage: "doc.badge.checkmark").font(.callout)
              Text("Enter this file’s password, then review the Wallet identity before importing.").font(.caption).foregroundStyle(.secondary)
            }
            TransferPasswordField(title: "Recovery-file password", text: $filePassword)
            Text("Decrypts your existing backup. It does not change the backup file’s password.")
              .font(.caption).foregroundStyle(.secondary)
            Toggle("Use the same password to unlock Transfer on this Mac", isOn: $reuseFilePassword)
              .onChange(of: reuseFilePassword) { _ in password = ""; confirmation = "" }
            if reuseFilePassword {
              Text("Transfer saves a separate encrypted Wallet copy using this password. Your identity and recovery file stay the same.")
                .font(.caption).foregroundStyle(.secondary)
              if !filePassword.isEmpty && !TransferPasswordRules.permitsLocal(filePassword) {
                Text("Transfer needs an unlock password of at least 12 characters, up to 4096 UTF-8 bytes. Turn off the option above to choose a separate password; your recovery-file password stays unchanged.")
                  .font(.callout).foregroundStyle(.secondary)
              }
            }
          }
          if mode == "create" || !reuseFilePassword {
            TransferPasswordField(title: "Unlock password for Transfer on this Mac", text: $password)
            TransferPasswordField(title: "Confirm unlock password", text: $confirmation)
            Text("At least 12 characters. This protects only Transfer’s local Wallet copy; it does not change your recovery backup or other apps.")
              .font(.caption).foregroundStyle(.secondary)
            if !confirmation.isEmpty && password != confirmation {
              Text("The unlock passwords do not match.").font(.callout).foregroundStyle(.secondary)
            }
          }
          if mode == "create" {
            Button("Create this app's Wallet") { create() }.buttonStyle(.borderedProminent)
              .disabled(model.busy || !TransferPasswordRules.permitsLocal(password) || password != confirmation)
            Text("A new identity will not inherit authority from any existing Wallet. Import your own recovery file to use your existing identity.")
              .font(.callout).foregroundStyle(.secondary)
          } else {
            Button("Review Wallet import") { prepareImport() }.buttonStyle(.borderedProminent)
              .disabled(model.busy || selectedFile == nil || importPassword == nil)
          }
        } else { ProgressView("Loading Wallet…") }
        if model.busy { ProgressView() }
        if let notice { Text(notice).foregroundStyle(.secondary) }
        Divider()
        Text("Grant approvals").font(.headline)
        Text("Choose a registered DevGraph in Resources & requests to review its inbox and approve an exact selection using this Castalia Wallet. The server must already authorize your Wallet as an operator. Unlocking here does not unlock Chrome.")
          .foregroundStyle(.secondary)
        Text("This app stores its encrypted Wallet separately from Zenith and Chrome. It starts locked after launch and locks when you choose Lock Wallet, quit, or reach the selected timeout. Signing decisions still require their own approval. Public identity and loaded information remain visible while locked. Passwords never enter the resource registry.")
          .font(.footnote).foregroundStyle(.secondary)
      }.frame(maxWidth: 640, alignment: .leading).padding(28)
    }.disabled(model.busy)
      .onDisappear { clear(); model.repository?.invalidatePendingWork(); Task { await model.repository?.cancel() } }
      .onReceive(NotificationCenter.default.publisher(for: NSApplication.didResignActiveNotification)) { _ in clear() }
      .sheet(isPresented: $choosingRecovery) {
        TransferRecoveryPicker(catalog: model.fileCatalog) { file in
          selectedFile = nil; selectedName = nil; filePassword = ""
          selectedFile = try RecoveryFileCatalog.readRecovery(file.url)
          selectedName = file.url.lastPathComponent
          notice = nil; choosingRecovery = false
        }
      }
      .sheet(item: $preview, onDismiss: {
        if !committing {
          model.repository?.invalidatePendingWork()
          Task { await model.repository?.cancel() }
        }
      }) { item in
        let value = item.preview
        VStack(alignment: .leading, spacing: 20) {
          Text("Import this Wallet?").font(.title2.bold())
          Text("Castalia decrypted the recovery file. Confirm its public identity before saving this app's encrypted Wallet.")
          Text(value.publicKey).font(.caption.monospaced()).textSelection(.enabled)
          HStack {
            Button("Cancel") { preview = nil; model.repository?.invalidatePendingWork(); Task { await model.repository?.cancel() } }
            Spacer()
            Button("Import Wallet") {
              committing = true
              preview = nil
              model.perform({ try await $0.commit(value) }) { _ in notice = "Wallet imported on this Mac." }
            }.buttonStyle(.borderedProminent)
          }
        }.padding(24).frame(width: 560)
      }
  }
  private func clearPasswords() {
    password = ""; confirmation = ""; filePassword = ""
    backupPassword = ""; backupConfirmation = ""
  }
  private func clear() {
    clearPasswords(); selectedFile = nil; selectedName = nil; preview = nil
  }
  private func unlock() {
    guard !password.isEmpty else { return }; let secret = password; password = ""
    let lifecycle = model.repository?.lifecycleTicket()
    let identity = model.wallet?.publicKey
    model.perform { try await $0.unlock(password: secret, expectedLifecycle: lifecycle, expectedIdentity: identity) }
  }
  private func create() {
    let secret = password; clear()
    model.perform({ try await $0.create(password: secret) }) { _ in
      notice = "Wallet created. Export and check a recovery backup next."
    }
  }
  private func prepareImport() {
    guard let selectedFile, let new = importPassword else { return }
    let old = filePassword; clearPasswords()
    model.error = nil; notice = nil
    model.perform({ try await $0.prepareRestore(file: selectedFile, filePassword: old, password: new) }) {
      committing = false; preview = ImportReview(preview: $0)
    }
  }
  private func readEncryptedFile() -> (Data, String)? {
    let panel = NSOpenPanel(); panel.canChooseDirectories = false
    guard panel.runModal() == .OK, let url = panel.url else { return nil }
    do { return (try EncryptedImportFile.read(url), url.lastPathComponent) }
    catch { model.error = "Choose a supported encrypted recovery file, no larger than 1 MiB."; return nil }
  }
  private func exportBackup() {
    let panel = NSSavePanel(); panel.nameFieldStringValue = "transfer-wallet.castalia-recovery"
    guard panel.runModal() == .OK, let url = panel.url else { return }
    let secret = backupPassword; backupPassword = ""; backupConfirmation = ""
    model.perform({ try await $0.exportRecovery(password: secret) }) { data in
      do {
        try data.write(to: url, options: [.atomic])
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        notice = "Encrypted recovery file exported. Check the saved file before relying on it."
      } catch { model.error = "Could not save the encrypted backup." }
    }
  }
  private func verifyBackup() {
    guard let (data, _) = readEncryptedFile() else { return }
    let secret = backupPassword; backupPassword = ""; backupConfirmation = ""
    model.perform({ try await $0.verifyBackup(file: data, password: secret) }) { _ in
      notice = "Recovery file checked against this Wallet."
    }
  }
}

// A preview token remains opaque to the renderer and is accepted only by the
// core's original lifecycle/revision transaction.
private struct ImportReview: Identifiable {
  let id = UUID()
  let preview: RestorePreview
}
#endif
