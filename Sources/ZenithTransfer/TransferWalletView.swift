#if os(macOS)
import AppKit
import SwiftUI
import ZenithKit

struct TransferWalletView: View {
  enum Section { case setup, recovery, security }
  @ObservedObject var model: TransferModel
  var section: Section = .setup
  var onUnlocked: () -> Void = {}
  @State private var unlockFailure: String?
  @State private var password = ""
  @State private var confirmation = ""
  @State private var filePassword = ""
  @State private var selectedFile: Data?
  @State private var selectedName: String?
  @State private var preview: WalletImportReview?
  @State private var committing = false
  @State private var mode = "choose"
  @State private var importStep = 1
  @State private var backupPassword = ""
  @State private var backupConfirmation = ""
  @State private var notice: String?
  @State private var choosingRecovery = false
  @State private var checkingBackup = false
  private var importPassword: String? {
    TransferPasswordRules.importPassword(file: filePassword, local: password, confirmation: confirmation, reuse: reuseFilePassword)
  }
  @State private var reuseFilePassword = true
  private var title: String {
    if model.wallet?.configured != true { return mode == "create" ? "Create a wallet" : mode == "import" ? "Import wallet" : "Welcome to Zenith" }
    return section == .recovery ? "Recovery" : "Unlock & security"
  }
  var body: some View {
    ScrollView {
      VStack(alignment: .leading, spacing: 24) {
        Text(title).font(.largeTitle.bold())
        if let state = model.wallet, state.configured {
          if !model.walletUnlocked {
            Text("Unlock your wallet").font(.title2.bold())
            Text("Your wallet stays on this device.").foregroundStyle(.secondary)
            TransferPasswordField(title: "Wallet password", text: $password, submit: unlock)
            Button("Unlock") { unlock() }.buttonStyle(TransferPrimaryButtonStyle()).disabled(model.busy || password.isEmpty)
            if let unlockFailure {
              Label(unlockFailure, systemImage: "exclamationmark.circle")
                .font(.callout).foregroundStyle(.red).accessibilityIdentifier("wallet-unlock-error")
            }
          } else if section == .recovery || !state.backupVerified {
            recovery(state)
          } else {
            Label("Wallet unlocked", systemImage: "lock.open").font(.headline)
            Text("Switching apps or screens does not lock your Wallet. Signing decisions still require their own approval.").foregroundStyle(.secondary)
            Button("Lock wallet") { clear(); model.lock() }
          }
          if section == .security {
            Divider()
            Text("Automatic lock").font(.headline)
            Picker("Lock after inactivity", selection: $model.unlockDuration) {
              ForEach((TransferUnlockDuration.selectableCases.contains(model.unlockDuration) ? TransferUnlockDuration.selectableCases : [model.unlockDuration] + TransferUnlockDuration.selectableCases)) { Text($0.label).tag($0) }
            }
            Text("The default is one hour without activity. Interacting with Transfer resets the timer; background reads and refreshes do not. Quitting or Lock wallet always locks this local copy.").font(.footnote).foregroundStyle(.secondary)
            if model.walletUnlocked, let deadline = model.unlockDeadline { Text("Locks after inactivity · " + deadline.formatted(date: .omitted, time: .shortened)).font(.caption) }
          }
        } else if model.wallet != nil {
          if mode == "choose" {
            Text("Start fresh or bring your wallet to this device.").foregroundStyle(.secondary)
            startChoice("Create a wallet", "Start with a new wallet.", "plus.circle") { clear(); mode = "create" }
            startChoice("Import wallet", "Choose an encrypted recovery backup already on this Mac.", "doc.badge.arrow.up") { clear(); mode = "import"; importStep = 1 }
            Text("Powered by Castalia Wallet").font(.footnote).foregroundStyle(.secondary)
          } else {
            Button("Back") {
              if mode == "import" && importStep > 1 { importStep -= 1 }
              else { clear(); mode = "choose" }
            }
            if mode == "create" {
              Text("Create · 1 of 3").font(.subheadline).foregroundStyle(.secondary)
              Text("A password for this device").font(.title2.bold())
              Text("Next, save and check an encrypted recovery backup.").foregroundStyle(.secondary)
              localPasswordFields
              Button("Create wallet") { create() }.buttonStyle(TransferPrimaryButtonStyle())
                .disabled(model.busy || !TransferPasswordRules.permitsLocal(password) || password != confirmation)
            } else {
              Text("Import · \(importStep) of 4").font(.subheadline).foregroundStyle(.secondary)
              if importStep == 1 {
                Text("Choose your recovery backup").font(.title2.bold())
                Button(selectedName == nil ? "Choose a saved recovery file…" : "Change recovery file…") { choosingRecovery = true }
                if let selectedName { Label(selectedName, systemImage: "doc.badge.lock") }
                Text("Your backup stays encrypted until you enter its password.").foregroundStyle(.secondary)
                Button("Continue") { importStep = 2 }.buttonStyle(TransferPrimaryButtonStyle()).disabled(selectedFile == nil)
              } else if importStep == 2 {
                Text("Enter the backup password").font(.title2.bold())
                Text("Use the password chosen when this file was saved.").foregroundStyle(.secondary)
                TransferPasswordField(title: "Backup password", text: $filePassword)
                Button("Continue") { importStep = 3 }.buttonStyle(TransferPrimaryButtonStyle()).disabled(filePassword.isEmpty)
              } else {
                Text("A password for this device").font(.title2.bold())
                Toggle("Use the backup password to unlock this Wallet", isOn: $reuseFilePassword)
                  .onChange(of: reuseFilePassword) { _ in password = ""; confirmation = "" }
                Text("This protects the local Wallet copy. Your recovery file and identity stay unchanged.").foregroundStyle(.secondary)
                if !reuseFilePassword { localPasswordFields }
                else if !filePassword.isEmpty && !TransferPasswordRules.permitsLocal(filePassword) {
                  Text("Choose a separate unlock password of at least 12 characters for this older backup.").foregroundStyle(.secondary)
                }
                Button("Review wallet") { prepareImport() }.buttonStyle(TransferPrimaryButtonStyle()).disabled(model.busy || importPassword == nil)
              }
            }
          }
        } else { ProgressView("Opening wallet") }
        if model.busy { ProgressView("Working securely on this device") }
        if let notice { Text(notice).foregroundStyle(.secondary) }
        Text("Private keys stay inside Castalia. Unlocking and importing do not grant service access.").font(.footnote).foregroundStyle(.secondary)
      }.frame(maxWidth: 560, alignment: .leading).frame(maxWidth: .infinity).padding(24)
    }.disabled(model.busy)
      .onDisappear { clear(); model.repository?.invalidatePendingWork(); Task { await model.repository?.cancel() } }
      .onChange(of: model.walletUnlocked) { unlocked in
        if !unlocked && preview != nil { preview = nil; model.repository?.invalidatePendingWork(); Task { await model.repository?.cancel() } }
      }
      .onReceive(NotificationCenter.default.publisher(for: NSApplication.didResignActiveNotification)) { _ in clearPasswords() }
      .sheet(isPresented: $choosingRecovery) {
        TransferRecoveryPicker(catalog: model.fileCatalog) { file in
          selectedFile = nil; selectedName = nil; filePassword = ""
          selectedFile = try RecoveryFileCatalog.readRecovery(file.url); selectedName = file.url.lastPathComponent
          notice = nil; choosingRecovery = false
        }
      }
      .sheet(item: $preview, onDismiss: {
        if !committing { model.repository?.invalidatePendingWork(); Task { await model.repository?.cancel() } }
      }) { item in
        let value = item.preview
        VStack(alignment: .leading, spacing: 20) {
          Text("Import · 4 of 4").font(.subheadline).foregroundStyle(.secondary)
          Text("Review your wallet").font(.title2.bold())
          Text("Your backup has been checked. Confirm its public identity before saving this device’s encrypted copy.")
          ScrollView { WalletImportReviewContent(review: item) }.frame(maxHeight: 420)
          Text("Importing does not activate memberships or connect service access.").foregroundStyle(.secondary)
          HStack {
            Button("Cancel") { preview = nil; model.repository?.invalidatePendingWork(); Task { await model.repository?.cancel() } }
            Spacer()
            Button("Import wallet") {
              committing = true; preview = nil
              model.perform({ try await $0.commit(value) }) { _ in notice = "Wallet imported on this device." }
            }.buttonStyle(TransferPrimaryButtonStyle())
          }
        }.padding(24).frame(width: 560)
      }
  }
  private var localPasswordFields: some View {
    VStack(alignment: .leading, spacing: 16) {
      TransferPasswordField(title: "Wallet password", text: $password)
      TransferPasswordField(title: "Repeat wallet password", text: $confirmation)
      Text(!confirmation.isEmpty && confirmation != password ? "The passwords don’t match yet." : "Use at least 12 characters.").font(.footnote).foregroundStyle(.secondary)
    }
  }
  private func startChoice(_ title: String, _ detail: String, _ icon: String, action: @escaping () -> Void) -> some View {
    Button(action: action) {
      HStack(spacing: 16) {
        Image(systemName: icon).font(.title2).foregroundStyle(.tint)
        VStack(alignment: .leading, spacing: 4) { Text(title).font(.headline); Text(detail).font(.subheadline).foregroundStyle(.secondary) }.frame(maxWidth: .infinity, alignment: .leading)
        Image(systemName: "chevron.right").foregroundStyle(.secondary)
      }.padding(20).background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 16))
    }.buttonStyle(.plain)
  }
  private func recovery(_ state: WalletState) -> some View {
    VStack(alignment: .leading, spacing: 20) {
      Label(state.backupVerified ? "Recovery checked" : "Check your recovery file", systemImage: "checkmark.shield").font(.headline)
      Picker("Recovery action", selection: $checkingBackup) { Text("Save a recovery backup").tag(false); Text("Check a saved backup").tag(true) }.pickerStyle(.segmented)
      Text(checkingBackup ? "Select the saved file and enter its password. Castalia checks that it restores this Wallet." : "Save an encrypted file that can restore this Wallet on another device.").foregroundStyle(.secondary)
      TransferPasswordField(title: "Backup password", text: $backupPassword)
      if !checkingBackup { TransferPasswordField(title: "Repeat backup password", text: $backupConfirmation) }
      if checkingBackup {
        Button("Check recovery file…") { verifyBackup() }.buttonStyle(TransferPrimaryButtonStyle()).disabled(model.busy || backupPassword.isEmpty)
      } else {
        Button("Save recovery file…") { exportBackup() }.buttonStyle(TransferPrimaryButtonStyle()).disabled(model.busy || !TransferPasswordRules.permitsLocal(backupPassword) || backupPassword != backupConfirmation)
      }
      Text("Saving and checking are separate steps. Use the actual saved file before relying on the backup.").font(.footnote).foregroundStyle(.secondary)
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
    guard !model.busy, !model.locking, !password.isEmpty else { return }; let secret = password; password = ""
    notice = nil; unlockFailure = nil
    let lifecycle = model.repository?.lifecycleTicket()
    let identity = model.wallet?.publicKey
    model.perform(onFailure: { unlockFailure = $0 }, {
      try await $0.unlock(password: secret, expectedLifecycle: lifecycle, expectedIdentity: identity)
    }, success: { state in
      if state.unlocked && model.walletUnlocked { onUnlocked() }
    })
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
      committing = false; preview = WalletImportReview(preview: $0, context: .recovery)
    }
  }
  private func readEncryptedFile() -> (Data, String)? {
    let panel = NSOpenPanel(); panel.canChooseDirectories = false
    guard panel.runModal() == .OK, let url = panel.url else { return nil }
    do { return (try EncryptedImportFile.read(url), url.lastPathComponent) }
    catch { model.error = "Choose a supported encrypted recovery file, no larger than 1 MiB."; return nil }
  }
  private func exportBackup() {
    let panel = NSSavePanel(); panel.nameFieldStringValue = "Castalia.castalia-recovery"
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

/// Modal caller owns navigation; the security destination itself remains open.
/// Keep dismissal outside the busy Wallet body so an empty form or an in-flight
/// unlock never traps the user. Disappearance invalidates unfinished custody work.
struct TransferWalletSheet: View {
  @ObservedObject var model: TransferModel
  @Environment(\.dismiss) private var dismiss
  var body: some View {
    VStack(spacing: 0) {
      HStack {
        Text("Castalia Wallet").font(.headline)
        Spacer()
        Button("Close", action: close)
          .keyboardShortcut(.cancelAction)
          .accessibilityIdentifier("close-wallet-sheet")
      }.padding(20)
      Divider()
      TransferWalletView(model: model, section: .security, onUnlocked: { dismiss() })
    }.frame(width: 640, height: 640)
      .onExitCommand(perform: close)
  }
  private func close() {
    // Invalidate synchronously: SwiftUI can delay onDisappear until after an
    // animation, which must not leave an unfinished unlock authorized.
    model.repository?.invalidatePendingWork()
    Task { await model.repository?.cancel() }
    dismiss()
  }
}

#endif
