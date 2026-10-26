import SwiftUI

/// Shared native UI over the portable core section. All mutations use the
/// original preview/CAS/lifecycle transaction. No registry file is edited here.
public struct PortableWalletIdentitiesView: View {
  let repository: (any WalletSession)?
  let unlocked: Bool
  let legacy: [IdentityAccount]
  let changed: () -> Void
  @State private var snapshot: WalletIdentitySnapshot?
  @State private var editing: WalletIdentity?
  @State private var editorOpen = false
  @State private var review: RestorePreview?
  @State private var proposed: WalletIdentitySection?
  @State private var reviewReason = ""
  @State private var busy = false
  @State private var uncertain = false
  @State private var message: String?
  @State private var operation: Task<Void, Never>?
  public init(repository: (any WalletSession)?, unlocked: Bool, legacy: [IdentityAccount], changed: @escaping () -> Void) {
    self.repository = repository; self.unlocked = unlocked; self.legacy = legacy; self.changed = changed
  }
  public var body: some View {
    Group {
      if !unlocked { Text("Unlock Wallet to view your identities and accounts.").padding(24) }
      else if let review, let proposed {
        ScrollView {
          VStack(alignment: .leading, spacing: 24) {
            Text("Review Wallet identities").font(.largeTitle.bold())
            Text(reviewReason)
            WalletIdentityReviewRows(section: proposed)
            Text("These are public descriptors, not proof of account control. Saving does not connect Matrix, install Nostr keys, authenticate GitHub/X or grant service access.").foregroundStyle(.secondary)
            Text("Save a new Castaway backup after confirming. Existing backups and original app records remain unchanged.").font(.footnote).foregroundStyle(.secondary)
            HStack {
              Button("Cancel") { cancelDraft() }
              Spacer()
              Button("Confirm and save") { commit(review) }.buttonStyle(.borderedProminent).disabled(busy || uncertain)
            }
            feedback
          }.frame(maxWidth: 680, alignment: .leading).frame(maxWidth: .infinity).padding(24)
        }
      } else if editorOpen, let snapshot {
        WalletIdentityEditor(original: editing, save: { value in
          var accounts = snapshot.section.accounts.filter { $0.accountId != value.accountId }; accounts.append(value)
          do { prepare(try WalletIdentitySection(ownerMemberKey: snapshot.section.ownerMemberKey, accounts: accounts), reason: editing == nil ? "Add this identity to Wallet." : "Replace the reviewed public identity fields.") }
          catch { message = safeMessage(error) }
        }, cancel: { editorOpen = false; editing = nil }, busy: busy, message: message)
      } else {
        ScrollView {
          VStack(alignment: .leading, spacing: 24) {
            Text("Identities & accounts").font(.largeTitle.bold())
            Text("Portable Wallet identities are included in new Castaway data backups. Your recovery file restores the signing identity.").foregroundStyle(.secondary)
            if let snapshot {
              DisclosureGroup("Castalia public identity") { Text(snapshot.section.ownerMemberKey).font(.caption.monospaced()).textSelection(.enabled) }
              HStack {
                Text("Wallet identities").font(.title2.bold()); Spacer()
                Button("Add identity") { editing = nil; editorOpen = true; message = nil }.disabled(busy)
              }
              if snapshot.section.accounts.isEmpty { Text("No portable identities saved.").foregroundStyle(.secondary) }
              ForEach(snapshot.section.accounts) { account in
                GroupBox(account.kind.title) {
                  VStack(alignment: .leading, spacing: 10) {
                    Text(account.label).font(.headline)
                    Text(account.identifier).font(.callout.monospaced()).textSelection(.enabled)
                    if !account.server.isEmpty { Text(account.server).font(.caption).foregroundStyle(.secondary).textSelection(.enabled) }
                    HStack {
                      Button("Edit") { editing = account; editorOpen = true; message = nil }
                      Button("Remove…", role: .destructive) {
                        do { prepare(try WalletIdentitySection(ownerMemberKey: snapshot.section.ownerMemberKey, accounts: snapshot.section.accounts.filter { $0.accountId != account.accountId }), reason: "Remove \(account.label) from the Wallet identity section. This does not revoke provider access or edit the original application record.") }
                        catch { message = safeMessage(error) }
                      }
                    }.disabled(busy)
                  }.padding(8).frame(maxWidth: .infinity, alignment: .leading)
                }
              }
              if legacy.contains(where: { $0.provider != .tailscale }) {
                GroupBox("Existing application records") {
                  VStack(alignment: .leading, spacing: 10) {
                    Text("Copy your saved Matrix/Nostr records into Wallet after review. Stable IDs and fields are preserved; original files are kept. Tailscale records stay in application settings.").foregroundStyle(.secondary)
                    Button("Review existing records for Wallet") {
                      do {
                        let migration = try WalletIdentityMigration.prepare(existing: snapshot.section, legacy: legacy)
                        if migration.added.isEmpty { message = "These records are already included. No changes were made." }
                        else { prepare(migration.proposed, reason: "Copy \(migration.added.count) existing Matrix/Nostr record(s). Original app records and all Tailscale records remain unchanged.") }
                      } catch { message = safeMessage(error) }
                    }.disabled(busy)
                  }.padding(8)
                }
              }
              if let accounts = snapshot.chainAccounts?.accounts {
                Text("Crypto accounts").font(.title2.bold())
                Text("Derived from your recovered identity. Public address display only; transaction signing is not available here.").font(.footnote).foregroundStyle(.secondary)
                ForEach(accounts) { account in
                  GroupBox(account.networkId) { Text(account.address).font(.caption.monospaced()).textSelection(.enabled).padding(8).frame(maxWidth: .infinity, alignment: .leading) }
                }
              }
            } else {
              Text("Wallet identities are not loaded.").foregroundStyle(.secondary)
              Button("Load Wallet identities") { reload() }.disabled(busy)
            }
            Text("Matrix sessions, provider tokens, rewards workflows, and network enrollment are application state and are not part of these descriptors.").font(.footnote).foregroundStyle(.secondary)
            feedback
          }.frame(maxWidth: 680, alignment: .leading).frame(maxWidth: .infinity).padding(24)
        }
      }
    }.task(id: unlocked) { if unlocked { reload() } else { stop() } }
      .onDisappear { stop() }
  }
  @ViewBuilder private var feedback: some View {
    if busy { ProgressView("Working with Wallet…") }
    if let message { Text(message).font(.callout).foregroundStyle(.secondary) }
  }
  private func reload() {
    guard unlocked, !busy, let repository else { return }
    busy = true; message = nil
    let ticket = repository.lifecycleTicket()
    operation = Task { @MainActor in
      do {
        let value = try await repository.walletIdentitySnapshot()
        try Task.checkCancellation(); try repository.checkLifecycle(ticket)
        snapshot = value
      } catch { if !Task.isCancelled { message = safeMessage(error) } }
      busy = false
    }
  }
  private func prepare(_ section: WalletIdentitySection, reason: String) {
    guard unlocked, !busy, let repository, let snapshot else { return }
    busy = true; message = nil; uncertain = false
    let ticket = repository.lifecycleTicket()
    operation = Task { @MainActor in
      do {
        let value = try await repository.prepareWalletIdentities(section, expectedRevision: snapshot.revision)
        try Task.checkCancellation(); try repository.checkLifecycle(ticket)
        guard value.publicKey == section.ownerMemberKey, value.walletIdentities == section else { throw WalletFailure.invalidFile }
        proposed = section; reviewReason = reason; review = value; editorOpen = false; editing = nil
      } catch { if !Task.isCancelled { message = safeMessage(error) } }
      busy = false
    }
  }
  private func commit(_ preview: RestorePreview) {
    guard unlocked, !busy, !uncertain, let repository else { return }
    busy = true; message = nil
    operation = Task { @MainActor in
      do {
        _ = try await repository.commit(preview)
        try Task.checkCancellation()
        review = nil; proposed = nil; busy = false; changed(); reload()
      } catch {
        // Never repeat a candidate after an uncertain durable commit.
        if !Task.isCancelled { uncertain = true; message = "Saving was not confirmed. Reload and unlock Wallet before trying again; do not repeat this confirmation."; changed() }
        busy = false
      }
    }
  }
  private func cancelDraft() {
    operation?.cancel(); operation = nil
    review = nil; proposed = nil; editorOpen = false; editing = nil; busy = false; uncertain = false; message = nil
    repository?.invalidatePendingWork(); Task { await repository?.cancel() }
  }
  private func stop() { cancelDraft(); snapshot = nil }
  private func safeMessage(_ error: Error) -> String {
    (error as? WalletIdentityError)?.errorDescription ?? (error as? WalletFailure)?.errorDescription ?? "Wallet identities could not be loaded or saved. Existing records were preserved."
  }
}

public struct WalletIdentityReviewRows: View {
  let section: WalletIdentitySection
  public init(section: WalletIdentitySection) { self.section = section }
  public var body: some View {
    VStack(alignment: .leading, spacing: 12) {
      Text("Wallet identities (\(section.accounts.count))").font(.headline)
      ForEach(section.accounts) { record in
        VStack(alignment: .leading, spacing: 5) {
          Text(record.kind.title + " · " + record.label).font(.headline)
          Text(record.identifier).font(.caption.monospaced())
          if !record.server.isEmpty { Text(record.server).font(.caption) }
        }.textSelection(.enabled).padding(.vertical, 4)
      }
    }
  }
}

private struct WalletIdentityEditor: View {
  let original: WalletIdentity?
  let save: (WalletIdentity) -> Void
  let cancel: () -> Void
  let busy: Bool
  let message: String?
  @State private var kind = WalletIdentityKind.matrix
  @State private var label = ""
  @State private var identifier = ""
  @State private var server = ""
  @State private var validation: String?
  var body: some View {
    ScrollView {
      VStack(alignment: .leading, spacing: 24) {
        Text(original == nil ? "Add Wallet identity" : "Edit Wallet identity").font(.largeTitle.bold())
        Picker("Provider", selection: $kind) { ForEach(WalletIdentityKind.allCases) { Text($0.title).tag($0) } }.disabled(original != nil)
        TextField("Display label", text: $label)
        TextField(kind == .matrix ? "Matrix ID (@name:server)" : kind == .nostr ? "Nostr public key (64 lowercase hex characters)" : "Stable numeric provider account ID", text: $identifier).portableIdentityInput()
        if kind == .matrix || kind == .nostr {
          TextField(kind == .matrix ? "Homeserver (https://…)" : "Optional relay (wss://…)", text: $server).portableIdentityInput()
        } else {
          Text("Use the provider’s permanent numeric ID. A username can be the display label, but is not a stable account ID.").font(.footnote).foregroundStyle(.secondary)
        }
        Text("Public descriptors only. Never enter tokens, passwords, private keys or active session data.").foregroundStyle(.secondary)
        HStack {
          Button("Cancel", action: cancel); Spacer()
          Button("Review identity") {
            do { save(try WalletIdentity(accountId: original?.accountId ?? UUID().uuidString.lowercased(), kind: kind, label: label, identifier: identifier, server: kind == .github || kind == .x ? "" : server)) }
            catch { validation = WalletIdentityError.invalid.errorDescription }
          }.buttonStyle(.borderedProminent).disabled(busy || label.isEmpty || identifier.isEmpty)
        }
        if let validation { Text(validation).foregroundStyle(.secondary) }
        if let message { Text(message).foregroundStyle(.secondary) }
      }.textFieldStyle(.roundedBorder).frame(maxWidth: 680, alignment: .leading).frame(maxWidth: .infinity).padding(24)
    }.onAppear { if let original { kind = original.kind; label = original.label; identifier = original.identifier; server = original.server } }
  }
}

private extension View {
  @ViewBuilder func portableIdentityInput() -> some View {
    #if os(iOS)
    self.textInputAutocapitalization(.never).autocorrectionDisabled()
    #else
    self.autocorrectionDisabled()
    #endif
  }
}

/// Preserved application records are evidence for an explicit migration, never a
/// second editable identity store. Rendering this view does not write any file.
public struct LegacyWalletIdentityRecordsView: View {
  let records: [IdentityAccount]
  public init(records: [IdentityAccount]) { self.records = records }
  public var body: some View {
    let legacy = records.filter { $0.provider != .tailscale }
    if !legacy.isEmpty {
      GroupBox("Legacy Matrix/Nostr records · Read only") {
        VStack(alignment: .leading, spacing: 12) {
          Text("Original application files are preserved. Open Wallet identities and choose Review existing records for Wallet to copy them after review. Future edits happen only in Wallet; these originals do not change.").font(.footnote).foregroundStyle(.secondary)
          ForEach(legacy) { record in
            VStack(alignment: .leading, spacing: 6) {
              Text(record.provider.title + " · " + record.label).font(.headline)
              Text(record.identifier).font(.callout.monospaced()).textSelection(.enabled)
              if !record.server.isEmpty { Text(record.server).font(.caption).foregroundStyle(.secondary).textSelection(.enabled) }
            }
          }
        }.padding(8).frame(maxWidth: .infinity, alignment: .leading)
      }
    }
  }
}
