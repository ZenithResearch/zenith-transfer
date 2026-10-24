import SwiftUI
import UniformTypeIdentifiers

struct HolderGrantBackupDocument: FileDocument {
  static var readableContentTypes: [UTType] { [.json, .data] }
  var data: Data
  init(data: Data) { self.data = data }
  init(configuration: ReadConfiguration) throws {
    data = configuration.file.regularFileContents ?? Data()
  }
  func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
    FileWrapper(regularFileWithContents: data)
  }
}
public struct HolderGrantSummaryView: View {
  let summary: HolderGrantSummary
  public init(summary: HolderGrantSummary) { self.summary = summary }
  public var body: some View {
    VStack(alignment: .leading, spacing: 10) {
      Text(summary.service).font(.headline).textSelection(.enabled)
      Text("Provider: " + summary.issuer).foregroundStyle(.secondary)
      Text("Wallet: " + summary.holder_public_key).font(.caption.monospaced()).textSelection(.enabled)
      Text("Self-issued credentials last at most \(summary.max_credential_lifetime_seconds) seconds.").font(.footnote)
      Text(
        summary.validity.not_after.map {
          "Grant expires " + Date(timeIntervalSince1970: Double($0)).formatted()
        } ?? "Until revoked")
      Text("Only this Wallet can use this grant. Onward delegation is disabled.").font(.footnote)
      ForEach(Array(summary.permissions.enumerated()), id: \.offset) { _, p in
        VStack(alignment: .leading, spacing: 5) {
          Text(p.title).font(.subheadline.bold())
          if p.scope.mode == "all" { Text("All resources permitted by the conditions below") }
          ForEach(Array((p.scope.roots ?? []).enumerated()), id: \.offset) { _, root in
            Text(root.map { $0.kind + "/" + $0.id }.joined(separator: " → "))
          }
          DisclosureGroup("Conditions") {
            Text(p.conditions).font(.caption.monospaced()).textSelection(.enabled)
          }
        }.padding(.vertical, 4)
      }
      Text(
        "Paths include their current descendants. Resources that move outside the path lose access. The provider checks current grant status at each access."
      ).font(.footnote).foregroundStyle(.secondary)
    }.frame(maxWidth: .infinity, alignment: .leading)
  }
}
public struct WalletGrantsView: View {
  let repository: (any WalletSession)?
  let unlocked: Bool
  @State private var grants: [HolderGrantSummary] = []
  @State private var busy = false
  @State private var notice: String?
  @State private var importing = false
  @State private var exporting = false
  @State private var document = HolderGrantBackupDocument(data: Data())
  @State private var review: RestorePreview?
  public init(repository: (any WalletSession)?, unlocked: Bool) {
    self.repository = repository
    self.unlocked = unlocked
  }
  public var body: some View {
    VStack(alignment: .leading, spacing: 18) {
      Text("Saved grants").font(.largeTitle.bold())
      Text(
        "Provider-signed permissions saved in your encrypted Wallet database. Wallet can produce equal or narrower credentials for itself from these grants."
      ).foregroundStyle(.secondary)
      if grants.isEmpty {
        Text(
          unlocked
            ? "No reusable grants saved. Connect to a service and choose Save grant in Wallet."
            : "Unlock Wallet to load saved grants.")
      }
      ForEach(grants) { grant in GroupBox { HolderGrantSummaryView(summary: grant).padding(8) } }
      HStack {
        Button("Export encrypted grant backup…") {
          run { r in
            document = HolderGrantBackupDocument(data: try await r.exportHolderGrantBackup())
            exporting = true
          }
        }
        Button("Restore grant backup…") { importing = true }
      }.disabled(!unlocked || busy)
      Text(
        "Keep this backup with your Wallet recovery file. The grant backup contains no signing key and can only be opened by the same recovered Wallet. Restoring a grant cannot revive revoked access or change provider trust."
      ).font(.footnote).foregroundStyle(.secondary)
      if busy { ProgressView() }
      if let notice { Text(notice).foregroundStyle(.secondary) }
    }.padding(24).frame(maxWidth: 700, alignment: .leading)
      .task(id: unlocked) { if unlocked { await refresh() } }
      .fileExporter(
        isPresented: $exporting, document: document, contentType: .json,
        defaultFilename: "castalia-grant-backup.json"
      ) { result in if case .failure = result { notice = "The grant backup could not be saved." } }
      .fileImporter(isPresented: $importing, allowedContentTypes: [.json, .data]) { result in
        guard case .success(let url) = result else { return }
        run { r in
          let access = url.startAccessingSecurityScopedResource()
          defer { if access { url.stopAccessingSecurityScopedResource() } }
          let data = try EncryptedImportFile.readBoundedBytes(url)
          review = try await r.prepareHolderGrantBackup(data)
        }
      }
      .sheet(item: $review, onDismiss: { Task { await repository?.cancel() } }) { preview in
        VStack(alignment: .leading, spacing: 18) {
          Text("Restore saved grants?").font(.title2.bold())
          Text(
            "The encrypted backup belongs to this Wallet. Existing conflicting grants are preserved and rejected rather than overwritten."
          )
          ScrollView { ForEach(preview.holderGrants ?? []) { g in HolderGrantSummaryView(summary: g) } }
          HStack {
            Button("Cancel") { review = nil }
            Button("Restore grants") {
              run { r in
                _ = try await r.commit(preview)
                review = nil
                await refresh()
              }
            }.buttonStyle(.borderedProminent)
          }
        }.padding(24).frame(minWidth: 320)
      }
  }
  @MainActor private func refresh() async {
    guard let repository, unlocked else { return }
    do { grants = try await repository.holderGrantSummaries() } catch {
      notice = "Saved grants could not be read. Your Wallet data is unchanged."
    }
  }
  private func run(_ action: @escaping @MainActor (any WalletSession) async throws -> Void) {
    guard let repository, unlocked, !busy else { return }
    busy = true
    notice = nil
    Task { @MainActor in
      defer { busy = false }
      do { try await action(repository) } catch {
        notice =
          "This grant operation could not finish. Unlock Wallet and check the selected file or service."
      }
    }
  }
}
