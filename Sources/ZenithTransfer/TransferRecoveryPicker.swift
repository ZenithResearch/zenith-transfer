#if os(macOS)
import AppKit
import SwiftUI
import ZenithKit

/// Shared discovery state for Wallet import and the encrypted-file QR helper.
/// Only public envelope metadata is retained; no decrypted data or passwords.
@MainActor final class TransferFileCatalog: ObservableObject {
  @Published private(set) var sections: [RecoveryCatalogSection] = []
  @Published private(set) var loading = false
  @Published private(set) var loaded = false
  @Published private var selectedFiles: [URL: RecoveryCatalogFile] = [:]
  var files: [RecoveryCatalogFile] {
    var all = Dictionary(sections.flatMap(\.files).map { ($0.url, $0) }, uniquingKeysWith: { _, last in last })
    all.merge(selectedFiles) { _, selected in selected }
    return all.values.sorted {
      $0.modified == $1.modified ? $0.url.path < $1.url.path : $0.modified > $1.modified
    }
  }
  func remember(_ file: RecoveryCatalogFile) { selectedFiles[file.url] = file }
  func refresh() async {
    guard !loading else { return }
    loading = true
    let folders = RecoveryFileCatalog.defaultFolders()
    let extraURLs = Array(selectedFiles.keys)
    let discovered = await Task.detached {
      (RecoveryFileCatalog.scan(folders), extraURLs.map { RecoveryFileCatalog.inspect($0) })
    }.value
    sections = discovered.0
    selectedFiles = Dictionary(uniqueKeysWithValues: discovered.1.map { ($0.url, $0) })
    loaded = true; loading = false
  }
}

struct TransferRecoveryPicker: View {
  @ObservedObject var catalog: TransferFileCatalog
  let select: (RecoveryCatalogFile) throws -> Void
  @Environment(\.dismiss) private var dismiss
  @State private var query = ""
  @State private var problem: String?
  private var matches: [RecoveryCatalogFile] {
    catalog.files.filter { query.isEmpty || $0.url.lastPathComponent.localizedCaseInsensitiveContains(query)
      || $0.url.deletingLastPathComponent().path.localizedCaseInsensitiveContains(query) }
  }
  private var recovery: [RecoveryCatalogFile] { matches.filter { $0.format?.kind == .recovery } }
  private var other: [RecoveryCatalogFile] { matches.filter { $0.format?.kind != .recovery } }
  var body: some View {
    VStack(alignment: .leading, spacing: 16) {
      HStack {
        VStack(alignment: .leading, spacing: 5) {
          Text("Choose a recovery backup").font(.title2.bold())
          Text("The same files discovered in Transfer files, newest first.").foregroundStyle(.secondary)
        }
        Spacer()
        Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
      }
      TextField("Search filenames or folders", text: $query)
      HStack {
        Text(catalog.loading ? "Checking folders…" : "\(recovery.count) recovery backups").font(.headline)
        Spacer()
        Button("Refresh", systemImage: "arrow.clockwise") { Task { await catalog.refresh() } }
          .disabled(catalog.loading)
        Button("Choose another file…") { chooseAnother() }
      }
      ScrollView {
        LazyVStack(alignment: .leading, spacing: 10) {
          ForEach(recovery) { file in
            Button { use(file) } label: { row(file, selectable: true) }.buttonStyle(.plain)
          }
          if recovery.isEmpty && !catalog.loading {
            Text(query.isEmpty ? "No recovery backups found in the checked folders. Choose another file to locate yours." : "No matching recovery backups.")
              .foregroundStyle(.secondary).padding(.vertical, 20)
          }
          if !other.isEmpty {
            DisclosureGroup("Data files and unavailable files (\(other.count))") {
              Text("Castaway data files do not restore a signing identity.").font(.callout).foregroundStyle(.secondary)
              ForEach(other) { row($0, selectable: false) }
            }.padding(.top, 10)
          }
          DisclosureGroup("Folders checked") {
            ForEach(catalog.sections) { section in
              VStack(alignment: .leading, spacing: 3) {
                Text(shortPath(section.folder.url))
                Text(section.problem ?? "\(section.files.count) files found").foregroundStyle(.secondary)
              }.font(.caption).padding(.vertical, 4)
            }
          }.padding(.top, 10)
        }
      }
      if let problem { Text(problem).font(.callout).foregroundStyle(.red) }
      Text("Selecting a file does not import it. Enter its password and confirm the public identity on the next screen. Nothing is uploaded.")
        .font(.footnote).foregroundStyle(.secondary)
    }.padding(24).frame(width: 680, height: 580)
      .task { if !catalog.loaded { await catalog.refresh() } }
  }
  private func row(_ file: RecoveryCatalogFile, selectable: Bool) -> some View {
    HStack(alignment: .top, spacing: 12) {
      Image(systemName: selectable ? "key.fill" : "doc").foregroundStyle(.secondary).padding(.top, 3)
      VStack(alignment: .leading, spacing: 5) {
        Text(file.url.lastPathComponent).font(.headline).lineLimit(2).truncationMode(.middle)
        Text(file.modified == .distantPast ? "Saved date unavailable" : "Saved \(file.modified.formatted(date: .abbreviated, time: .shortened))")
          .font(.caption).foregroundStyle(.secondary)
        Text(shortPath(file.url.deletingLastPathComponent())).font(.caption).foregroundStyle(.secondary).lineLimit(2)
        if let format = file.format {
          Text("\(format.title) · \(format.version)\(format.legacyFilename ? " · Legacy filename" : "")")
            .font(.caption).foregroundStyle(.secondary)
        } else { Text(file.problem ?? "Unavailable").font(.caption).foregroundStyle(.secondary) }
      }
      Spacer(minLength: 0)
      if selectable { Image(systemName: "chevron.right").foregroundStyle(.secondary) }
    }.frame(maxWidth: .infinity, alignment: .leading).padding(12)
      .background(Color.primary.opacity(0.04)).cornerRadius(10).contentShape(Rectangle())
  }
  private func shortPath(_ url: URL) -> String {
    let home = NSHomeDirectory()
    return url.path.hasPrefix(home + "/") ? "~" + url.path.dropFirst(home.count) : url.path
  }
  private func chooseAnother() {
    let panel = NSOpenPanel(); panel.canChooseDirectories = false
    guard panel.runModal() == .OK, let url = panel.url else { return }
    let file = RecoveryFileCatalog.inspect(url)
    catalog.remember(file)
    use(file)
  }
  private func use(_ file: RecoveryCatalogFile) {
    do { try select(file); problem = nil }
    catch { problem = "This file is unavailable or is not a supported recovery backup. Refresh the list or choose another file." }
  }
}
#endif
