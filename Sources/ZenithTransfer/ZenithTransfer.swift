#if os(macOS)
import AppKit
import Combine
import SwiftUI
import UniformTypeIdentifiers
import ZenithKit

@main
@MainActor
struct ZenithTransferApp: App {
  @StateObject private var model=TransferModel()
  var body: some Scene {
    WindowGroup("Zenith Transfer") {
      TransferConsole(model:model).frame(minWidth: 920, minHeight: 680)
    }.defaultSize(width: 980, height: 780)
  }
}

struct TransferWindow: View {
  @State private var choosing = false
  @ObservedObject var catalogModel: TransferFileCatalog
  private var sections: [RecoveryCatalogSection] { catalogModel.sections }
  private var loading: Bool { catalogModel.loading }
  @State private var selected: RecoveryCatalogFile?
  @State private var frames: [String] = []
  @State private var index = 0
  @State private var image: CGImage?
  @State private var error: String?
  @State private var playing = true
  private let timer = Timer.publish(every: 0.5, on: .main, in: .common).autoconnect()
  private var files: [RecoveryCatalogFile] { catalogModel.files }

  var body: some View {
    VStack(alignment: .leading, spacing: 20) {
      HStack(alignment: .top) {
        VStack(alignment: .leading, spacing: 6) {
          Text("Your wallet files").font(.largeTitle.bold())
          Text("Choose a file to transfer to your iPhone.").foregroundStyle(.secondary)
        }
        Spacer()
        Button("Choose another file") { choosing = true }.keyboardShortcut("o", modifiers: .command)
      }
      HStack(alignment: .top, spacing: 24) {
        catalog.frame(width: 310)
        Divider()
        detail.frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
      }
      Text("Only encrypted headers are checked here. Your phone checks the contents after you enter the password. Nothing is uploaded.")
        .font(.footnote).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
      if let error { Text(error).foregroundStyle(.red) }
    }.padding(24)
      .task { if !catalogModel.loaded { await refresh() } }
      .fileImporter(isPresented: $choosing, allowedContentTypes: [.data, .json, .item]) { result in
        do { select(RecoveryFileCatalog.inspect(try result.get())) }
        catch { if (error as NSError).code != NSUserCancelledError { errorMessage("The file could not be opened.") } }
      }
      .onReceive(timer) { _ in if playing && frames.count > 1 { advance() } }
      .onReceive(NotificationCenter.default.publisher(for: NSApplication.willTerminateNotification)) { _ in clearQR() }
  }

  private var catalog: some View {
    VStack(alignment: .leading, spacing: 12) {
      HStack {
        Text(loading ? "Checking folders…" : "\(files.count) files found").font(.headline)
        Spacer()
        Button("Refresh", systemImage: "arrow.clockwise") { Task { await refresh() } }
          .labelStyle(.iconOnly).disabled(loading).help("Refresh wallet files")
      }
      Text("Newest first").font(.caption).foregroundStyle(.secondary)
      ScrollView {
        LazyVStack(alignment: .leading, spacing: 12) {
          ForEach(files) { file in
            Button { select(file) } label: {
              VStack(alignment: .leading, spacing: 6) {
                Text(file.url.lastPathComponent).font(.callout.weight(.medium))
                  .lineLimit(3).truncationMode(.middle)
                if let format = file.format {
                  Text("\(format.title) · \(format.version)").font(.callout)
                  Label(format.badge, systemImage: format.legacyFilename ? "clock.arrow.circlepath" : "doc")
                    .font(.caption).foregroundStyle(format.legacyFilename ? Color.orange : Color.secondary)
                } else {
                  Text(file.declaredSchema ?? "Unrecognized format").font(.caption).lineLimit(2)
                  Text("Not supported").font(.caption).foregroundStyle(.secondary)
                }
                savedDate(file).font(.caption).foregroundStyle(.secondary)
                Text("\(file.url.deletingLastPathComponent().lastPathComponent) · \(ByteCountFormatter.string(fromByteCount: Int64(file.bytes), countStyle: .file))")
                  .font(.caption).foregroundStyle(.secondary)
              }.frame(maxWidth: .infinity, alignment: .leading).padding(12)
                .background(selected?.id == file.id ? Color.accentColor.opacity(0.13) : Color.primary.opacity(0.04))
                .clipShape(RoundedRectangle(cornerRadius: 10)).contentShape(Rectangle())
            }.buttonStyle(.plain)
              .accessibilityAddTraits(selected?.id == file.id ? .isSelected : [])
          }
          if !loading && files.isEmpty {
            Text("No matching files").foregroundStyle(.secondary)
          }
          DisclosureGroup("Folders checked") {
            ForEach(sections) { section in
              VStack(alignment: .leading, spacing: 4) {
                Text(section.folder.url.path.replacingOccurrences(of: NSHomeDirectory(), with: "~"))
                  .textSelection(.enabled)
                Text(section.problem ?? "\(section.files.count) matching files")
              }.font(.caption).foregroundStyle(.secondary).padding(.vertical, 4)
            }
          }
          ForEach(sections.filter { $0.problem != nil }) { section in
            Text("\(section.folder.title): \(section.problem!)").font(.caption).foregroundStyle(.secondary)
          }
        }
      }
    }
  }

  @ViewBuilder private var detail: some View {
    if let selected {
      VStack(alignment: .leading, spacing: 12) {
        if let format = selected.format {
          Text("\(format.title) · \(format.version)").font(.title2.bold())
          Text(selected.url.lastPathComponent).font(.callout).lineLimit(2).truncationMode(.middle)
          savedDate(selected).font(.callout).foregroundStyle(.secondary)
          Text(format.schema).font(.caption.monospaced()).textSelection(.enabled)
          if let contents = format.contentsSchema {
            Text("Contents: \(contents)").font(.caption.monospaced()).textSelection(.enabled)
          }
          Text(format.explanation).font(.callout).fixedSize(horizontal: false, vertical: true)
          if let image {
            Image(decorative: image, scale: 1).interpolation(.none).resizable().scaledToFit()
              .padding(12).background(.white).frame(maxWidth: .infinity, maxHeight: .infinity)
              .accessibilityLabel("Encrypted file QR, part \(index + 1) of \(frames.count)")
            if frames.count > 1 {
              HStack {
                Text("Part \(index + 1) of \(frames.count)").monospacedDigit()
                Spacer()
                Button(playing ? "Pause" : "Play") { playing.toggle() }
                Button("Next part") { playing = false; advance() }
              }
            } else { Text("One QR contains the complete encrypted file.").font(.callout).foregroundStyle(.secondary) }
            Text("On your phone, choose Scan laptop QR. Enter the file password there. A photo of this QR is a copy of your encrypted backup.")
              .font(.footnote).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            Button("Hide QR") { clearQR() }
          } else {
            Spacer()
            if selected.canShowQR { Button("Show QR") { select(selected) }.buttonStyle(.borderedProminent) }
            else { Text("This file is larger than 64 KiB. Transfer it using USB or Files.") }
            Spacer()
          }
        } else {
          Text("This file needs attention").font(.title2.bold())
          Text(selected.url.lastPathComponent).lineLimit(3)
          savedDate(selected).font(.callout).foregroundStyle(.secondary)
          if let schema = selected.declaredSchema { Text("Declared format: \(schema)").font(.caption.monospaced()) }
          Text(selected.problem ?? "This file cannot be transferred.")
          Text("Keep the original file. No conversion or changes have been made.").foregroundStyle(.secondary)
          Spacer()
        }
      }
    } else {
      VStack(alignment: .leading, spacing: 18) {
        Text("Recovery or data?").font(.title2.bold())
        formatHelp(".castalia-recovery", "v1 · Wallet recovery", "Restores your signing identity.")
        formatHelp(".castaway", "v1 · Castaway data", "Adds data to a matching wallet. It does not restore signing identity.")
        Divider()
        Text("Older filenames").font(.headline)
        Text("Some older .castaway and .castalia-wallet files contain recovery backups. Their naming is deprecated; the v1 recovery contents are still supported.")
        Text("Each file is labeled by its contents, not its extension.").foregroundStyle(.secondary)
        Spacer()
        Text("Select a file on the left to see its version and QR. Only one file is shown as a QR at a time.")
          .font(.callout).foregroundStyle(.secondary)
      }
    }
  }

  private func savedDate(_ file: RecoveryCatalogFile) -> some View {
    Text(file.modified == .distantPast
      ? "Saved date unavailable"
      : "Saved \(file.modified.formatted(date: .abbreviated, time: .shortened))")
      .help("The file’s last modification date on this Mac, shown in your local time zone.")
  }

  private func formatHelp(_ ext: String, _ title: String, _ help: String) -> some View {
    VStack(alignment: .leading, spacing: 5) {
      Text(ext).font(.headline.monospaced())
      Text(title).font(.callout.weight(.medium))
      Text(help).font(.callout).foregroundStyle(.secondary)
    }
  }
  private func refresh() async {
    await catalogModel.refresh()
    selected = nil
    clearQR()
  }
  private func select(_ file: RecoveryCatalogFile) {
    clearQR()
    selected = RecoveryFileCatalog.inspect(file.url)
    if let selected { catalogModel.remember(selected) }
    guard let current = selected, current.canShowQR else { return }
    do {
      let data = try EncryptedImportFile.read(current.url)
      let format = try RecoveryFileFormat.inspect(data, filename: current.url.lastPathComponent)
      guard format == current.format else { throw RecoveryTransferError.invalidFile }
      let encoded = try RecoveryQR.frames(for: data)
      image = try RecoveryQRImage.render(encoded[0])
      frames = encoded
      index = 0
      playing = true
    } catch { errorMessage(error.localizedDescription) }
  }
  private func advance() {
    guard !frames.isEmpty else { return }
    index = (index + 1) % frames.count
    do { image = try RecoveryQRImage.render(frames[index]) }
    catch { errorMessage(error.localizedDescription) }
  }
  private func errorMessage(_ message: String) { clearQR(); error = message }
  private func clearQR() { image = nil; frames = []; index = 0; error = nil }
}
#else
@main enum UnsupportedPlatform { static func main() {} }
#endif
