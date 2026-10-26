#if os(macOS)
import SwiftUI
import ZenithKit

@MainActor final class TransferPresetLibrary: ObservableObject {
  @Published var customs: [CredentialPresetRevision] = []
  @Published var error: String?
  private var store: CredentialPresetStore?
  var available: [CredentialPresetRevision] { CredentialPresetRevision.builtins + customs.filter { !$0.archived } }
  init() {
    do {
      let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
      store = try CredentialPresetStore(directory: base.appendingPathComponent("ZenithTransfer/CredentialPresets"))
      try reload()
    } catch { self.error = "The preset library could not be opened safely." }
  }
  func reload() throws { guard let store else { throw CredentialPresetError.storage }; customs = try store.latest() }
  func save(_ value: CredentialPresetRevision, replacing expected: CredentialPresetRevision?) throws {
    guard let store else { throw CredentialPresetError.storage }
    try store.append(value, replacing: expected); try reload()
  }
}

/// Native member-permission controls shared with the preset creator.
struct TransferPermissionEditor: View {
  @Binding var reads: Set<String>
  @Binding var writes: Set<String>
  @Binding var arenaRead: Bool
  var body: some View {
    VStack(alignment: .leading, spacing: 14) {
      Text("Work read permissions").font(.headline)
      ForEach(WorkReadPermission.allCases, id: \.rawValue) { permission in
        Toggle(isOn: selected(permission.rawValue, set: $reads)) {
          VStack(alignment: .leading, spacing: 3) {
            Text(permission.title)
            Text(permission.explanation).font(.caption).foregroundStyle(.secondary)
          }
        }
      }
      Toggle("List and read Arena records", isOn: $arenaRead)
      Text("Select the specific Arenas when issuing this credential. Arena metadata does not grant access to its Work.").font(.caption).foregroundStyle(.secondary)
      Label(WorkReadPermission.arenaAvailability, systemImage: "info.circle")
        .font(.caption).foregroundStyle(.secondary)
      Text("Write permissions").font(.headline)
      LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], alignment: .leading, spacing: 12) {
        ForEach(OwnerPermissionPreset.allOperations, id: \.self) { operation in
          Toggle(OwnerPermissionPreset.title(operation), isOn: selected(operation, set: $writes))
        }
      }
      Text("Applies to Initiative, Project, Issue and Task. Access administration and separate receipt/evidence permissions are configured separately.")
        .font(.caption).foregroundStyle(.secondary)
    }
  }
  private func selected(_ value: String, set: Binding<Set<String>>) -> Binding<Bool> {
    Binding(get: { set.wrappedValue.contains(value) }, set: { chosen in
      if chosen { set.wrappedValue.insert(value) } else { set.wrappedValue.remove(value) }
    })
  }
}

struct TransferPresetsView: View {
  @ObservedObject var library: TransferPresetLibrary
  @State private var editing: PresetEditTarget?
  @State private var showArchived = false
  struct PresetEditTarget: Identifiable { let id = UUID(); let source: CredentialPresetRevision?; let duplicate: Bool }
  var body: some View {
    VStack(alignment: .leading, spacing: 18) {
      HStack {
        VStack(alignment: .leading, spacing: 5) {
          Text("Credential presets").font(.largeTitle.bold())
          Text("Reusable permission recipes. Choose resources and duration when you set up access.").foregroundStyle(.secondary)
        }
        Spacer()
        Button("New preset") { editing = PresetEditTarget(source: nil, duplicate: false) }.buttonStyle(TransferPrimaryButtonStyle())
      }
      Text("Changing a recipe saves a new revision. It does not change existing credentials, grants or owner policies.").font(.callout)
      Toggle("Show archived presets", isOn: $showArchived)
      ScrollView {
        VStack(alignment: .leading, spacing: 14) {
          ForEach(CredentialPresetRevision.builtins + library.customs.filter { showArchived || !$0.archived }) { preset in
            HStack(alignment: .top, spacing: 20) {
              VStack(alignment: .leading, spacing: 6) {
                Text(preset.name + (preset.archived ? " · Archived" : "")).font(.headline)
                Text(preset.description).foregroundStyle(.secondary)
                Text("Revision \(preset.revision) · \(preset.readOperations.count) read permissions · \(preset.writeOperations.count) write permissions").font(.caption)
                if let seat = preset.seat { Label(seat.label, systemImage: "person.crop.rectangle").font(.caption) }
              }
              Spacer()
              Button("Duplicate") { editing = PresetEditTarget(source: preset, duplicate: true) }
              if preset.presetID.hasPrefix("custom-") {
                Button(preset.archived ? "Restore or edit" : "Edit") { editing = PresetEditTarget(source: preset, duplicate: false) }
              }
            }.padding(18).background(Color.primary.opacity(0.035)).cornerRadius(12)
          }
        }
      }
      if let error = library.error { Text(error).foregroundStyle(.red) }
    }.padding(24)
      .sheet(item: $editing) { target in TransferPresetEditor(library: library, source: target.source, duplicate: target.duplicate) }
  }
}

struct TransferPresetEditor: View {
  @ObservedObject var library: TransferPresetLibrary
  let source: CredentialPresetRevision?
  let duplicate: Bool
  @State private var name = ""
  @State private var detail = ""
  @State private var reads = Set(CredentialPresetRevision.allReads)
  @State private var writes: Set<String> = []
  @State private var arenaRead = false
  @State private var linkSeat = false
  @State private var seatClass = PresetSeatAssociation.sharedSeatClassIRI
  @State private var seatType = ""
  @State private var seatLabel = ""
  @State private var archived = false
  @State private var error: String?
  @State private var review: CredentialPresetRevision?
  @State private var newID = "custom-" + UUID().uuidString.lowercased()
  @Environment(\.dismiss) private var dismiss
  var body: some View {
    VStack(spacing: 0) {
      HStack { Text(source == nil || duplicate ? "Create credential preset" : "New preset revision").font(.title2.bold()); Spacer(); Button("Cancel") { dismiss() } }.padding(20)
      Divider()
      ScrollView {
        VStack(alignment: .leading, spacing: 20) {
          if let review {
            Text("Review \(review.name) · revision \(review.revision)").font(.title3.bold())
            Text(review.description)
            Text("Read: " + (review.readOperations.isEmpty ? "None" : review.readOperations.joined(separator: ", ")))
            if review.arenaRead == true { Text("Arena records: list and read · select Arenas during grant setup") }
            Text("Write: " + (review.writeOperations.isEmpty ? "None" : review.writeOperations.map(OwnerPermissionPreset.title).joined(separator: ", ")))
            if let seat = review.seat {
              Text("Seat type: \(seat.label)")
              Text("Class: \(seat.seatClassIRI)\nType: \(seat.seatTypeIRI)").font(.caption.monospaced()).textSelection(.enabled)
            }
            Text(review.archived ? "Archived: unavailable for new selections. Previous revisions remain intact." : "Available for new selections. Existing access stays unchanged.")
            Text("Preset fingerprint: " + review.digest).font(.caption.monospaced()).textSelection(.enabled)
            HStack {
              Button("Back to edit") { self.review = nil }
              Spacer()
              Button("Save preset revision") { save(review) }.buttonStyle(TransferPrimaryButtonStyle())
            }
          } else {
            TextField("Preset name", text: $name)
            TextField("Description", text: $detail)
            HStack {
              Text("Start with")
              ForEach(CredentialPresetRevision.builtins) { preset in
                Button(preset.name) { reads = Set(preset.readOperations); writes = Set(preset.writeOperations) }
              }
            }
            TransferPermissionEditor(reads: $reads, writes: $writes, arenaRead: $arenaRead)
            Divider()
            Toggle("Associate with a shared Seat type", isOn: $linkSeat)
            if linkSeat {
              TextField("Seat type name", text: $seatLabel)
              Text("Shared class: Seat").font(.caption)
              Text(PresetSeatAssociation.sharedSeatClassIRI).font(.caption.monospaced()).foregroundStyle(.secondary).textSelection(.enabled)
              if !library.available.compactMap(\.seat).isEmpty {
                Menu("Use an existing seat-type reference") {
                  ForEach(Array(Set(library.available.compactMap { $0.seat?.seatTypeIRI })).sorted(), id: \.self) { iri in
                    if let seat = library.available.compactMap(\.seat).first(where: { $0.seatTypeIRI == iri }) {
                      Button(seat.label) { seatType = seat.seatTypeIRI; seatLabel = seat.label }
                    }
                  }
                }
              }
              HStack {
                TextField("Seat type IRI", text: $seatType)
                Button("New local type reference") { seatType = "urn:zenith:seat-type:" + UUID().uuidString.lowercased() }
              }
              Text("A Seat is a position in an organization, occupied by a Person or Agent. This recipe references a Seat type using the shared Seat class. Type references are descriptive; a local reference does not register an organization or appointment. Assigning a seat never grants access automatically.").font(.caption).foregroundStyle(.secondary)
            }
            if source != nil && !duplicate { Toggle("Archive this preset for new selections", isOn: $archived) }
            Text("A preset contains permissions only. Holder Wallet, resource paths, expiry and the operator’s approval are chosen separately.").foregroundStyle(.secondary)
            Button("Review preset") { prepare() }.buttonStyle(TransferPrimaryButtonStyle())
          }
          if let error { Text(error).foregroundStyle(.red) }
        }.padding(24)
      }
    }.frame(width: 820, height: 720).onAppear {
      if let source {
        name = source.name + (duplicate ? " copy" : ""); detail = source.description
        reads = Set(source.readOperations); writes = Set(source.writeOperations); arenaRead = source.arenaRead == true
        archived = duplicate ? false : source.archived
        if let seat = source.seat { linkSeat = true; seatClass = seat.seatClassIRI; seatType = seat.seatTypeIRI; seatLabel = seat.label }
      }
    }
  }
  private func prepare() {
    do {
      let seat = try linkSeat ? PresetSeatAssociation(seatClassIRI: seatClass, seatTypeIRI: seatType, label: seatLabel) : nil
      review = try CredentialPresetRevision(presetID: duplicate || source == nil ? newID : source!.presetID,
        revision: duplicate || source == nil ? 1 : source!.revision + 1,
        name: name.trimmingCharacters(in: .whitespacesAndNewlines), description: detail,
        readOperations: CredentialPresetRevision.allReads.filter { reads.contains($0) },
        writeOperations: OwnerPermissionPreset.allOperations.filter { writes.contains($0) }, seat: seat, archived: archived, arenaRead: arenaRead)
      error = nil
    } catch { self.error = (error as? LocalizedError)?.errorDescription ?? "Check the preset settings." }
  }
  private func save(_ value: CredentialPresetRevision) {
    do { try library.save(value, replacing: duplicate ? nil : source); dismiss() }
    catch { self.error = (error as? LocalizedError)?.errorDescription ?? "The revision could not be saved." }
  }
}
#endif
