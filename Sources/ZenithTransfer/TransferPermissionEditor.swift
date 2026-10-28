#if os(macOS)
import SwiftUI
import ZenithKit

/// One permission surface for recipes and individual grants. All bindings use
/// canonical action IDs; only the existing preset adapter uses short Work IDs.
struct TransferPermissionEditor: View {
  @Binding var reads: Set<String>
  @Binding var writes: Set<String>
  @Binding var arenaRead: Bool
  var availableReads = CredentialPresetRevision.allReads
  var availableWrites = Set(OwnerPermissionPreset.allOperations.map { "devgraph.work." + $0 + ".v2" })
  var allowsArenaRead = true
  var arenaExplanation = "Select the specific Arenas when provisioning access. Arena metadata does not grant access to its Work."
  var writesEnabled = true
  var hierarchyScope = false
  var locked = false

  var body: some View {
    VStack(alignment: .leading, spacing: 14) {
      if locked { Label("Requested permissions · fixed", systemImage: "lock").font(.callout) }
      Text("Read permissions").font(.headline)
      ForEach(availableReads, id: \.self) { op in
        if locked {
          readOnlyPermission(WorkReadPermission(rawValue: op)?.title ?? ["children":"Read Work children", "blockers":"Read Work blockers"][op] ?? op, selected: reads.contains(op))
        } else {
        Toggle(isOn: selected(op, set: $reads)) {
          VStack(alignment: .leading, spacing: 3) {
            Text(WorkReadPermission(rawValue: op)?.title ?? ["children":"Read Work children", "blockers":"Read Work blockers"][op] ?? op)
            if let value = WorkReadPermission(rawValue: op) { Text(value.explanation).font(.caption).foregroundStyle(.secondary) }
          }
        }.disabled(locked)
        }
      }
      if locked { readOnlyPermission("List and read Arena records", selected:arenaRead) }
      else { Toggle("List and read Arena records", isOn: $arenaRead).disabled(!allowsArenaRead) }
      Text(arenaExplanation).font(.caption).foregroundStyle(.secondary)
      Label(WorkReadPermission.arenaAvailability, systemImage: "info.circle").font(.caption).foregroundStyle(.secondary)
      Text("Write permissions").font(.headline)
      let actions = DevGraphPermissionCatalog.writes.filter { availableWrites.contains($0.id) }
      if actions.isEmpty { Text("No write actions are available in this configuration.").foregroundStyle(.secondary) }
      ForEach(actions.filter { $0.id == "devgraph.work.patch.v2" }) { actionToggle($0) }
      let other = actions.filter { $0.id != "devgraph.work.patch.v2" }
      if !other.isEmpty {
        DisclosureGroup("Other write actions · \(other.filter { writes.contains($0.id) }.count) selected") {
          VStack(alignment: .leading, spacing: 12) { ForEach(other) { actionToggle($0) } }.padding(.top, 8)
        }
      }
    }
  }
  @ViewBuilder private func actionToggle(_ action: DevGraphPermissionCatalog.Action) -> some View {
    if locked {
      readOnlyPermission(action.title == "Edit Work" ? "Edit details" : action.title, selected:writes.contains(action.id))
    } else {
    Toggle(isOn: selected(action.id, set: $writes)) {
      VStack(alignment: .leading, spacing: 3) {
        Text(action.title == "Edit Work" ? "Edit details" : action.title)
        Text(action.explanation).font(.caption).foregroundStyle(.secondary)
        if hierarchyScope && !action.hierarchy { Text("Requires exact resources or explicit all-permitted coverage.").font(.caption).foregroundStyle(.secondary) }
      }
    }.disabled(locked || !writesEnabled || hierarchyScope && !action.hierarchy && !writes.contains(action.id))
    }
  }
  private func readOnlyPermission(_ title: String, selected: Bool) -> some View {
    HStack {
      Image(systemName: selected ? "checkmark.circle.fill" : "circle")
      Text(title)
      Spacer()
      Text(selected ? "Requested" : "Not requested").font(.caption).foregroundStyle(.secondary)
    }.accessibilityElement(children:.combine)
  }
  private func selected(_ value: String, set: Binding<Set<String>>) -> Binding<Bool> {
    Binding(get: { set.wrappedValue.contains(value) }, set: { enabled in
      guard !locked else { return }
      if enabled { set.wrappedValue.insert(value) } else { set.wrappedValue.remove(value) }
    })
  }
}

enum TransferPresetPermissionAdapter {
  static let supportedWrites = Set(OwnerPermissionPreset.allOperations.map { "devgraph.work." + $0 + ".v2" })
  static func canonical(_ operations: [String]) -> Set<String> { Set(operations.map { "devgraph.work." + $0 + ".v2" }) }
  static func stored(_ actions: Set<String>) throws -> [String] {
    guard actions.isSubset(of: supportedWrites) else { throw CredentialPresetError.invalid }
    return OwnerPermissionPreset.allOperations.filter { actions.contains("devgraph.work." + $0 + ".v2") }
  }
}
#endif
