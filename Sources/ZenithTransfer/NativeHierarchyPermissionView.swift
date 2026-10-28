#if os(macOS)
import SwiftUI
import ZenithKit

struct NativeHierarchyPermissionView: View {
  @ObservedObject var editor: NativeCredentialModel
  let inbox: NativeOperatorInbox
  let serviceName: String
  var body: some View {
    VStack(alignment: .leading, spacing: 14) {
      Text("Choose access by resource").font(.headline)
      Text("Expand an Arena, Initiative or Project and choose Read, Write, or both. Access includes that branch’s current and future Work descendants; it does not include sibling branches.")
        .font(.callout).foregroundStyle(.secondary)
      HStack {
        Label(serviceName, systemImage: "server.rack").font(.headline)
        Spacer()
        Text("Read").frame(width: 72)
        Text("Write").frame(width: 72)
      }
      Divider()
      ForEach(WorkScopeSelection.tree(inbox.scopes)) { hierarchyRow($0, depth: 0) }
      if inbox.scopes.isEmpty { Text("No verified resource branches are available. Refresh the request context or use advanced rules for exact IDs.").foregroundStyle(.secondary) }
      Text("Read: view and browse Work. Selecting an Arena also reads that Arena record. Write: edit Work details. Use advanced rules for creation, progress, moves, reviews and other actions.")
        .font(.caption).foregroundStyle(.secondary)
      Text("A check inherited from a parent is labelled below the resource. Remove it at that parent to narrow access.")
        .font(.caption).foregroundStyle(.secondary)
      if inbox.activation["write"] as? Bool == false { Text("This server has not enabled write credential issuance.").font(.caption).foregroundStyle(.secondary) }
      else if inbox.activation["mixed"] as? Bool == false { Text("This server requires separate read and write credentials.").font(.caption).foregroundStyle(.secondary) }
      Text("\(editor.hierarchy.readPaths.count) read branches · \(editor.hierarchy.writePaths.count) write branches")
        .font(.caption).foregroundStyle(.secondary)
    }
  }
  private func hierarchyRow(_ row: WorkScopeTreeNode, depth: Int) -> AnyView {
    let path = row.option.resource_path
    let inheritedRead = editor.hierarchy.inherited(path, .read)
    let inheritedWrite = editor.hierarchy.inherited(path, .write)
    return AnyView(VStack(alignment: .leading, spacing: 10) {
      HStack(spacing: 8) {
        HStack(spacing: 8) {
          if row.children != nil {
            Button { if editor.expanded.contains(row.id) { editor.expanded.remove(row.id) } else { editor.expanded.insert(row.id) } } label: {
              Image(systemName: editor.expanded.contains(row.id) ? "chevron.down" : "chevron.right").frame(width: 16, height: 24)
            }.buttonStyle(.plain).accessibilityLabel((editor.expanded.contains(row.id) ? "Collapse " : "Expand ") + row.option.title)
          } else { Color.clear.frame(width: 16, height: 24) }
          VStack(alignment: .leading, spacing: 3) {
            Text(row.option.title)
            Text(row.option.kind + (inheritedRead || inheritedWrite ? " · Inherited " + [inheritedRead ? "Read" : nil, inheritedWrite ? "Write" : nil].compactMap { $0 }.joined(separator: " and ") : ""))
              .font(.caption).foregroundStyle(.secondary)
          }
        }.padding(.leading, CGFloat(depth * 22))
        Spacer(minLength: 12)
        hierarchyToggle(row.option, access: .read).frame(width: 72)
        hierarchyToggle(row.option, access: .write).frame(width: 72)
      }
      if editor.expanded.contains(row.id), let children = row.children { ForEach(children) { hierarchyRow($0, depth: depth + 1) } }
    })
  }
  private func hierarchyToggle(_ row: WorkScopeOption, access: NativeHierarchyPermissions.Access) -> some View {
    let selected = editor.hierarchy.includes(row.resource_path, access)
    let inherited = editor.hierarchy.inherited(row.resource_path, access)
    let available = selected || editor.hierarchyAvailable(row, access: access)
    let name = access == .read ? "Read" : "Write"
    return Toggle(name, isOn: Binding(get: { selected }, set: { editor.setHierarchy(row, access: access, enabled: $0) }))
      .labelsHidden().toggleStyle(.checkbox)
      .accessibilityLabel(name + " " + row.title)
      .accessibilityValue(inherited ? "Inherited from parent" : selected ? "Selected" : available ? "Not selected" : "Unavailable under server policy")
      .help(inherited ? "Included by a parent. Change its selection to narrow access." : available ? name + " on this branch and its Work descendants" : "The server policy does not allow this selection.")
      .disabled(inherited || !available)
  }
}
#endif
