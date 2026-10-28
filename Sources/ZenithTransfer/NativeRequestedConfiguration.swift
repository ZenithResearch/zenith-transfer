#if os(macOS)
import Foundation
import ZenithKit

enum NativeRequestedConfigurationError: LocalizedError {
  case changed, unsupported, unrepresentable
  var errorDescription: String? {
    switch self {
    case .changed: return "The requested preset or catalog changed. Ask for a revised request; no requested field was replaced."
    case .unsupported: return "This request cannot be represented safely by this editor. Ask for a revised request; no permissions were substituted."
    case .unrepresentable: return "The exact requested fields are unavailable under the current policy or selection. Ask for a revised request."
    }
  }
}

/// UI constraints over the existing v2 preference, never a new authority or wire
/// contract. Missing preset/path fields remain unspecified, never global.
struct NativeRequestedConfiguration {
  let preset: WorkAccessPreset?
  let paths: [WorkResourcePath]?
  let reference: [String: Any]?
  var locksPermissions: Bool { preset != nil }
  var locksScope: Bool { paths != nil }
  var hasRequestedFields: Bool { locksPermissions || locksScope }

  init(recipient: NativeGrantRecipient, inbox: NativeOperatorInbox) throws {
    guard let intent = recipient.raw["intent"], !(intent is NSNull) else {
      preset = nil; paths = nil; reference = nil; return
    }
    guard let value = intent as? [String: Any], Set(value.keys).isSubset(of: ["schema", "preference", "read_grants", "write_grants"]),
      value["schema"] as? String == "devgraph.access-intent.v2",
      let preference = value["preference"] as? [String: Any],
      Set(preference.keys).isSubset(of: ["id", "version", "catalog_digest_sha256", "resource_paths"]),
      let digest = preference["catalog_digest_sha256"] as? String, GrantJSON.hex(digest, 64),
      let catalog = inbox.catalog else { throw NativeRequestedConfigurationError.unsupported }
    // PresetIntent inherits the empty v1 arrays. Some valid producers encode
    // those defaults explicitly; nonempty arrays are not a preset preference.
    for key in ["read_grants", "write_grants"] where value[key] != nil {
      guard let rows = value[key] as? [Any], rows.isEmpty else { throw NativeRequestedConfigurationError.unsupported }
    }
    guard digest == catalog.catalog_digest_sha256 else { throw NativeRequestedConfigurationError.changed }
    let id = preference["id"]
    let version = preference["version"]
    if id == nil || id is NSNull {
      guard version == nil || version is NSNull else { throw NativeRequestedConfigurationError.unsupported }
      preset = nil; reference = nil
    } else {
      guard let identifier = id as? String, let revision = GrantJSON.integer(version), revision > 0,
        let matched = catalog.presets.first(where: { $0.id == identifier && $0.version == UInt64(revision) })
      else { throw NativeRequestedConfigurationError.changed }
      guard Set(matched.read_operations).isSubset(of: inbox.permissions.reads),
        !matched.read_operations.isEmpty || !matched.write_operations.isEmpty,
        Set(matched.write_operations).isSubset(of: inbox.permissions.writes),
        Set(matched.write_operations).isSubset(of: Set(DevGraphPermissionCatalog.writes.map(\.id))),
        matched.write_operations.isEmpty || inbox.activation["write"] as? Bool != false,
        matched.read_operations.isEmpty || matched.write_operations.isEmpty || inbox.activation["mixed"] as? Bool != false
      else { throw NativeRequestedConfigurationError.unrepresentable }
      preset = matched
      reference = ["id": matched.id, "version": matched.version, "catalog_digest_sha256": digest]
    }
    if let raw = preference["resource_paths"] {
      guard !(raw is NSNull) else { throw NativeRequestedConfigurationError.unsupported }
      guard try GrantJSON.rows(raw).allSatisfy({ Set($0.keys) == ["schema", "path"] }) else { throw NativeRequestedConfigurationError.unsupported }
      let decoded = try JSONDecoder().decode([WorkResourcePath].self, from: GrantJSON.data(raw))
      guard decoded.count <= 16, Set(decoded).count == decoded.count,
        decoded.allSatisfy({ path in catalog.scopes.contains(where: { $0.resource_path == path }) })
      else { throw NativeRequestedConfigurationError.unrepresentable }
      // Keep the exact requested paths. Do not silently normalize a redundant
      // request or pretend missing catalog branches are an all-resource scope.
      guard try Set(WorkScopeSelection.normalized(decoded)) == Set(decoded),
        (decoded.isEmpty || preset?.write_operations.allSatisfy({ id in DevGraphPermissionCatalog.writes.first(where: { $0.id == id })?.hierarchy == true }) != false)
      else { throw NativeRequestedConfigurationError.unrepresentable }
      paths = decoded.isEmpty ? nil : decoded
    } else { paths = nil }
  }

  func validate(_ rules: [NativeGrantChoice]) throws {
    guard hasRequestedFields else { return }
    guard !rules.isEmpty else { throw NativeRequestedConfigurationError.unrepresentable }
    for choice in rules {
      if let preset {
        guard choice.reads == Set(preset.read_operations), choice.writes == Set(preset.write_operations),
          choice.arenaIDs.isEmpty, !choice.allArenas else { throw NativeRequestedConfigurationError.unrepresentable }
      }
      if let paths {
        guard !choice.wholeGraph, choice.exactResources == nil, !choice.paths.isEmpty,
          Set(choice.paths).isSubset(of:Set(paths)) else { throw NativeRequestedConfigurationError.unrepresentable }
      }
    }
    if let paths { guard Set(rules.flatMap(\.paths)) == Set(paths) else { throw NativeRequestedConfigurationError.unrepresentable } }
  }

  func validateCompiled(_ selection: [String: Any]) throws {
    guard let paths else { return }
    var covered: Set<WorkResourcePath> = []
    for side in ["read", "write"] {
      guard let value = selection[side] as? [String: Any] else { continue }
      for grant in try GrantJSON.rows(value[side + "_grants"]) {
        if grant["scope"] as? String == "devgraph.arena.read" { continue }
        let actual = try NativeGrantSelection.paths(grant)
        guard !actual.isEmpty, Set(actual).isSubset(of:Set(paths)) else { throw NativeRequestedConfigurationError.unrepresentable }
        covered.formUnion(actual)
      }
    }
    guard covered == Set(paths) else { throw NativeRequestedConfigurationError.unrepresentable }
  }
}
#endif
