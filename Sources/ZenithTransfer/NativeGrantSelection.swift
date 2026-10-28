#if os(macOS)
import CryptoKit
import CoreFoundation
import Foundation
import ZenithKit

// Wire contracts stay unchanged. The Swift editor creates the exact same
// selections as the established operator client; no delegation fields exist.
enum NativeGrantError: LocalizedError {
  case invalid, scope, applicability, permissions, changed, recovery, expired, denied, busy
  var errorDescription: String? {
    switch self {
    case .invalid: return "This server response or credential selection is unsupported. Nothing new was issued."
    case .scope: return "Each rule needs a scope. Choose hierarchy branches, exact IDs for every checked resource kind, or explicitly all permitted resources."
    case .applicability: return "A selected action cannot use this rule’s hierarchy. Use another rule with exact resource IDs or explicitly all permitted resources."
    case .permissions: return "Select permissions available for this request. The current server cannot issue that selection."
    case .changed: return "The request, policy or assignment changed. Reload the inbox and review again."
    case .recovery: return "The original result is uncertain. Check its status before preparing another decision."
    case .expired: return "This approval expired. Refresh it to review the same decision."
    case .denied: return "The server refused this action. Check your Wallet authority and the selected scope."
    case .busy: return "Finish or cancel the prepared action first."
    }
  }
}

/// Only a local rule number and closed diagnostic are exposed; no server text.
struct NativeGrantRuleError: LocalizedError {
  let index: Int
  let cause: NativeGrantError
  var errorDescription: String? { "Rule \(index + 1): " + (cause.errorDescription ?? "Check this selection.") }
}

enum GrantJSON {
  static func data(_ value: Any) throws -> Data {
    try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys, .withoutEscapingSlashes, .fragmentsAllowed])
  }
  static func object(_ data: Data) throws -> [String: Any] {
    var reader = GrantJSONReader(data); try reader.validate()
    guard let result = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw NativeGrantError.invalid }
    return result
  }
  static func equal(_ a: Any?, _ b: Any?) -> Bool {
    guard let a, let b, let x = try? data(a), let y = try? data(b) else { return false }; return x == y
  }
  static func digest(_ value: Any) throws -> String { SHA256.hash(data: try data(value)).map { String(format: "%02x", $0) }.joined() }
  static func hex(_ value: Any?, _ count: Int) -> Bool {
    (value as? String)?.range(of: "^[a-f0-9]{\(count)}$", options: .regularExpression) != nil
  }
  static func integer(_ value: Any?) -> Int? {
    guard let n = value as? NSNumber, CFGetTypeID(n) != CFBooleanGetTypeID(),
      !["d", "f"].contains(String(cString: n.objCType)), n.int64Value >= 0,
      n.int64Value <= 9_007_199_254_740_991 else { return nil }; return n.intValue
  }
  static func bool(_ value: Any?) -> Bool? {
    guard let n = value as? NSNumber, CFGetTypeID(n) == CFBooleanGetTypeID() else { return nil }; return n.boolValue
  }
  static func strings(_ value: Any?) throws -> [String] {
    guard let a = value as? [String], a.count <= 256, Set(a).count == a.count else { throw NativeGrantError.invalid }; return a
  }
  static func rows(_ value: Any?) throws -> [[String: Any]] {
    guard let rows = value as? [[String: Any]], rows.count <= 2000 else { throw NativeGrantError.invalid }; return rows
  }
}

/// Bound raw protocol JSON before Foundation collapses duplicate/escaped keys.
private struct GrantJSONReader {
  let bytes: [UInt8]; var cursor = 0
  init(_ data: Data) { bytes = Array(data) }
  mutating func space() { while cursor < bytes.count && [9,10,13,32].contains(bytes[cursor]) { cursor += 1 } }
  mutating func take(_ byte: UInt8) throws {
    space(); guard cursor < bytes.count, bytes[cursor] == byte else { throw NativeGrantError.invalid }; cursor += 1
  }
  mutating func string() throws -> String {
    space(); let start = cursor; try take(34); var escaped = false
    while cursor < bytes.count {
      let b = bytes[cursor]; cursor += 1
      if escaped { escaped = false; continue }; if b == 92 { escaped = true; continue }
      if b == 34 { return try JSONDecoder().decode(String.self, from: Data(bytes[start..<cursor])) }
    }
    throw NativeGrantError.invalid
  }
  mutating func value(_ depth: Int) throws {
    space(); guard depth <= 20, cursor < bytes.count else { throw NativeGrantError.invalid }
    switch bytes[cursor] {
    case 34: _ = try string()
    case 123:
      try take(123); space(); var keys: Set<String> = []
      if cursor < bytes.count && bytes[cursor] == 125 { cursor += 1; return }
      while true {
        guard keys.insert(try string()).inserted, keys.count <= 128 else { throw NativeGrantError.invalid }
        try take(58); try value(depth + 1); space(); guard cursor < bytes.count else { throw NativeGrantError.invalid }
        if bytes[cursor] == 125 { cursor += 1; break }; try take(44)
      }
    case 91:
      try take(91); space(); var count = 0
      if cursor < bytes.count && bytes[cursor] == 93 { cursor += 1; return }
      while true {
        count += 1; guard count <= 2048 else { throw NativeGrantError.invalid }
        try value(depth + 1); space(); guard cursor < bytes.count else { throw NativeGrantError.invalid }
        if bytes[cursor] == 93 { cursor += 1; break }; try take(44)
      }
    default:
      for literal in ["true", "false", "null"] {
        if bytes[cursor...].starts(with: Array(literal.utf8)) { cursor += literal.utf8.count; return }
      }
      let start = cursor
      while cursor < bytes.count && (48...57).contains(bytes[cursor]) { cursor += 1 }
      guard cursor > start, cursor - start == 1 || bytes[start] != 48,
        let n = UInt64(String(decoding: bytes[start..<cursor], as: UTF8.self)), n <= 9_007_199_254_740_991 else { throw NativeGrantError.invalid }
    }
  }
  mutating func validate() throws {
    guard !bytes.isEmpty, bytes.count <= 1_048_576 else { throw NativeGrantError.invalid }
    try value(0); space(); guard cursor == bytes.count else { throw NativeGrantError.invalid }
  }
}

struct NativeGrantRecipient: Identifiable {
  let raw: [String: Any]
  let id: String
  let subject: String
  let installation: String
  let version: Int
  let digest: String
  init(_ raw: [String: Any]) throws {
    guard GrantJSON.hex(raw["request_id"], 32), GrantJSON.hex(raw["subject_public_key"], 64),
      GrantJSON.hex(raw["installation_id"], 32), GrantJSON.hex(raw["request_digest_sha256"], 64),
      let version = GrantJSON.integer(raw["version"]), version > 0 else { throw NativeGrantError.invalid }
    self.raw = raw; id = raw["request_id"] as! String; subject = raw["subject_public_key"] as! String
    installation = raw["installation_id"] as! String; digest = raw["request_digest_sha256"] as! String; self.version = version
  }
}

struct NativeGrantPermissions {
  let reads: [String]
  let arenaIDs: [String]
  let allArenas: Bool
  let writes: [String]
  let kinds: [String]
  let validity: GrantValidity
  let supportsPaths: Bool
  init(_ ceiling: [String: Any], currentArenaIDs: [String] = []) throws {
    let schema = ceiling["schema"] as? String ?? ""
    guard ["devgraph.access-draft.v2", "devgraph.access-draft.v3", "devgraph.access-draft.v4", "devgraph.access-draft.v5", "devgraph.access-draft.v6", "devgraph.access-draft.v7", "devgraph.access-draft.v8"].contains(schema) else { throw NativeGrantError.invalid }
    supportsPaths = ["devgraph.access-draft.v4", "devgraph.access-draft.v5", "devgraph.access-draft.v6", "devgraph.access-draft.v7", "devgraph.access-draft.v8"].contains(schema)
    if ["devgraph.access-draft.v5", "devgraph.access-draft.v6", "devgraph.access-draft.v7", "devgraph.access-draft.v8"].contains(schema) { validity = try GrantValidity.decode(GrantJSON.data(ceiling["validity"] as Any)) }
    else {
      guard let start = GrantJSON.integer(ceiling["not_before"]), let end = GrantJSON.integer(ceiling["not_after"]) else { throw NativeGrantError.invalid }
      validity = try GrantValidity.decode(GrantJSON.data(["schema": GrantValidity.schema, "mode": "dated", "not_before": start, "not_after": end]))
    }
    let read = try GrantJSON.rows(ceiling["read_grants"] ?? [[String: Any]]())
    let write = try GrantJSON.rows(ceiling["write_grants"] ?? [[String: Any]]())
    // New authority-bearing fields require an explicit reader upgrade. In
    // particular, do not carry a future delegation flag through a cloned rule.
    let readFields: Set<String> = ["schema", "scope", "operations", "relationship_types", "work_kinds", "work_ids", "arena_ids", "include_archived", "resource_paths"]
    let writeFields: Set<String> = ["schema", "operation", "resources", "arena_ids", "resource_paths"]
    for grant in read {
      if grant["scope"] as? String == "devgraph.arena.read" {
        if ["devgraph.access-draft.v7", "devgraph.access-draft.v8"].contains(schema), Set(grant.keys) == ["scope", "all_arenas"], grant["all_arenas"] as? Bool == true { continue }
        guard ["devgraph.access-draft.v6", "devgraph.access-draft.v7", "devgraph.access-draft.v8"].contains(schema), Set(grant.keys) == ["scope", "arena_ids"] else { throw NativeGrantError.invalid }
        let ids = try GrantJSON.strings(grant["arena_ids"])
        guard !ids.isEmpty, ids.count <= 256, ids.allSatisfy({ $0.range(of: "^[a-z0-9][a-z0-9-]{0,255}$", options: .regularExpression) != nil }) else { throw NativeGrantError.invalid }
        continue
      }
      guard Set(grant.keys).isSubset(of: readFields), grant["scope"] as? String == "devgraph.work.read",
        GrantJSON.bool(grant["include_archived"]) != nil else { throw NativeGrantError.invalid }
      _ = try GrantJSON.strings(grant["relationship_types"])
      _ = try NativeGrantSelection.paths(grant)
    }
    for grant in write {
      guard Set(grant.keys).isSubset(of: writeFields) else { throw NativeGrantError.invalid }
      for row in try GrantJSON.rows(grant["resources"]) {
        guard Set(row.keys).isSubset(of: ["kind", "ids"]), row["kind"] is String else { throw NativeGrantError.invalid }
        if let ids = row["ids"] { guard !(try GrantJSON.strings(ids)).isEmpty else { throw NativeGrantError.invalid } }
      }
      _ = try NativeGrantSelection.paths(grant)
    }
    let workRead = read.filter { $0["scope"] as? String == "devgraph.work.read" }
    allArenas = read.contains { $0["scope"] as? String == "devgraph.arena.read" && $0["all_arenas"] as? Bool == true }
    arenaIDs = Array(Set(try read.filter { $0["scope"] as? String == "devgraph.arena.read" }.flatMap { ($0["all_arenas"] as? Bool == true ? currentArenaIDs : try GrantJSON.strings($0["arena_ids"])) })).sorted()
    reads = Array(Set(try workRead.flatMap { try GrantJSON.strings($0["operations"]) })).sorted()
    writes = Array(Set(write.compactMap { $0["operation"] as? String })).sorted()
    kinds = Array(Set(try workRead.flatMap { try GrantJSON.strings($0["work_kinds"]) } + write.flatMap { ($0["resources"] as? [[String: Any]] ?? []).compactMap { $0["kind"] as? String } } + (read.contains { $0["scope"] as? String == "devgraph.arena.read" } ? ["Arena"] : []))).sorted()
    let allowed = Set(CredentialPresetRevision.allReads + ["children", "blockers"])
    let allowedWrites = Set(DevGraphPermissionCatalog.writes.map(\.id))
    guard Set(reads).isSubset(of: allowed), Set(writes).isSubset(of: allowedWrites) else { throw NativeGrantError.invalid }
  }
}

struct NativeGrantChoice: Equatable {
  var arenaIDs: Set<String> = []
  var allArenas = false
  var reads: Set<String> = []
  var writes: Set<String> = []
  var kinds: Set<String> = []
  /// Exact IDs are an alternative to hierarchy coverage, never an implicit wildcard.
  var exactResources: [String: Set<String>]? = nil
  var wholeGraph = false
  var paths: [WorkResourcePath] = []
  var untilRevoked = true
  var expiry = Date().addingTimeInterval(30 * 86400)
  // No mutable onward-delegation flag: current contracts only issue leaf grants.
}

enum NativeGrantSelection {
  /// Arena metadata follows the same selected hierarchy as Work. A standalone
  /// Initiative/Project path does not imply authority to read an unknown Arena.
  static func arenaCoverage(_ choice: NativeGrantChoice, available: [String]) -> Set<String> {
    if let exact = choice.exactResources { return Set(available).intersection(exact["Arena"] ?? []) }
    if choice.wholeGraph && choice.paths.isEmpty { return Set(available) }
    guard !choice.wholeGraph, !choice.paths.isEmpty else { return [] }
    let anchors = Set(choice.paths.flatMap(\.path).filter { $0.hasPrefix("Arena/") }.map { String($0.dropFirst(6)) })
    return Set(available).intersection(anchors)
  }
  static func narrow(_ parent: [WorkResourcePath], _ child: [WorkResourcePath]) throws -> [WorkResourcePath] {
    if parent.isEmpty { return child }; if child.isEmpty { return parent }
    var result: [WorkResourcePath] = []
    for a in parent { for b in child {
      var map = Dictionary(uniqueKeysWithValues: a.path.map { value -> (String, String) in let s = value.split(separator: "/"); return (String(s[0]), String(s[1])) })
      var matches = true
      for value in b.path {
        let s = value.split(separator: "/"), key = String(s[0]), id = String(s[1])
        if let old = map[key], old != id { matches = false; break }; map[key] = id
      }
      if matches {
        let path = try WorkResourcePath(path: ["Arena", "Initiative", "Project"].compactMap { kind in map[kind].map { kind + "/" + $0 } })
        if !result.contains(path) { result.append(path) }
      }
    }}
    return result.sorted { $0.path.lexicographicallyPrecedes($1.path) }
  }
  static func paths(_ grant: [String: Any]) throws -> [WorkResourcePath] {
    guard let raw = grant["resource_paths"] else { return [] }
    let paths = try JSONDecoder().decode([WorkResourcePath].self, from: GrantJSON.data(raw))
    guard !paths.isEmpty, paths.count <= 16 else { throw NativeGrantError.invalid }
    for p in paths { try p.validate() }; return paths
  }
  /// Compile each rule independently against its original parent rows. Never
  /// combine an action union with a scope union. Existing signed wire shapes
  /// and Wallet Core's secS holder-grant verifier remain unchanged.
  static func makeRules(ceiling: [String: Any], ceilingDigest: String, recipient: NativeGrantRecipient,
    rules: [NativeGrantChoice], scopes: [WorkScopeOption], preset: [String: Any]? = nil, now: Int) throws -> [String: Any] {
    guard !rules.isEmpty, rules.count <= 16, let first = rules.first,
      rules.allSatisfy({ $0.untilRevoked == first.untilRevoked && (first.untilRevoked || $0.expiry == first.expiry) }) else { throw NativeGrantError.permissions }
    var result: [String: Any] = [:]
    for (index, rule) in rules.enumerated() {
      // The legacy single-rule compiler retained a historical omission of
      // path-bound creation. New rule editing must report it, never omit it.
      if !rule.paths.isEmpty && rule.writes.contains(where: { id in
        DevGraphPermissionCatalog.writes.contains { $0.id == id && !$0.hierarchy }
      }) { throw NativeGrantRuleError(index: index, cause: .applicability) }
      let compiled: [String: Any]
      do {
        compiled = try make(ceiling: ceiling, ceilingDigest: ceilingDigest, recipient: recipient,
          choice: rule, scopes: scopes, preset: rules.count == 1 ? preset : nil, now: now)
      } catch let cause as NativeGrantError { throw NativeGrantRuleError(index: index, cause: cause) }
      let emitted = Set(((compiled["write"] as? [String: Any])?["write_grants"] as? [[String: Any]] ?? []).compactMap { $0["operation"] as? String })
      let readRows = (compiled["read"] as? [String: Any])?["read_grants"] as? [[String: Any]] ?? []
      let emittedReads = Set(readRows.flatMap { $0["operations"] as? [String] ?? [] })
      let emittedArenas = Set(readRows.flatMap { $0["arena_ids"] as? [String] ?? [] })
      let emittedAll = readRows.contains { $0["scope"] as? String == "devgraph.arena.read" && $0["all_arenas"] as? Bool == true }
      guard emitted == rule.writes, emittedReads == rule.reads, emittedArenas == rule.arenaIDs, emittedAll == rule.allArenas else { throw NativeGrantRuleError(index: index, cause: .permissions) }
      for side in ["read", "write"] {
        guard var draft = compiled[side] as? [String: Any] else { continue }
        let field = side + "_grants"
        var grants = (result[side] as? [String: Any])?[field] as? [[String: Any]] ?? []
        for grant in try GrantJSON.rows(draft[field]) where !grants.contains(where: { GrantJSON.equal($0, grant) }) { grants.append(grant) }
        guard grants.count <= (side == "read" ? 16 : 64) else { throw NativeGrantError.permissions }
        if side == "read" {
          let operations = grants.reduce(0) { $0 + (($1["scope"] as? String == "devgraph.arena.read") ? 2 : ($1["operations"] as? [String] ?? []).count) }
          guard operations <= 32 else { throw NativeGrantError.permissions }
        }
        if side == "read", grants.contains(where: { $0["scope"] as? String == "devgraph.arena.read" && $0["all_arenas"] as? Bool == true }) {
          draft["schema"] = "devgraph.access-draft.v8"
        }
        draft[field] = grants; result[side] = draft
      }
    }
    guard try GrantJSON.data(result).count <= 262144 else { throw NativeGrantError.permissions }
    return result
  }
  static func make(ceiling: [String: Any], ceilingDigest: String, recipient: NativeGrantRecipient,
    choice: NativeGrantChoice, scopes: [WorkScopeOption], preset: [String: Any]? = nil, now: Int) throws -> [String: Any] {
    let available = try NativeGrantPermissions(ceiling, currentArenaIDs: scopes.filter { $0.resource_path.path.count == 1 && $0.resource_path.path[0].hasPrefix("Arena/") }.map { String($0.resource_path.path[0].dropFirst(6)) })
    let allowedFields: Set<String> = ["schema", "issuer", "receiver", "write_audience", "subject_public_key", "installation_id", "not_before", "not_after", "validity", "lifetime_seconds", "read_grants", "write_grants", "previous_digest", "preset"]
    guard Set(ceiling.keys).isSubset(of: allowedFields), GrantJSON.hex(ceilingDigest, 64), now >= 0,
      available.validity.contains(UInt64(now)),
      Set(choice.reads).isSubset(of: Set(available.reads)), Set(choice.writes).isSubset(of: Set(available.writes)),
      Set(choice.kinds).isSubset(of: Set(available.kinds)),
      choice.reads.isEmpty && choice.writes.isEmpty || !choice.kinds.isEmpty,
      !choice.allArenas || available.allArenas && choice.arenaIDs.isEmpty && choice.wholeGraph && choice.paths.isEmpty && choice.exactResources == nil,
      Set(choice.arenaIDs).isSubset(of: Set(available.arenaIDs)),
      choice.arenaIDs.count <= 256,
      Set(choice.arenaIDs).isSubset(of: arenaCoverage(choice, available: available.arenaIDs)),
      !choice.reads.isEmpty || !choice.writes.isEmpty || !choice.arenaIDs.isEmpty || choice.allArenas else { throw NativeGrantError.permissions }
    if let exact = choice.exactResources {
      guard !choice.wholeGraph, choice.paths.isEmpty, !exact.isEmpty, exact.count <= 11,
        Set(exact.keys) == choice.kinds,
        exact.values.allSatisfy({ !$0.isEmpty && $0.count <= 256 && $0.allSatisfy { $0.range(of: "^[a-z0-9][a-z0-9-]{0,255}$", options: .regularExpression) != nil } }) else { throw NativeGrantError.scope }
    } else {
      guard choice.wholeGraph ? choice.paths.isEmpty : !choice.paths.isEmpty else { throw NativeGrantError.scope }
    }
    let selectedPaths = try WorkScopeSelection.normalized(choice.paths)
    guard selectedPaths.allSatisfy({ p in scopes.contains { $0.resource_path == p } }), selectedPaths.isEmpty || available.supportsPaths else { throw NativeGrantError.scope }
    if let subject = ceiling["subject_public_key"] as? String, subject != recipient.subject { throw NativeGrantError.permissions }
    let end: UInt64?
    if choice.untilRevoked {
      guard available.validity.notAfter == nil, ["devgraph.access-draft.v5", "devgraph.access-draft.v6", "devgraph.access-draft.v7", "devgraph.access-draft.v8"].contains(ceiling["schema"] as? String ?? "") else { throw NativeGrantError.permissions }; end = nil
    } else {
      let t = choice.expiry.timeIntervalSince1970
      guard t.isFinite, t > Double(now), t <= 9_007_199_254_740_991,
        available.validity.notAfter.map({ t <= Double($0) }) ?? true else { throw NativeGrantError.permissions }; end = UInt64(t)
    }
    var base = ceiling
    if ["devgraph.access-draft.v7", "devgraph.access-draft.v8"].contains(base["schema"] as? String ?? "") { base["schema"] = "devgraph.access-draft.v6" }
    base["subject_public_key"] = recipient.subject; base["previous_digest"] = ceilingDigest
    base.removeValue(forKey: "preset"); if let preset, choice.arenaIDs.isEmpty && !choice.allArenas { base["preset"] = preset }
    if ["devgraph.access-draft.v5", "devgraph.access-draft.v6", "devgraph.access-draft.v7", "devgraph.access-draft.v8"].contains(ceiling["schema"] as? String ?? "") {
      var validity: [String: Any] = ["schema": GrantValidity.schema, "mode": end == nil ? "until_revoked" : "dated", "not_before": now]
      if let end { validity["not_after"] = end }; base["validity"] = validity
    } else { base["not_before"] = now; base["not_after"] = end }
    func constrain(_ value: [String: Any]) throws -> [String: Any]? {
      var grant = value; let parent = try paths(grant), narrowed = try narrow(parent, selectedPaths)
      if (!parent.isEmpty || !selectedPaths.isEmpty) && narrowed.isEmpty { return nil }
      if !narrowed.isEmpty {
        grant["resource_paths"] = try JSONSerialization.jsonObject(with: JSONEncoder().encode(narrowed))
        grant["schema"] = grant["operations"] != nil ? "devgraph.path-read-grant.v1" : "devgraph.path-write-grant.v1"
      }
      return grant
    }
    var result: [String: Any] = [:]
    if !choice.reads.isEmpty || !choice.arenaIDs.isEmpty || choice.allArenas {
      var read = base; if choice.allArenas { read["schema"] = "devgraph.access-draft.v8" }; read.removeValue(forKey: "write_grants"); read["installation_id"] = recipient.installation
      if !available.supportsPaths { read["schema"] = "devgraph.access-draft.v2" }
      let grants = try GrantJSON.rows(ceiling["read_grants"] ?? [[String: Any]]()).compactMap { raw -> [String: Any]? in
        if raw["scope"] as? String == "devgraph.arena.read" {
          if choice.allArenas {
            return raw["all_arenas"] as? Bool == true ? ["scope": "devgraph.arena.read", "all_arenas": true] : nil
          }
          let ids = raw["all_arenas"] as? Bool == true ? choice.arenaIDs.sorted() : try GrantJSON.strings(raw["arena_ids"]).filter { choice.arenaIDs.contains($0) }
          return ids.isEmpty ? nil : ["scope": "devgraph.arena.read", "arena_ids": ids]
        }
        var g = raw
        g["operations"] = try GrantJSON.strings(raw["operations"]).filter { choice.reads.contains($0) }
        g["work_kinds"] = try GrantJSON.strings(raw["work_kinds"]).filter { choice.kinds.contains($0) }
        if (g["operations"] as! [String]).isEmpty || (g["work_kinds"] as! [String]).isEmpty { return nil }
        if let exact = choice.exactResources {
          let selectedKinds = Set(g["work_kinds"] as! [String])
          let selectedIDs = exact.filter { selectedKinds.contains($0.key) }.flatMap { kind, ids in ids.map { kind + "/" + $0 } }.sorted()
          g["work_ids"] = try raw["work_ids"].map { ids in try GrantJSON.strings(ids).filter { selectedIDs.contains($0) } } ?? selectedIDs
          if (g["work_ids"] as! [String]).isEmpty { return nil }
        } else if let ids = raw["work_ids"] {
          g["work_ids"] = try GrantJSON.strings(ids).filter { id in
            guard let kind = id.split(separator: "/").first else { return false }; return choice.kinds.contains(String(kind))
          }
          if (g["work_ids"] as! [String]).isEmpty { return nil }
        }
        return try constrain(g)
      }
      guard !grants.isEmpty else { throw NativeGrantError.permissions }; read["read_grants"] = grants; result["read"] = read
    }
    if !choice.writes.isEmpty {
      guard ceiling["installation_id"] == nil || ceiling["installation_id"] is NSNull else { throw NativeGrantError.permissions }
      var write = base; write.removeValue(forKey: "read_grants"); write.removeValue(forKey: "installation_id")
      let grants = try GrantJSON.rows(ceiling["write_grants"] ?? [[String: Any]]()).flatMap { raw -> [[String: Any]] in
        guard let operation = raw["operation"] as? String, choice.writes.contains(operation) else { return [] }
        var g = raw; let existingPaths = try paths(g)
        let pathBound = !selectedPaths.isEmpty || !existingPaths.isEmpty
        if pathBound && ["devgraph.work.create.v2", "devgraph.arena.create.v1"].contains(operation) { return [] }
        let rows = try GrantJSON.rows(raw["resources"]).compactMap { row -> [String: Any]? in
          guard let kind = row["kind"] as? String, choice.kinds.contains(kind) else { return nil }
          var selected = row
          if let exact = choice.exactResources {
            guard let ids = exact[kind] else { return nil }
            let subset = try row["ids"].map { try GrantJSON.strings($0).filter { ids.contains($0) } } ?? ids.sorted()
            guard !subset.isEmpty else { return nil }; selected["ids"] = subset
          }
          return selected
        }
        if !pathBound { guard !rows.isEmpty else { return [] }; g["resources"] = rows; return [g] }
        // Arena records do not use Work path wildcards. Emit exact IDs from
        // the verified selected anchors, preserving every parent restriction.
        var output: [[String: Any]] = []
        let hierarchy = rows.filter { ["Initiative", "Project", "Issue", "Task"].contains($0["kind"] as? String ?? "") }
        if !hierarchy.isEmpty {
          g["resources"] = hierarchy
          if let narrowed = try constrain(g) { output.append(narrowed) }
        }
        if existingPaths.isEmpty, let arena = rows.first(where: { $0["kind"] as? String == "Arena" }) {
          let anchors = Set(selectedPaths.flatMap(\.path).filter { $0.hasPrefix("Arena/") }.map { String($0.dropFirst(6)) })
          var ids = try arena["ids"].map { try GrantJSON.strings($0).filter { anchors.contains($0) } } ?? anchors.sorted()
          if let filter = raw["arena_ids"] { let allowed = try GrantJSON.strings(filter); ids = ids.filter { allowed.contains($0) } }
          if !ids.isEmpty {
            var exact = raw; exact["resources"] = [["kind": "Arena", "ids": ids]]
            output.append(exact)
          }
        }
        return output
      }
      guard !grants.isEmpty else { throw NativeGrantError.permissions }; write["write_grants"] = grants; result["write"] = write
    }
    return result
  }
}
#endif
