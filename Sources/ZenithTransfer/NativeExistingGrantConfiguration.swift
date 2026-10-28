#if os(macOS)
import Foundation
import ZenithKit

enum NativeExistingGrantError: LocalizedError {
  case unavailable, unsupported, components
  var errorDescription: String? {
    switch self {
    case .unavailable: return "Reload the inbox from an updated server to configure this grant. Its current permissions are unchanged."
    case .unsupported: return "This grant has restrictions the editor cannot reproduce exactly. Its current permissions are preserved; no replacement was prepared."
    case .components: return "Keep at least one permission in each existing read or write component. Use the separate revocation action to remove this grant."
    }
  }
}

/// Hydration is accepted only after compiling the initial choices back to the
/// exact original resource/action/filter rows. Never infer scope from access_mode.
struct NativeExistingGrantConfiguration {
  static let schema = "devgraph.grant-configuration.v1"
  let recipient: NativeGrantRecipient
  let selection: [String: Any]
  let rules: [NativeGrantChoice]

  init(grant: [String: Any], inbox: NativeOperatorInbox, now: Int) throws {
    guard inbox.activation["configure_existing_grants"] as? String == Self.schema,
      let configuration = grant["configuration"] as? [String: Any],
      configuration["schema"] as? String == Self.schema,
      let selection = configuration["selection"] as? [String: Any],
      !selection.isEmpty, Set(selection.keys).isSubset(of: ["read", "write"]),
      GrantJSON.integer(grant["version"]) == 2 else { throw NativeExistingGrantError.unavailable }
    var raw = grant
    raw["previous_assignment_digest"] = selection["read"] != nil ? grant["assignment_digest"] : NSNull()
    raw["previous_write_assignment_digest"] = selection["write"] != nil
      ? (selection["read"] != nil ? grant["write_assignment_digest"] : grant["assignment_digest"]) : NSNull()
    let recipient = try NativeGrantRecipient(raw)
    var rules: [NativeGrantChoice] = []
    var end: UInt64?? = nil
    func append(_ rule: NativeGrantChoice) {
      if let i = rules.firstIndex(where: {
        $0.kinds == rule.kinds && $0.paths == rule.paths && $0.wholeGraph == rule.wholeGraph && $0.exactResources == rule.exactResources
      }) {
        rules[i].reads.formUnion(rule.reads); rules[i].writes.formUnion(rule.writes)
        rules[i].arenaIDs.formUnion(rule.arenaIDs); rules[i].allArenas = rules[i].allArenas || rule.allArenas
      } else { rules.append(rule) }
    }
    for side in ["read", "write"] {
      guard let draft = selection[side] as? [String: Any] else { continue }
      let allowed:Set<String> = ["schema","issuer","receiver","write_audience","subject_public_key","installation_id","not_before","not_after","validity","lifetime_seconds","read_grants","write_grants","previous_digest","preset"]
      guard Set(draft.keys).isSubset(of:allowed),
        draft["issuer"] as? String == inbox.ceiling["issuer"] as? String,
        draft["receiver"] as? String == inbox.ceiling["receiver"] as? String,
        draft["write_audience"] as? String == inbox.ceiling["write_audience"] as? String,
        draft["subject_public_key"] as? String == recipient.subject,
        side != "read" || draft["installation_id"] as? String == recipient.installation,
        side != "write" || draft["installation_id"] == nil || draft["installation_id"] is NSNull,
        let lifetime = GrantJSON.integer(draft["lifetime_seconds"]), lifetime > 0,
        lifetime <= (GrantJSON.integer(inbox.ceiling["lifetime_seconds"]) ?? 0),
        try GrantJSON.digest(draft) == raw[side == "read" ? "previous_assignment_digest" : "previous_write_assignment_digest"] as? String
      else { throw NativeExistingGrantError.unsupported }
      let validity = try NativeGrantPermissions(draft).validity
      guard validity.contains(UInt64(now)), end == nil || end! == validity.notAfter else { throw NativeExistingGrantError.unsupported }
      end = .some(validity.notAfter)
      for row in try GrantJSON.rows(draft[side + "_grants"] ?? [[String:Any]]()) {
        var rule = NativeGrantChoice()
        rule.untilRevoked = validity.notAfter == nil
        if let expires = validity.notAfter { rule.expiry = Date(timeIntervalSince1970: Double(expires)) }
        rule.paths = try NativeGrantSelection.paths(row)
        rule.wholeGraph = rule.paths.isEmpty
        if side == "read", row["scope"] as? String == "devgraph.arena.read" {
          rule.allArenas = row["all_arenas"] as? Bool == true
          rule.arenaIDs = Set(try GrantJSON.strings(row["arena_ids"] ?? [String]()))
          // A specific Arena-only rule is displayed as exact scope, never all.
          rule.kinds = ["Arena"]
          if !rule.allArenas { rule.exactResources = ["Arena":rule.arenaIDs]; rule.wholeGraph = false }
        } else if side == "read" {
          rule.reads = Set(try GrantJSON.strings(row["operations"]))
          rule.kinds = Set(try GrantJSON.strings(row["work_kinds"]))
          if let ids = row["work_ids"] {
            guard rule.paths.isEmpty else { throw NativeExistingGrantError.unsupported }
            var exact: [String:Set<String>] = [:]
            for id in try GrantJSON.strings(ids) {
              let parts = id.split(separator:"/", maxSplits:1).map(String.init)
              guard parts.count == 2 else { throw NativeExistingGrantError.unsupported }
              exact[parts[0],default:[]].insert(parts[1])
            }
            rule.exactResources = exact; rule.wholeGraph = false
          }
        } else {
          guard let operation = row["operation"] as? String else { throw NativeExistingGrantError.unsupported }
          rule.writes = [operation]
          let resources = try GrantJSON.rows(row["resources"])
          rule.kinds = Set(resources.compactMap { $0["kind"] as? String })
          if resources.contains(where: { $0["ids"] != nil }) {
            guard rule.paths.isEmpty, resources.allSatisfy({ $0["ids"] != nil }) else { throw NativeExistingGrantError.unsupported }
            var exact: [String:Set<String>] = [:]
            for resource in resources {
              guard let kind = resource["kind"] as? String, exact[kind] == nil else { throw NativeExistingGrantError.unsupported }
              exact[kind] = Set(try GrantJSON.strings(resource["ids"]))
            }
            rule.exactResources = exact; rule.wholeGraph = false
          }
        }
        append(rule)
      }
    }
    guard !rules.isEmpty, rules.count <= 16 else { throw NativeExistingGrantError.unsupported }
    let compiled = try NativeGrantSelection.makeRules(ceiling:inbox.ceiling, ceilingDigest:inbox.digest,
      recipient:recipient, rules:rules, scopes:inbox.scopes, now:now)
    for side in selection.keys {
      let original = selection[side] as! [String:Any]
      guard let produced = compiled[side] as? [String:Any],
        Self.sameRows(original[side + "_grants"], produced[side + "_grants"]) else { throw NativeExistingGrantError.unsupported }
    }
    self.recipient = recipient; self.selection = selection; self.rules = rules
  }

  private static func canonical(_ value: Any) -> Any {
    if let object = value as? [String:Any] { return object.mapValues(canonical) }
    if let array = value as? [Any] {
      return array.map(canonical).sorted { (try? GrantJSON.data($0).lexicographicallyPrecedes(GrantJSON.data($1))) == true }
    }
    return value
  }
  static func sameRows(_ a: Any?, _ b: Any?) -> Bool {
    guard let a, let b else { return false }; return GrantJSON.equal(canonical(a), canonical(b))
  }
  func preservingLimits(_ compiled: [String:Any]) throws -> [String:Any] {
    guard Set(compiled.keys) == Set(selection.keys) else { throw NativeExistingGrantError.components }
    var result = compiled
    for side in selection.keys {
      var draft = result[side] as! [String:Any]
      // The editor does not expose credential lifetime; retain its exact cap.
      draft["lifetime_seconds"] = (selection[side] as! [String:Any])["lifetime_seconds"]
      result[side] = draft
    }
    return result
  }
}
#endif
