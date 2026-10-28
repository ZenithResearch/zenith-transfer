#if os(macOS)
import Foundation
import ZenithKit

/// The two columns remain independent rule sets. Read on a parent never moves
/// a child's Write actions onto that parent when compiling the existing wire.
struct NativeHierarchyPermissions: Equatable {
  enum Access { case read, write }
  var readPaths: [WorkResourcePath] = []
  var writePaths: [WorkResourcePath] = []
  static let writeActions: Set<String> = ["devgraph.work.patch.v2"]
  static let workKinds: Set<String> = ["Initiative", "Project", "Issue", "Task"]

  func paths(_ access: Access) -> [WorkResourcePath] { access == .read ? readPaths : writePaths }
  func includes(_ path: WorkResourcePath, _ access: Access) -> Bool {
    paths(access).contains { WorkScopeSelection.covers($0, path) }
  }
  func inherited(_ path: WorkResourcePath, _ access: Access) -> Bool {
    paths(access).contains { $0 != path && WorkScopeSelection.covers($0, path) }
  }
  mutating func set(_ path: WorkResourcePath, _ access: Access, enabled: Bool) throws {
    let old = paths(access)
    let updated = try WorkScopeSelection.normalized(enabled ? old + [path] : old.filter { $0 != path })
    if access == .read { readPaths = updated } else { writePaths = updated }
  }
  func rules(permissions: NativeGrantPermissions, validity: NativeGrantChoice) throws -> [NativeGrantChoice] {
    var result: [NativeGrantChoice] = []
    for access in [Access.read, .write] {
      let selected = paths(access)
      guard !selected.isEmpty else { continue }
      var rule = NativeGrantChoice()
      rule.untilRevoked = validity.untilRevoked; rule.expiry = validity.expiry
      rule.paths = try WorkScopeSelection.normalized(selected)
      rule.kinds = Self.workKinds.intersection(permissions.kinds)
      if access == .read {
        rule.reads = Set(permissions.reads)
        // Reading a Project doesn't silently add its containing Arena record.
        let arenaIDs = selected.compactMap { path -> String? in
          guard let last = path.path.last, last.hasPrefix("Arena/") else { return nil }
          return String(last.dropFirst(6))
        }
        rule.arenaIDs = Set(arenaIDs).intersection(permissions.arenaIDs)
        guard !rule.reads.isEmpty || !rule.arenaIDs.isEmpty else { throw NativeGrantError.permissions }
      } else {
        rule.writes = Self.writeActions.intersection(permissions.writes)
        guard !rule.writes.isEmpty else { throw NativeGrantError.permissions }
      }
      result.append(rule)
    }
    return result
  }
}

/// Only closed protocol codes are shown. Arbitrary server/core text stays private.
enum NativeCredentialDiagnostic {
  static func message(_ error: Error) -> String {
    if case WalletFailure.core(let code) = error {
      switch code {
      case "service_binding_expired":
        return "The verified server connection expired. Reopen this server to refresh it. Original actions remain saved. (service_binding_expired)"
      case "invalid_service_binding":
        return "The server connection could not be verified. Reopen the server and check its saved connection. No authority was changed. (invalid_service_binding)"
      case "invalid_access_request":
        return "Wallet could not validate the server’s approval request. No decision was signed. Refresh the request context. (invalid_access_request)"
      case "invalid_access_catalog":
        return "The server’s resource hierarchy could not be verified. Refresh the request context; no wider scope was selected. (invalid_access_catalog)"
      case "operator_update_required":
        return "This Wallet build cannot review operator requests. Update Transfer before continuing. (operator_update_required)"
      case "access_approval_expired", "access_approval_unavailable":
        return "The approval expired or is no longer available. Resume the original action to refresh its review. (\(code))"
      case "operator_recovery_required", "recover_original_action_first":
        return "Check the original action’s result before preparing another decision. Its request is preserved. (\(code))"
      case "invalid_operator_recovery":
        return "The original action record could not be validated. Keep it for recovery and update Transfer before continuing. (invalid_operator_recovery)"
      case "approval_denied": return "Wallet review was cancelled. No new decision was signed."
      default: break
      }
    }
    if error is WalletFailure || error is NativeGrantError || error is NativeGrantRuleError || error is LocalAdminRPCError || error is NativeOperatorServerError {
      return (error as? LocalizedError)?.errorDescription ?? "Could not finish this step. Check the Wallet and saved server connection."
    }
    return "Could not finish this step. Check the Wallet and saved server connection."
  }
}
#endif
