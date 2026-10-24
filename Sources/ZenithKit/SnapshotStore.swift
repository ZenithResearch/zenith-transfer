import Foundation
import SQLite3

public enum WalletFailure: Error, Equatable, LocalizedError {
  case storage, conflict, locked
  case core(String)
  case invalidFile
  public var errorDescription: String? {
    switch self {
    case .storage: return "Could not save. Your wallet is unchanged."
    case .conflict: return "Your wallet changed. Unlock it again before continuing."
    case .locked: return "Unlock your wallet to continue."
    case .invalidFile: return "This file could not be read. Choose an encrypted recovery file."
    case .core(let code):
      switch code {
      case "identity_conflict", "duplicate_or_invalid_identity":
        return "An identity conflicts with a saved record. Nothing was overwritten; review the records separately."
      case "invalid_wallet_identities", "unsupported_identity_fields", "invalid_identity_text", "invalid_provider_identity", "identities_too_large", "identity_limit":
        return "Check the public identity fields. Passwords, tokens, private keys and session data are not accepted here."
      case "password_minimum_12": return "Use a password with at least 12 characters."
      case "backup_verification_required": return "Check your saved recovery file first."
      case "wallet_already_exists":
        return
          "This installation already has a wallet. Restore another wallet in a separate installation."
      case "backup_identity_mismatch": return "This recovery file belongs to a different wallet."
      case "wallet_locked": return "Unlock your wallet to continue."
      case "trust_setup_required", "untrusted_issuer":
        return
          "This file needs an approved membership provider. Set up Membership before importing it."
      case "data_file_requires_recovery":
        return "This is a data file. Choose your recovery file to restore your wallet."
      case "data_file_invalid":
        return "Could not open this data file. Check its password and try again."
      case "access_expired", "access_denied", "membership_required", "invalid_read_authority":
        return "Work access needs attention. Open Membership or reconnect Work access in Wallet."
      case "service_setup_required": return "This build needs an approved service configuration."
      case "issuer_setup_required": return "The access provider has changed. An updated connection configuration is needed."
      case "invalid_response", "invalid_credential", "invalid_read_challenge":
        return "The service returned an unexpected response. No connection was saved."
      case "work_view_changed": return "Work changed while loading. Return to Work and pull to refresh before loading more."
      case "unsupported_read_scope": return "Your current access does not include this kind of work or action."
      case "service_rejected_request":
        return "The service could not complete this request. Try again later."
      case "recovery_file_invalid", "unlock_failed":
        return "Could not unlock. Check the file and its password."
      case "preview_stale", "preview_expired":
        return "This preview expired. Choose your file again."
      default: return "Could not complete this step. Your saved wallet is unchanged."
      }
    }
  }
}

/// Single-row transaction. Call only from the repository actor; no plaintext custody.
final class SnapshotStore {
  struct Stored {
    let snapshot: String
    let revision: UInt64
  }
  private var db: OpaquePointer?
  init(directory: URL) throws {
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    var directory = directory
    var values = URLResourceValues()
    values.isExcludedFromBackup = true
    try directory.setResourceValues(values)
    #if os(iOS)
      try FileManager.default.setAttributes(
        [.protectionKey: FileProtectionType.complete], ofItemAtPath: directory.path)
    #endif
    let path = directory.appendingPathComponent("wallet.sqlite").path
    guard
      sqlite3_open_v2(
        path, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, nil)
        == SQLITE_OK
    else {
      sqlite3_close(db)
      db = nil
      throw WalletFailure.storage
    }
    do {
      try execute("PRAGMA journal_mode=DELETE")
      try execute("PRAGMA synchronous=FULL")
      try execute("PRAGMA busy_timeout=1000")
      try execute(
        "CREATE TABLE IF NOT EXISTS snapshot (id INTEGER PRIMARY KEY CHECK(id=1), revision INTEGER NOT NULL, encrypted TEXT NOT NULL)"
      )
      #if os(iOS)
        try FileManager.default.setAttributes(
          [.protectionKey: FileProtectionType.complete], ofItemAtPath: path)
      #endif
    } catch {
      sqlite3_close(db)
      db = nil
      throw error
    }
  }
  deinit { sqlite3_close(db) }
  private func execute(_ sql: String) throws {
    guard sqlite3_exec(db, sql, nil, nil, nil) == SQLITE_OK else { throw WalletFailure.storage }
  }
  func read() throws -> Stored? {
    var statement: OpaquePointer?
    guard
      sqlite3_prepare_v2(
        db, "SELECT revision, encrypted FROM snapshot WHERE id=1", -1, &statement, nil) == SQLITE_OK
    else { throw WalletFailure.storage }
    defer { sqlite3_finalize(statement) }
    let result = sqlite3_step(statement)
    if result == SQLITE_DONE { return nil }
    guard result == SQLITE_ROW, sqlite3_column_int64(statement, 0) > 0,
      let text = sqlite3_column_text(statement, 1)
    else { throw WalletFailure.storage }
    return Stored(
      snapshot: String(cString: text), revision: UInt64(sqlite3_column_int64(statement, 0)))
  }
  func commit(snapshot: String, expectedRevision: UInt64, revision: UInt64) throws {
    guard expectedRevision < 9_007_199_254_740_991, revision == expectedRevision + 1,
      revision <= 9_007_199_254_740_991, snapshot.utf8.count <= 2_097_152
    else { throw WalletFailure.conflict }
    try execute("BEGIN IMMEDIATE")
    var committed = false
    defer { if !committed { try? execute("ROLLBACK") } }
    guard (try read()?.revision ?? 0) == expectedRevision else { throw WalletFailure.conflict }
    var statement: OpaquePointer?
    guard
      sqlite3_prepare_v2(
        db, "INSERT OR REPLACE INTO snapshot(id,revision,encrypted) VALUES(1,?,?)", -1, &statement,
        nil) == SQLITE_OK
    else { throw WalletFailure.storage }
    defer { sqlite3_finalize(statement) }
    sqlite3_bind_int64(statement, 1, Int64(revision))
    let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
    guard sqlite3_bind_text(statement, 2, snapshot, -1, transient) == SQLITE_OK,
      sqlite3_step(statement) == SQLITE_DONE
    else { throw WalletFailure.storage }
    try execute("COMMIT")
    committed = true
  }
}
