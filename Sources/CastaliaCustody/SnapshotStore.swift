import Foundation
import SQLite3
import ZenithKit

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
