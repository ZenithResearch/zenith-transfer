import CastaliaSignerProtocol
import CryptoKit
import Foundation
import SQLite3
import Darwin

/// This target belongs only in the signer. A client must never receive its key,
/// directory, journal store or raw snapshot. The supplied key is device-only.
public final class EncryptedSignerJournal: SignerJournalStore, @unchecked Sendable {
  private let lock = NSLock()
  private let key: SymmetricKey
  private var db: OpaquePointer?
  private static let maximumBytes = 16_777_216
  private let aad = Data("castalia/signer-journal/v1\0".utf8)

  public init(directory: URL, key: SymmetricKey) throws {
    guard key.bitCount == 256, directory.isFileURL else { throw SignerFailure.invalidMessage }
    self.key = key
    // No automatic recovery or replacement of an unexpected file/directory.
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
      attributes: [.posixPermissions: 0o700])
    var statValue = stat()
    guard lstat(directory.path, &statValue) == 0, statValue.st_mode & S_IFMT == S_IFDIR,
      statValue.st_uid == getuid(), statValue.st_mode & 0o077 == 0 else { throw SignerFailure.unavailable }
    // macOS's standard temporary/Application Support paths may themselves have
    // a system-owned symlink ancestor. Resolve ancestors after refusing a
    // symlink at the supplied private directory, before SQLite's NOFOLLOW open.
    guard let resolved = realpath(directory.path, nil) else { throw SignerFailure.unavailable }
    let filePath = String(cString: resolved) + "/consent.sqlite"; free(resolved)
    let file = directory.appendingPathComponent("consent.sqlite")
    let descriptor = open(filePath, O_CREAT | O_EXCL | O_RDWR | O_NOFOLLOW | O_CLOEXEC, 0o600)
    if descriptor >= 0 { close(descriptor) }
    else if errno != EEXIST { throw SignerFailure.unavailable }
    guard lstat(filePath, &statValue) == 0, statValue.st_mode & S_IFMT == S_IFREG,
      statValue.st_uid == getuid(), statValue.st_nlink == 1, statValue.st_mode & 0o077 == 0 else {
      throw SignerFailure.unavailable
    }
    // SQLITE_OPEN_NOFOLLOW is available on the supported Apple SQLite runtime.
    guard sqlite3_open_v2(filePath, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX | SQLITE_OPEN_NOFOLLOW, nil) == SQLITE_OK else {
      sqlite3_close(db); db = nil; throw SignerFailure.unavailable
    }
    do {
      try execute("PRAGMA journal_mode=DELETE")
      try execute("PRAGMA synchronous=FULL")
      try execute("PRAGMA busy_timeout=1000")
      try execute("PRAGMA trusted_schema=OFF")
      try execute("CREATE TABLE IF NOT EXISTS consent (id INTEGER PRIMARY KEY CHECK(id=1), revision INTEGER NOT NULL, sealed BLOB NOT NULL)")
      var values = URLResourceValues(); values.isExcludedFromBackup = true
      var folder = directory; try folder.setResourceValues(values)
      #if os(iOS)
      for target in [directory, file] {
        try FileManager.default.setAttributes([.protectionKey: FileProtectionType.complete], ofItemAtPath: target.path)
      }
      #endif
    } catch { sqlite3_close(db); db = nil; throw SignerFailure.unavailable }
  }
  deinit { sqlite3_close(db) }
  private func execute(_ sql: String) throws {
    guard sqlite3_exec(db, sql, nil, nil, nil) == SQLITE_OK else { throw SignerFailure.unavailable }
  }
  private func associatedData(_ revision: UInt64) -> Data {
    var bytes = aad; bytes.append(contentsOf: String(revision).utf8); return bytes
  }
  private func read() throws -> SignerJournalSnapshot? {
    var statement: OpaquePointer?
    guard sqlite3_prepare_v2(db, "SELECT revision, sealed FROM consent WHERE id=1", -1, &statement, nil) == SQLITE_OK else {
      throw SignerFailure.unavailable
    }
    defer { sqlite3_finalize(statement) }
    let result = sqlite3_step(statement)
    if result == SQLITE_DONE { return nil }
    let revision = sqlite3_column_int64(statement, 0)
    let count = Int(sqlite3_column_bytes(statement, 1))
    guard result == SQLITE_ROW, revision > 0, revision < 9_007_199_254_740_991,
      (29...Self.maximumBytes + 28).contains(count), let pointer = sqlite3_column_blob(statement, 1) else {
      throw SignerFailure.unavailable
    }
    do {
      let sealed = try AES.GCM.SealedBox(combined: Data(bytes: pointer, count: count))
      var plaintext = try AES.GCM.open(sealed, using: key, authenticating: associatedData(UInt64(revision)))
      defer { plaintext.resetBytes(in: 0..<plaintext.count) }
      let snapshot = try JSONDecoder().decode(SignerJournalSnapshot.self, from: plaintext)
      guard snapshot.revision == UInt64(revision) else { throw SignerFailure.unavailable }
      return snapshot
    } catch { throw SignerFailure.unavailable }
  }
  public func load() throws -> SignerJournalSnapshot? {
    lock.lock(); defer { lock.unlock() }; return try read()
  }
  public func save(_ snapshot: SignerJournalSnapshot, expectedRevision: UInt64) throws {
    lock.lock(); defer { lock.unlock() }
    guard snapshot.schema == "castalia.signer-journal.v1", expectedRevision < 9_007_199_254_740_990,
      snapshot.revision == expectedRevision + 1 else { throw SignerFailure.changedRequest }
    var plaintext = try SignerWire.encode(snapshot)
    defer { plaintext.resetBytes(in: 0..<plaintext.count) }
    guard plaintext.count <= Self.maximumBytes,
      let sealed = try AES.GCM.seal(plaintext, using: key, authenticating: associatedData(snapshot.revision)).combined else {
      throw SignerFailure.unavailable
    }
    try execute("BEGIN IMMEDIATE")
    var committed = false
    defer { if !committed { try? execute("ROLLBACK") } }
    guard (try read()?.revision ?? 0) == expectedRevision else { throw SignerFailure.changedRequest }
    var statement: OpaquePointer?
    guard sqlite3_prepare_v2(db, "INSERT OR REPLACE INTO consent(id,revision,sealed) VALUES(1,?,?)", -1, &statement, nil) == SQLITE_OK else {
      throw SignerFailure.unavailable
    }
    defer { sqlite3_finalize(statement) }
    sqlite3_bind_int64(statement, 1, Int64(snapshot.revision))
    let copied = sealed.withUnsafeBytes {
      sqlite3_bind_blob(statement, 2, $0.baseAddress, Int32(sealed.count), unsafeBitCast(-1, to: sqlite3_destructor_type.self))
    }
    guard copied == SQLITE_OK, sqlite3_step(statement) == SQLITE_DONE else { throw SignerFailure.unavailable }
    try execute("COMMIT"); committed = true
  }
}
