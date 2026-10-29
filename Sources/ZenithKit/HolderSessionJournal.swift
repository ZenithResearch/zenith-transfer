#if os(macOS)
import Darwin
import Foundation

/// Separate application audit storage. Neither a Wallet backup nor a key store;
/// retaining this record never permits restoration/recreation of session custody.
final class HolderSessionJournal: HolderSessionRecordStore, @unchecked Sendable {
  private let directory: URL
  init(directory: URL) throws {
    self.directory = directory
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    var info = stat()
    guard lstat(directory.path, &info) == 0, info.st_uid == getuid(), info.st_mode & S_IFMT == S_IFDIR,
      info.st_mode & 0o077 == 0 else { throw HolderSessionError.invalid }
  }
  func save(_ record: HolderSessionFlowRecord, replacing previous: HolderSessionFlowRecord?) throws {
    try validate(record)
    let file = directory.appendingPathComponent(HS.digest(Data((record.clientID + ":" + record.requestHandle).utf8)) + ".json")
    var failure: NSError?, outcome: Result<Void, Error> = .failure(HolderSessionError.invalid)
    NSFileCoordinator().coordinate(writingItemAt: file, options: .forMerging, error: &failure) { _ in
      outcome = Result {
        let existing = try read(file)
        if let previous {
          guard let existing, existing == (try encode(previous)), record.version == previous.version + 1,
            record.clientID == previous.clientID, record.requestID == previous.requestID,
            record.requestHandle == previous.requestHandle, record.service == previous.service,
            record.challenge == previous.challenge,
            !previous.dispatched || record.dispatched else { throw HolderSessionError.changed }
        } else {
          guard existing == nil, record.version == 1, record.phase == .awaitingHuman, !record.dispatched,
            try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil).count < 64
          else { throw HolderSessionError.changed }
        }
        try encode(record).write(to: file, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
        let fd = open(file.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw HolderSessionError.invalid }; defer { Darwin.close(fd) }
        guard fsync(fd) == 0 else { throw HolderSessionError.invalid }
        let parent = open(directory.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard parent >= 0 else { throw HolderSessionError.invalid }; defer { Darwin.close(parent) }
        guard fsync(parent) == 0 else { throw HolderSessionError.invalid }
      }
    }
    if failure != nil { throw HolderSessionError.invalid }; try outcome.get()
  }
  private func encode(_ record: HolderSessionFlowRecord) throws -> Data {
    let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    return try encoder.encode(record)
  }
  private func read(_ file: URL) throws -> Data? {
    let fd = open(file.path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
    if fd < 0 { if errno == ENOENT { return nil }; throw HolderSessionError.invalid }
    let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
    var info = stat()
    guard fstat(fd, &info) == 0, info.st_uid == getuid(), info.st_mode & S_IFMT == S_IFREG,
      info.st_mode & 0o077 == 0, info.st_nlink == 1, info.st_size <= 262144,
      let data = try handle.readToEnd(), data.count <= 262144 else { throw HolderSessionError.invalid }
    return data
  }
  private func validate(_ record: HolderSessionFlowRecord) throws {
    guard record.schema == "zenith.holder-session-record.v1", record.version > 0,
      record.version <= 9_007_199_254_740_991,
      ![.idle, .preparing].contains(record.phase) else { throw HolderSessionError.invalid }
    for id in [record.clientID, record.requestID, record.requestHandle] { _ = try HS.hex(id, 32) }
    try HS.text(record.service)
    if let handle = record.credentialHandle { _ = try HS.hex(handle, 32) }
    guard record.dispatched || record.credentialHandle == nil,
      record.phase != .issued || (record.dispatched && record.credentialHandle != nil),
      record.phase != .awaitingHuman || !record.dispatched else { throw HolderSessionError.invalid }
    let c = try HS.object(record.challenge)
    // Only the closed public challenge can enter this record. A root grant,
    // authorization envelope or private signing material cannot replace it.
    try HS.keys(c, "schema challenge_id request_id nonce issuer key_id service audience origin parent_grant_id parent_grant_digest parent_revision holder_public_key installation_id session_installation_id session_public_key permissions issued_at review_deadline expires_at")
    guard c["schema"] as? String == "secs.holder-session-challenge.v1", c["request_id"] as? String == record.requestID,
      c["service"] as? String == record.service else { throw HolderSessionError.changed }
    try HS.permissions(c["permissions"])
    _ = try HS.integer(c["expires_at"])
  }
}
#endif
