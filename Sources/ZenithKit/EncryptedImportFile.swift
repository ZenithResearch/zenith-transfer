import Foundation
import Darwin

public enum EncryptedImportFile {
  public static let maximumBytes = 1_048_576

  /// Copies a bounded, coordinated snapshot; never edits the source file.
  public static func read(_ url: URL) throws -> Data {
    let bytes = try readBoundedBytes(url)
    try validateEnvelope(bytes)
    return bytes
  }

  /// Catalog inspection may report an unsupported header, but never transfers it.
  static func readBoundedBytes(_ url: URL) throws -> Data {
    guard url.isFileURL else { throw RecoveryTransferError.invalidFile }
    let scoped = url.startAccessingSecurityScopedResource()
    defer { if scoped { url.stopAccessingSecurityScopedResource() } }
    try requireRegularFile(url)
    var coordinationError: NSError?
    var result: Result<Data, Error> = .failure(RecoveryTransferError.invalidFile)
    NSFileCoordinator().coordinate(readingItemAt: url, options: [], error: &coordinationError) { file in
      result = Result {
        // NSURL may cache resource values, and coordination may resolve links.
        // Inspect the original path again and open the coordinated path without
        // following a final symlink, then validate the descriptor itself.
        try requireRegularFile(url)
        let descriptor = file.withUnsafeFileSystemRepresentation { path in
          path.map { Darwin.open($0, O_RDONLY | O_NOFOLLOW | O_NONBLOCK) } ?? -1
        }
        guard descriptor >= 0 else { throw RecoveryTransferError.invalidFile }
        var info = stat()
        guard fstat(descriptor, &info) == 0, info.st_mode & S_IFMT == S_IFREG else {
          Darwin.close(descriptor)
          throw RecoveryTransferError.invalidFile
        }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        defer { try? handle.close() }
        let bytes = try handle.read(upToCount: maximumBytes + 1) ?? Data()
        guard !bytes.isEmpty, bytes.count <= maximumBytes else {
          throw RecoveryTransferError.invalidFile
        }
        return bytes
      }
    }
    if coordinationError != nil { throw RecoveryTransferError.invalidFile }
    return try result.get()
  }

  private static func requireRegularFile(_ url: URL) throws {
    var info = stat()
    let code = url.withUnsafeFileSystemRepresentation { path in
      path.map { lstat($0, &info) } ?? -1
    }
    guard code == 0, info.st_mode & S_IFMT == S_IFREG else { throw RecoveryTransferError.invalidFile }
  }

  /// A transport admission check, not cryptographic verification. It prevents
  /// ordinary plaintext/key files from entering the transfer UI. The unchanged
  /// Rust parser remains authoritative for the complete portable contract.
  public static func validateEnvelope(_ bytes: Data) throws {
    guard !bytes.isEmpty, bytes.count <= maximumBytes,
      let value = try? JSONSerialization.jsonObject(with: bytes) as? [String: Any],
      let schema = value["schema"] as? String
    else { throw RecoveryTransferError.invalidFile }
    let keys: Set<String>
    if schema == "castalia.wallet-custody.v1" {
      keys = ["schema", "keySuite", "publicKey", "createdAt", "kdf", "aead", "ciphertext"]
      guard value["keySuite"] as? String == "Ed25519" else { throw RecoveryTransferError.invalidFile }
    } else if schema == "castalia.castaway.v1" {
      keys = ["schema", "contentsSchema", "ownerPublicKey", "exportedAt", "kdf", "aead", "ciphertext"]
      guard value["contentsSchema"] as? String == "castalia.castaway-contents.v1" else {
        throw RecoveryTransferError.invalidFile
      }
    } else { throw RecoveryTransferError.invalidFile }
    let ownerField = schema == "castalia.wallet-custody.v1" ? "publicKey" : "ownerPublicKey"
    let dateField = schema == "castalia.wallet-custody.v1" ? "createdAt" : "exportedAt"
    guard Set(value.keys) == keys,
      let owner = value[ownerField] as? String, owner.utf8.count == 64,
      owner.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }),
      let date = value[dateField] as? Int, (0...9_007_199_254_740_991).contains(date),
      let kdf = value["kdf"] as? [String: Any],
      Set(kdf.keys) == ["name", "version", "salt", "memoryKiB", "iterations", "parallelism", "derivedKeyBytes"],
      kdf["name"] as? String == "Argon2id", kdf["version"] as? Int == 19,
      kdf["memoryKiB"] as? Int == 65_536, kdf["iterations"] as? Int == 3,
      kdf["parallelism"] as? Int == 1, kdf["derivedKeyBytes"] as? Int == 32,
      let salt = kdf["salt"] as? String, RecoveryQR.decode(salt)?.count == 16,
      let aead = value["aead"] as? [String: Any], Set(aead.keys) == ["name", "nonce", "tagBits"],
      aead["name"] as? String == "AES-256-GCM", aead["tagBits"] as? Int == 128,
      let nonce = aead["nonce"] as? String, RecoveryQR.decode(nonce)?.count == 12,
      let ciphertext = value["ciphertext"] as? String,
      let encrypted = RecoveryQR.decode(ciphertext), encrypted.count >= 16
    else { throw RecoveryTransferError.invalidFile }
  }
}

public enum USBImportInbox {
  /// Documents is intentionally the transfer surface. Custody stays in the
  /// separate Application Support directory and is never copied here.
  public static func directory() throws -> URL {
    var url = try FileManager.default.url(
      for: .documentDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
    var values = URLResourceValues()
    values.isExcludedFromBackup = true
    try url.setResourceValues(values)
    #if os(iOS)
      try FileManager.default.setAttributes(
        [.protectionKey: FileProtectionType.complete], ofItemAtPath: url.path)
    #endif
    return url
  }
  public static func files(in directory: URL) throws -> [URL] {
    let urls = try FileManager.default.contentsOfDirectory(
      at: directory, includingPropertiesForKeys: [.isRegularFileKey, .isSymbolicLinkKey],
      options: [.skipsHiddenFiles])
    return urls.filter {
      guard let values = try? $0.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey]) else {
        return false
      }
      return values.isRegularFile == true && values.isSymbolicLink != true
    }.sorted { $0.lastPathComponent < $1.lastPathComponent }.prefix(100).map { $0 }
  }
}
