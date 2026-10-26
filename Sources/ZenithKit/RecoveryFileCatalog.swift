import Foundation

/// Describes only the validated, public encrypted envelope. No decryption,
/// identity claim, membership verification or migration occurs during discovery.
public struct RecoveryFileFormat: Equatable, Sendable {
  public enum Kind: String, Sendable { case recovery, castaway }
  public let kind: Kind
  public let schema: String
  public let contentsSchema: String?
  public let legacyFilename: Bool
  public var title: String { kind == .recovery ? "Wallet recovery" : "Castaway data" }
  public var version: String { schema == "castalia.castaway.v2" ? "v2" : "v1" }
  public var badge: String { legacyFilename ? "Legacy filename" : "Current format" }
  public var explanation: String {
    if legacyFilename {
      return "This older filename contains a v1 recovery backup, not a Castaway data vault. The filename convention is deprecated; the recovery format is still supported. Keep the original and save a new .castalia-recovery backup after restoring."
    }
    return kind == .recovery
      ? "Restores your signing identity. Enter its password on this device, then review and confirm."
      : "Contains encrypted data for a matching wallet. It cannot restore your signing identity. On this device, open Recovery → Import or save a data file."
  }

  public static func inspect(_ data: Data, filename: String) throws -> Self {
    try EncryptedImportFile.validateEnvelope(data)
    let value = try JSONSerialization.jsonObject(with: data) as! [String: Any]
    let schema = value["schema"] as! String
    let kind: Kind = schema == "castalia.wallet-custody.v1" ? .recovery : .castaway
    let ext = (filename as NSString).pathExtension.lowercased()
    return Self(kind: kind, schema: schema, contentsSchema: value["contentsSchema"] as? String,
      legacyFilename: kind == .recovery && ["castaway", "castalia-wallet"].contains(ext))
  }
}

public struct RecoveryCatalogFolder: Identifiable, Sendable {
  public let url: URL
  public let title: String
  public var id: URL { url }
  public init(url: URL, title: String) { self.url = url; self.title = title }
}

public struct RecoveryCatalogFile: Identifiable, Sendable {
  public let url: URL
  public let bytes: Int
  public let modified: Date
  public let format: RecoveryFileFormat?
  public let declaredSchema: String?
  public let problem: String?
  public var id: URL { url }
  public var canShowQR: Bool { format != nil && bytes <= RecoveryQR.maximumBytes }
}

public struct RecoveryCatalogSection: Identifiable, Sendable {
  public let folder: RecoveryCatalogFolder
  public let files: [RecoveryCatalogFile]
  public let problem: String?
  public var id: URL { folder.id }
}

public enum RecoveryFileCatalog {
  public static let extensions: Set<String> = ["castalia-recovery", "castaway", "castalia-wallet"]

  /// ~/.castalia is the documented vault folder. Browser recovery downloads use
  /// Downloads, and save dialogs may use Documents. Never scan recursively.
  public static func defaultFolders(home: URL = URL(fileURLWithPath: NSHomeDirectory(), isDirectory: true)) -> [RecoveryCatalogFolder] {
    [RecoveryCatalogFolder(url: home.appendingPathComponent(".castalia"), title: "Wallet folder"),
     RecoveryCatalogFolder(url: home.appendingPathComponent("Downloads"), title: "Downloads"),
     RecoveryCatalogFolder(url: home.appendingPathComponent("Documents"), title: "Documents")]
  }

  public static func scan(_ folders: [RecoveryCatalogFolder]) -> [RecoveryCatalogSection] {
    folders.map { folder in
      guard FileManager.default.fileExists(atPath: folder.url.path) else {
        return RecoveryCatalogSection(folder: folder, files: [], problem: nil)
      }
      do {
        let urls = try FileManager.default.contentsOfDirectory(at: folder.url,
          includingPropertiesForKeys: [.isRegularFileKey, .isSymbolicLinkKey], options: [.skipsHiddenFiles])
        let matching: [URL] = urls.filter { url in
          guard extensions.contains(url.pathExtension.lowercased()),
            let values = try? url.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey])
          else { return false }
          return values.isRegularFile == true && values.isSymbolicLink != true
        }
        let inspected: [RecoveryCatalogFile] = matching.map { inspect($0) }
        let files = inspected.sorted {
          $0.modified == $1.modified ? $0.url.lastPathComponent < $1.url.lastPathComponent : $0.modified > $1.modified
        }
        return RecoveryCatalogSection(folder: folder, files: files, problem: nil)
      } catch {
        return RecoveryCatalogSection(folder: folder, files: [],
          problem: "This folder could not be read. Use Choose another file to select a backup.")
      }
    }
  }

  /// Re-read the selected file at import time; a cached discovery row is never
  /// authority to restore identity. Castaway data cannot become custody by name.
  public static func readRecovery(_ url: URL) throws -> Data {
    let data = try EncryptedImportFile.read(url)
    guard try RecoveryFileFormat.inspect(data, filename: url.lastPathComponent).kind == .recovery else {
      throw RecoveryTransferError.invalidFile
    }
    return data
  }

  public static func inspect(_ url: URL) -> RecoveryCatalogFile {
    let info = try? url.resourceValues(forKeys: [.fileSizeKey, .contentModificationDateKey])
    var declaredSchema: String?
    do {
      let bytes = try EncryptedImportFile.readBoundedBytes(url)
      if let value = try? JSONSerialization.jsonObject(with: bytes) as? [String: Any],
        let schema = value["schema"] as? String, schema.utf8.count <= 128,
        schema.utf8.allSatisfy({ (33...126).contains($0) }) {
        declaredSchema = schema
      }
      let format = try RecoveryFileFormat.inspect(bytes, filename: url.lastPathComponent)
      return RecoveryCatalogFile(url: url, bytes: bytes.count, modified: info?.contentModificationDate ?? .distantPast,
        format: format, declaredSchema: format.schema, problem: nil)
    } catch {
      let tooLarge = (info?.fileSize ?? 0) > EncryptedImportFile.maximumBytes
      return RecoveryCatalogFile(url: url, bytes: info?.fileSize ?? 0, modified: info?.contentModificationDate ?? .distantPast,
        format: nil, declaredSchema: declaredSchema,
        problem: tooLarge ? "Exceeds the 1 MiB import limit." : "Unsupported or damaged file. It cannot be transferred by this version.")
    }
  }
}
