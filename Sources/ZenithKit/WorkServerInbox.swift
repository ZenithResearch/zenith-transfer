import Foundation

/// Discover public connection profiles already copied to this app. Discovery
/// never approves trust, changes settings, or contacts a server.
public struct WorkServerInboxEntry: Identifiable, Sendable {
  public var id: URL { file }
  public let file: URL
  public let configuration: WorkAccessConfiguration
  public let modified: Date

  public func selectedConfiguration() throws -> WorkAccessConfiguration {
    let current = try WorkServerSettings.readFile(file)
    guard current == configuration else { throw WorkServerSetupError.changed }
    return current
  }
}

public enum WorkServerInbox {
  public static func profiles(in directory: URL) throws -> [WorkServerInboxEntry] {
    let keys: Set<URLResourceKey> = [.isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey, .contentModificationDateKey]
    let files = try FileManager.default.contentsOfDirectory(at: directory,
      includingPropertiesForKeys: Array(keys), options: [.skipsHiddenFiles])
    return files.filter { $0.pathExtension.lowercased() == "json" }
      .sorted { $0.lastPathComponent < $1.lastPathComponent }.prefix(100).compactMap { file in
        guard let attributes = try? file.resourceValues(forKeys: keys),
          attributes.isRegularFile == true, attributes.isSymbolicLink != true,
          let size = attributes.fileSize, size <= WorkServerSettings.maximumFileBytes,
          let configuration = try? WorkServerSettings.readFile(file) else { return nil }
        return WorkServerInboxEntry(file: file, configuration: configuration,
          modified: attributes.contentModificationDate ?? .distantPast)
      }.sorted {
        $0.modified == $1.modified ? $0.file.lastPathComponent < $1.file.lastPathComponent : $0.modified > $1.modified
      }
  }
}
