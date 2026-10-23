import CryptoKit
import Foundation

/// Local public connection settings. Registration is neither issuer ownership
/// nor an operator grant; the resource checks Wallet authority on every action.
public struct RegisteredResource: Codable, Identifiable, Equatable, Sendable {
  public let configuration: WorkAccessConfiguration
  public var id: String { configuration.origin }
  public var inboxURL: URL { configuration.receiver.appendingPathComponent("monitor/access/") }
  public init(configuration: WorkAccessConfiguration) throws {
    _ = try WorkServerSettings.decode(JSONEncoder().encode(configuration))
    self.configuration = configuration
  }
}

/// One bounded public record per origin, with cross-instance compare-and-swap.
/// Secrets, issued credentials and Wallet snapshots are never stored here.
public final class ResourceRegistry {
  private let directory: URL
  public init(directory: URL) throws {
    self.directory = directory
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
      attributes: [.posixPermissions: 0o700])
  }
  private func file(_ origin: String) -> URL {
    let digest = SHA256.hash(data: Data(origin.utf8)).map { String(format: "%02x", $0) }.joined()
    return directory.appendingPathComponent(digest + ".json")
  }
  public func load() throws -> [RegisteredResource] {
    let urls = try FileManager.default.contentsOfDirectory(at: directory,
      includingPropertiesForKeys: nil).filter { $0.pathExtension == "json" }
    guard urls.count <= 100 else { throw WorkServerSetupError.storage }
    return try urls.map { url in
      let item = try read(url)
      // File coordination may canonicalize /var to /private/var. Enumeration
      // already constrains the parent; compare the content-addressed basename.
      guard file(item.id).lastPathComponent == url.lastPathComponent else { throw WorkServerSetupError.storage }
      return item
    }.sorted { $0.configuration.name == $1.configuration.name ? $0.id < $1.id
      : $0.configuration.name < $1.configuration.name }
  }
  private func read(_ url: URL) throws -> RegisteredResource {
    let values = try url.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey])
    guard values.isRegularFile == true, values.isSymbolicLink != true else {
      throw WorkServerSetupError.storage
    }
    return try RegisteredResource(configuration: WorkServerSettings.readFile(url))
  }
  public func save(_ value: RegisteredResource?, replacing expected: RegisteredResource?) throws {
    guard let origin = value?.id ?? expected?.id, value == nil || expected == nil || value?.id == expected?.id
    else { throw WorkServerSetupError.changed }
    let url = file(origin)
    var coordinationError: NSError?
    var result: Result<Void, Error> = .failure(WorkServerSetupError.storage)
    NSFileCoordinator().coordinate(writingItemAt: url, options: .forMerging,
      error: &coordinationError) { coordinated in
      result = Result {
        let exists = FileManager.default.fileExists(atPath: coordinated.path)
        let current = exists ? try read(coordinated) : nil
        guard current == expected else { throw WorkServerSetupError.changed }
        if let value {
          _ = try RegisteredResource(configuration: value.configuration)
          if !exists { guard try load().count < 100 else { throw WorkServerSetupError.storage } }
          try JSONEncoder().encode(value.configuration).write(to: coordinated, options: .atomic)
          try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: coordinated.path)
        } else if exists { try FileManager.default.removeItem(at: coordinated) }
      }
    }
    if coordinationError != nil { throw WorkServerSetupError.storage }
    try result.get()
  }
}
