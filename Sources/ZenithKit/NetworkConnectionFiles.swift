import CryptoKit
import Darwin
import Foundation

public enum ConnectionFileKind: String, Sendable { case tailscale, devgraph }
public enum ConnectionFileFailure: Error, LocalizedError {
  case invalid, changed, storage
  public var errorDescription: String? {
    switch self {
    case .invalid: return "Choose a DevGraph connection JSON file or a text file containing only a Tailscale auth key. Wallet backups and API tokens are not connection files."
    case .changed: return "This file changed after review. Choose it again before connecting."
    case .storage: return "The connection file could not be read or saved. Choose a regular file you own."
    }
  }
}

/// Review metadata only: an enrollment secret is never retained in this value.
public struct ConnectionFileReview: Identifiable, Sendable {
  public var id: URL { file }
  public let file: URL
  public let kind: ConnectionFileKind
  public let configuration: WorkAccessConfiguration?
  private let digest: Data
  private init(file: URL, kind: ConnectionFileKind, configuration: WorkAccessConfiguration?, bytes: Data) {
    self.file = file; self.kind = kind; self.configuration = configuration
    digest = Data(SHA256.hash(data: bytes))
  }
  public static func read(_ file: URL, as kind: ConnectionFileKind) throws -> Self {
    let bytes = try NetworkConnectionFiles.read(file, maximum: kind == .tailscale ? 1024 : WorkServerSettings.maximumFileBytes)
    let configuration: WorkAccessConfiguration?
    if kind == .tailscale { _ = try TailscaleEnrollment.importKey(bytes); configuration = nil }
    else {
      var strict = OwnerPlanJSON(bytes, maximumBytes: WorkServerSettings.maximumFileBytes); try strict.validate()
      configuration = try WorkServerSettings.decode(bytes)
    }
    return Self(file: file, kind: kind, configuration: configuration, bytes: bytes)
  }
  private func current() throws -> Data {
    let bytes = try NetworkConnectionFiles.read(file, maximum: kind == .tailscale ? 1024 : WorkServerSettings.maximumFileBytes)
    guard Data(SHA256.hash(data: bytes)) == digest else { throw ConnectionFileFailure.changed }
    return bytes
  }
  public func selectedConfiguration() throws -> WorkAccessConfiguration {
    guard kind == .devgraph else { throw ConnectionFileFailure.invalid }
    return try WorkServerSettings.decode(current())
  }
  public func selectedEnrollmentKey() throws -> String {
    guard kind == .tailscale else { throw ConnectionFileFailure.invalid }
    return try TailscaleEnrollment.importKey(current())
  }
}

public enum NetworkConnectionFiles {
  public static func directory(applicationDirectory: URL) throws -> URL {
    let folder = applicationDirectory.appendingPathComponent("ConnectionFiles", isDirectory: true)
    try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    var info = stat()
    guard lstat(folder.path, &info) == 0, info.st_mode & S_IFMT == S_IFDIR, info.st_uid == getuid(), info.st_mode & 0o077 == 0 else { throw ConnectionFileFailure.storage }
    var excluded = folder; var values = URLResourceValues(); values.isExcludedFromBackup = true
    try excluded.setResourceValues(values)
    return folder
  }
  public static func scan(_ directory: URL) throws -> [ConnectionFileReview] {
    let files = try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil, options: [.skipsHiddenFiles])
    guard files.count <= 100 else { throw ConnectionFileFailure.storage }
    return files.sorted { $0.lastPathComponent < $1.lastPathComponent }.compactMap { file in
      let ext = file.pathExtension.lowercased()
      guard ["json", "txt", "key", "tailscale-key"].contains(ext) else { return nil }
      return try? ConnectionFileReview.read(file, as: ext == "json" ? .devgraph : .tailscale)
    }
  }
  public static func read(_ file: URL, maximum: Int) throws -> Data {
    guard file.isFileURL else { throw ConnectionFileFailure.storage }
    let scoped = file.startAccessingSecurityScopedResource()
    defer { if scoped { file.stopAccessingSecurityScopedResource() } }
    let fd = Darwin.open(file.path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK)
    guard fd >= 0 else { throw ConnectionFileFailure.storage }
    let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true); defer { try? handle.close() }
    var info = stat()
    guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG, info.st_uid == getuid(), info.st_nlink == 1,
      info.st_size > 0, info.st_size <= maximum else { throw ConnectionFileFailure.invalid }
    let bytes = try handle.read(upToCount: maximum + 1) ?? Data()
    guard !bytes.isEmpty, bytes.count <= maximum else { throw ConnectionFileFailure.invalid }
    return bytes
  }
  /// Explicit save only; refuses overwriting an existing file or following links.
  public static func saveEnrollmentKey(_ key: String, to file: URL) throws {
    let bytes = Data((try TailscaleEnrollment.validatedKey(key) + "\n").utf8)
    try save(bytes, to: file)
  }
  public static func saveConfiguration(_ value: WorkAccessConfiguration, to file: URL) throws {
    let bytes = try JSONEncoder().encode(value); _ = try WorkServerSettings.decode(bytes)
    try save(bytes, to: file)
  }
  private static func save(_ bytes: Data, to file: URL) throws {
    let fd = Darwin.open(file.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
    guard fd >= 0 else { throw ConnectionFileFailure.storage }
    let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true); defer { try? handle.close() }
    do { try handle.write(contentsOf: bytes); try handle.synchronize() }
    catch { try? FileManager.default.removeItem(at: file); throw ConnectionFileFailure.storage }
    var excluded = file; var values = URLResourceValues(); values.isExcludedFromBackup = true
    try? excluded.setResourceValues(values)
  }
}
