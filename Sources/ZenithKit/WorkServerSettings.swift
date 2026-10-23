import Foundation

public enum WorkServerSetupError: LocalizedError {
  case address, profile, storage, changed
  public var errorDescription: String? {
    switch self {
    case .address: return "Enter an HTTPS server address, without a path, password or query."
    case .profile: return "Choose a Devgraph connection file from your server administrator. It must contain only the server address and public verification settings."
    case .storage: return "Could not save the server settings. Try again after unlocking your device."
    case .changed: return "The saved server changed. Reopen Work access before continuing."
    }
  }
}

/// Public setup supplied by the operator, separately from the enrollment response.
/// This contains no membership, credential, private key or granted permission.
public enum WorkServerSettings {
  public static let maximumFileBytes = 16_384

  public static func address(_ text: String) throws -> URL {
    let text = text.trimmingCharacters(in: .whitespacesAndNewlines)
    guard text.count <= 2048, let url = URL(string: text), url.scheme == "https",
      let host = url.host, !host.isEmpty, url.user == nil, url.password == nil,
      url.query == nil, url.fragment == nil, url.path.isEmpty || url.path == "/",
      url.port.map({ (1...65535).contains($0) }) ?? true
    else { throw WorkServerSetupError.address }
    return url.path == "/" ? URL(string: String(url.absoluteString.dropLast()))! : url
  }

  public static func decode(_ data: Data) throws -> WorkAccessConfiguration {
    guard data.count <= maximumFileBytes,
      let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
      Set(object.keys).isSubset(of: ["name", "receiver", "issuer", "authority", "network", "tls_certificate_sha256"]),
      let authority = object["authority"] as? [String: Any],
      Set(authority.keys) == ["issuer", "key_id", "public_key", "receiver", "audience"],
      let value = try? JSONDecoder().decode(WorkAccessConfiguration.self, from: data),
      (try? value.validate()) != nil,
      (try? address(value.receiver.absoluteString)) != nil
    else { throw WorkServerSetupError.profile }
    return value
  }

  public static func readFile(_ url: URL) throws -> WorkAccessConfiguration {
    let file = try FileHandle(forReadingFrom: url)
    defer { try? file.close() }
    return try decode(file.read(upToCount: maximumFileBytes + 1) ?? Data())
  }
}

/// Installation-local, OS-protected public settings. Never a bundled default,
/// portable backup, read credential or substitute for Wallet consent.
public final class WorkServerStore {
  private let file: URL
  private let lock = NSRecursiveLock()
  public init(directory: URL) throws {
    do {
      try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
        attributes: [.posixPermissions: 0o700])
      var directory = directory
      var values = URLResourceValues()
      values.isExcludedFromBackup = true
      try directory.setResourceValues(values)
      #if os(iOS)
      try FileManager.default.setAttributes([.protectionKey: FileProtectionType.complete],
        ofItemAtPath: directory.path)
      #endif
      file = directory.appendingPathComponent("work-server.json")
    } catch { throw WorkServerSetupError.storage }
  }
  public func load() throws -> WorkAccessConfiguration? {
    lock.lock(); defer { lock.unlock() }
    guard FileManager.default.fileExists(atPath: file.path) else { return nil }
    return try WorkServerSettings.readFile(file)
  }
  public func save(_ value: WorkAccessConfiguration?, replacing expected: WorkAccessConfiguration?) throws {
    lock.lock(); defer { lock.unlock() }
    guard try load() == expected else { throw WorkServerSetupError.changed }
    do {
      if let value {
        try value.validate()
        let data = try JSONEncoder().encode(value)
        _ = try WorkServerSettings.decode(data)
        #if os(iOS)
        try data.write(to: file, options: [.atomic, .completeFileProtection])
        #else
        try data.write(to: file, options: .atomic)
        #endif
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
      } else if expected != nil {
        try FileManager.default.removeItem(at: file)
      }
    } catch { throw WorkServerSetupError.storage }
  }
}
