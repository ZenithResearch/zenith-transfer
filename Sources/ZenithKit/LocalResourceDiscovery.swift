#if os(macOS)
import Darwin
import Foundation

/// Advisory per-user service metadata. An ID is a stable local identifier,
/// never a claim of ownership, liveness, issuer trust or granted permission.
public struct LocalResource: Decodable, Identifiable, Equatable, Sendable {
  public let resource_id: String
  public let name: String
  public let endpoint: String
  public let connection: WorkAccessConfiguration?
  public let updated_at: UInt64
  public var id: String { resource_id }
  public var monitorURL: URL { URL(string: endpoint + "/monitor/")! }
  public static let schema = "zenith.local-resource.v1"
  public static let maximumBytes = 32_768

  public static func decode(_ data: Data) throws -> LocalResource {
    var strict = LocalResourceJSON(data)
    try strict.validate()
    guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
      Set(object.keys) == ["schema", "resource_id", "kind", "name", "endpoint", "connection", "updated_at"],
      object["schema"] as? String == schema, object["kind"] as? String == "devgraph",
      let value = try? JSONDecoder().decode(LocalResource.self, from: data),
      UUID(uuidString: value.id)?.uuidString.lowercased() == value.id,
      !value.name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
      value.name.unicodeScalars.count <= 80, Self.publicText(value.name),
      value.updated_at <= 9_007_199_254_740_991,
      value.endpoint.utf8.count <= 2048, Self.publicText(value.endpoint),
      let url = URL(string: value.endpoint), url.absoluteString == value.endpoint,
      url.host != nil, url.user == nil, url.password == nil, url.query == nil, url.fragment == nil,
      url.path.isEmpty, url.port.map({ (1...65535).contains($0) }) ?? true,
      url.scheme == "https" || (url.scheme == "http" && ["127.0.0.1", "[::1]", "::1", "localhost"].contains(url.host!))
    else { throw WorkServerSetupError.profile }
    if let connection = object["connection"] as? [String: Any] {
      let profile = try WorkServerSettings.decode(JSONSerialization.data(withJSONObject: connection))
      guard profile.origin == value.endpoint, profile.name == value.name else { throw WorkServerSetupError.profile }
    } else if !(object["connection"] is NSNull) { throw WorkServerSetupError.profile }
    return value
  }
  private static func publicText(_ value: String) -> Bool {
    value.unicodeScalars.allSatisfy { $0.value >= 32 && $0.value != 127 }
  }
}

public struct LocalResourceScan: Sendable {
  public let resources: [LocalResource]
  public let rejected: Int
  public let unavailable: Bool
}

public enum LocalResourceDiscovery {
  public static func directory(home: URL = FileManager.default.homeDirectoryForCurrentUser) -> URL {
    home.appendingPathComponent(".zenith/resources/v1", isDirectory: true)
  }
  public static func scan(home: URL = FileManager.default.homeDirectoryForCurrentUser) -> LocalResourceScan {
    var descriptor = Darwin.open(home.path, O_RDONLY | O_DIRECTORY)
    guard descriptor >= 0 else { return LocalResourceScan(resources: [], rejected: 0, unavailable: true) }
    defer { Darwin.close(descriptor) }
    for part in [".zenith", "resources", "v1"] {
      let next = openat(descriptor, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_NONBLOCK)
      guard next >= 0 else {
        return LocalResourceScan(resources: [], rejected: 0, unavailable: errno != ENOENT)
      }
      var info = stat()
      guard fstat(next, &info) == 0, info.st_uid == getuid(), info.st_mode & 0o077 == 0 else {
        Darwin.close(next); return LocalResourceScan(resources: [], rejected: 0, unavailable: true)
      }
      Darwin.close(descriptor); descriptor = next
    }
    // Enumerate through the held descriptor rather than following the path a
    // second time. The read-only duplicate is owned by fdopendir/closedir.
    guard let stream = fdopendir(dup(descriptor)) else { return LocalResourceScan(resources: [], rejected: 0, unavailable: true) }
    defer { closedir(stream) }
    var names: [String] = []
    while let item = readdir(stream) {
      let name = withUnsafePointer(to: &item.pointee.d_name) {
        $0.withMemoryRebound(to: CChar.self, capacity: Int(MAXNAMLEN) + 1) { String(cString: $0) }
      }
      if name.hasSuffix(".json") {
        names.append(name)
        guard names.count <= 100 else { return LocalResourceScan(resources: [], rejected: names.count, unavailable: true) }
      }
    }
    var resources: [LocalResource] = [], rejected = 0
    for name in names.sorted() {
      do {
        let fd = openat(descriptor, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK)
        guard fd >= 0 else { throw WorkServerSetupError.storage }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        defer { try? handle.close() }
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_uid == getuid(), info.st_mode & S_IFMT == S_IFREG,
          info.st_mode & 0o077 == 0, info.st_size <= LocalResource.maximumBytes else { throw WorkServerSetupError.storage }
        let value = try LocalResource.decode(handle.read(upToCount: LocalResource.maximumBytes + 1) ?? Data())
        guard name == value.id + ".json" else { throw WorkServerSetupError.storage }
        resources.append(value)
      } catch { rejected += 1 }
    }
    resources.sort { $0.name == $1.name ? $0.id < $1.id : $0.name < $1.name }
    return LocalResourceScan(resources: resources, rejected: rejected, unavailable: false)
  }
}

/// The closed discovery shape has objects, strings, null and unsigned integers.
/// Reject duplicate decoded keys (including escapes), float/bool tokens and
/// excessive nesting before Foundation can collapse or normalize them.
private struct LocalResourceJSON {
  let bytes: [UInt8]
  var cursor = 0
  init(_ data: Data) { bytes = Array(data) }
  func invalid() -> WorkServerSetupError { .profile }
  mutating func whitespace() { while cursor < bytes.count && [9, 10, 13, 32].contains(bytes[cursor]) { cursor += 1 } }
  mutating func take(_ b: UInt8) throws {
    whitespace(); guard cursor < bytes.count, bytes[cursor] == b else { throw invalid() }; cursor += 1
  }
  mutating func string() throws -> String {
    whitespace(); let start = cursor; try take(34)
    var escaped = false
    while cursor < bytes.count {
      let b = bytes[cursor]; cursor += 1
      if escaped { escaped = false; continue }
      if b == 92 { escaped = true; continue }
      if b == 34 { return try JSONDecoder().decode(String.self, from: Data(bytes[start..<cursor])) }
    }
    throw invalid()
  }
  mutating func object(depth: Int) throws {
    guard depth < 4 else { throw invalid() }
    try take(123); var keys: Set<String> = []
    whitespace()
    if cursor < bytes.count && bytes[cursor] == 125 { cursor += 1; return }
    while true {
      let key = try string(); guard keys.insert(key).inserted, keys.count <= 12 else { throw invalid() }
      try take(58); try value(depth: depth + 1); whitespace()
      guard cursor < bytes.count else { throw invalid() }
      if bytes[cursor] == 125 { cursor += 1; return }
      try take(44)
    }
  }
  mutating func value(depth: Int) throws {
    whitespace(); guard cursor < bytes.count else { throw invalid() }
    if bytes[cursor] == 123 { try object(depth: depth); return }
    if bytes[cursor] == 34 { _ = try string(); return }
    if bytes[cursor...].starts(with: Array("null".utf8)) { cursor += 4; return }
    let start = cursor
    while cursor < bytes.count && (48...57).contains(bytes[cursor]) { cursor += 1 }
    guard cursor > start, cursor - start == 1 || bytes[start] != 48,
      let n = UInt64(String(decoding: bytes[start..<cursor], as: UTF8.self)), n <= 9_007_199_254_740_991 else { throw invalid() }
  }
  mutating func validate() throws {
    guard !bytes.isEmpty, bytes.count <= LocalResource.maximumBytes else { throw invalid() }
    try object(depth: 0); whitespace(); guard cursor == bytes.count else { throw invalid() }
  }
}
#endif
