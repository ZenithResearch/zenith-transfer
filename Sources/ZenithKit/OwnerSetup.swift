#if os(macOS)
import CryptoKit
import Darwin
import Foundation

public enum OwnerSetupError: LocalizedError {
  case unavailable, changed, invalid, emptyScope, walletLocked, selectedConnectionUpgradeRequired
  public var errorDescription: String? {
    switch self {
    case .unavailable: return "Could not inspect this Mac’s configured DevGraph. Check that DevGraph is installed and running."
    case .changed: return "The local DevGraph or this setup changed. Reload it and review again."
    case .invalid: return "Review the Wallet, HTTPS address, permissions and selected paths."
    case .emptyScope: return "Choose at least one Arena, Initiative or Project, or explicitly choose the entire graph."
    case .walletLocked: return "Unlock your Transfer Wallet to choose it as this graph’s owner."
    case .selectedConnectionUpgradeRequired: return "Wallet administration is not available on this selected connection yet. The installed DevGraph needs matching Wallet administration support. Your connection has not been changed and no new listener has been selected."
    }
  }
}

/// Owner registration inherits the selected resource's exact endpoint. It must
/// never infer an IP/port or borrow another saved connection as a substitute.
public struct OwnerRegistrationTarget: Equatable, Sendable {
  public let resourceID: String
  public let endpoint: String
  public let name: String
  public init(resource: LocalResource) {
    resourceID = resource.id; endpoint = resource.endpoint; name = resource.name
  }
  public var needsInstalledWalletSupport: Bool {
    // Current native credential transport requires HTTPS. The installed private
    // HTTP API does not expose Wallet administration. Do not silently create a
    // different listener or weaken transport validation to make setup proceed.
    !OwnerSetupPlan.localWalletAddress(endpoint)
  }
  public func check(_ plan: OwnerSetupPlan) throws {
    guard plan.resourceID == resourceID, plan.resourceName == name,
      plan.localEndpoint == endpoint else { throw OwnerSetupError.changed }
    if plan.schema == "zenith.devgraph-owner-setup.v3" {
      try plan.validate()
    } else if plan.walletEndpoint != endpoint { throw OwnerSetupError.changed }
  }
}

public struct OwnerScopeNode: Codable, Equatable, Identifiable, Sendable {
  public let kind: String
  public let resourceID: String
  public let title: String
  public let path: [String]
  enum CodingKeys: String, CodingKey { case kind, title, path; case resourceID = "resource_id" }
  public var id: String { kind + "/" + resourceID }
  public var expandable: Bool { kind != "Project" }
  public init(kind: String, resourceID: String, title: String, path: [String]) throws {
    let allowed = ["Arena", "Initiative", "Project"]
    guard let rank = allowed.firstIndex(of: kind), Self.identifier(resourceID),
      !title.isEmpty, title.unicodeScalars.count <= 4096, path.last == kind + "/" + resourceID,
      path.count == rank + 1, path.enumerated().allSatisfy({ index, part in
        part.hasPrefix(allowed[index] + "/") && Self.identifier(String(part.dropFirst(allowed[index].count + 1)))
      }) else { throw OwnerSetupError.invalid }
    self.kind = kind; self.resourceID = resourceID; self.title = title; self.path = path
  }
  public static func identifier(_ value: String) -> Bool {
    value.range(of: "^[a-z0-9][a-z0-9-]{0,255}$", options: .regularExpression) != nil
  }
}

public enum OwnerPermissionPreset: String, Codable, CaseIterable, Sendable {
  case reader, contributor, projectManager = "project-manager", custom
  public var title: String { switch self {
    case .reader: return "Read only"
    case .contributor: return "Contributor"
    case .projectManager: return "Project Manager"
    case .custom: return "Custom permissions"
  } }
  public var operations: [String] { switch self {
    case .reader, .custom: return []
    case .contributor: return Array(Self.allOperations.prefix(7))
    case .projectManager: return Self.allOperations
  } }
  public static let allOperations = ["create", "patch", "progress.set", "dependency.add", "dependency.remove", "blocker.add", "blocker.remove", "parent.set", "workflow.assign", "workflow.transition", "archive", "restore"]
  public static func title(_ operation: String) -> String {
    ["create":"Create work", "patch":"Edit details", "progress.set":"Change progress", "dependency.add":"Add dependencies", "dependency.remove":"Remove dependencies", "blocker.add":"Add blockers", "blocker.remove":"Remove blockers", "parent.set":"Move work", "workflow.assign":"Assign workflows", "workflow.transition":"Transition workflow stages", "archive":"Archive work", "restore":"Restore work"][operation] ?? operation
  }
}

/// A reviewed configuration proposal, not an active credential or ownership proof.
/// Installation must recheck both local fingerprints and obtain its own approval.
public struct OwnerSetupPlan: Codable, Equatable, Sendable {
  public let schema: String
  public let resourceID: String
  public let resourceName: String
  public let localEndpoint: String
  public let registrationSHA256: String
  public let configurationSHA256: String
  public let ownerPublicKey: String
  public let walletEndpoint: String
  public let preset: OwnerPermissionPreset
  public let writeOperations: [String]
  public let readOperations: [String]?
  public let presetSnapshot: CredentialPresetRevision?
  public var effectiveReads: [String] { readOperations ?? CredentialPresetRevision.allReads }
  public let scopeMode: String
  public let paths: [OwnerScopeNode]
  public let notBefore: UInt64
  public let notAfter: UInt64?
  public let publishHierarchy: Bool
  public let status: String
  enum CodingKeys: String, CodingKey {
    case schema, preset, paths, status
    case readOperations = "read_operations", presetSnapshot = "preset_snapshot"
    case resourceID = "resource_id", resourceName = "resource_name", localEndpoint = "local_endpoint"
    case registrationSHA256 = "registration_sha256", configurationSHA256 = "configuration_sha256"
    case ownerPublicKey = "owner_public_key", walletEndpoint = "wallet_endpoint"
    case writeOperations = "write_operations", scopeMode = "scope_mode"
    case notBefore = "not_before", notAfter = "not_after", publishHierarchy = "publish_hierarchy"
  }
  public init(resource: LocalResource, registrationSHA256: String, configurationSHA256: String,
    ownerPublicKey: String, walletEndpoint: String, preset: OwnerPermissionPreset,
    writeOperations: [String], global: Bool, paths: [OwnerScopeNode], notBefore: UInt64,
    notAfter: UInt64?, publishHierarchy: Bool, readOperations: [String]? = nil,
    presetSnapshot: CredentialPresetRevision? = nil, walletAdminUpgrade: Bool = false) throws {
    self.schema = walletAdminUpgrade ? "zenith.devgraph-owner-setup.v3" : (readOperations != nil || presetSnapshot != nil ? "zenith.devgraph-owner-setup.v2" : "zenith.devgraph-owner-setup.v1"); self.status = "prepared_not_applied"
    resourceID = resource.id; resourceName = resource.name; localEndpoint = resource.endpoint
    self.registrationSHA256 = registrationSHA256; self.configurationSHA256 = configurationSHA256
    self.ownerPublicKey = ownerPublicKey; self.walletEndpoint = walletEndpoint
    self.preset = preset; self.writeOperations = writeOperations
    self.readOperations = readOperations ?? (presetSnapshot != nil ? presetSnapshot?.readOperations : nil)
    self.presetSnapshot = presetSnapshot
    scopeMode = global ? "global" : "paths"; self.paths = Self.normalized(paths)
    self.notBefore = notBefore; self.notAfter = notAfter; self.publishHierarchy = publishHierarchy
    try validate()
  }
  /// Local owner bootstrap is not a member credential. The owner can manage all
  /// supported grant operations; recipient permissions are selected separately.
  /// Retain v1/v2 decoding for previously saved, explicitly reviewed server plans.
  public static func ownerBootstrap(resource: LocalResource, inspection: OwnerSetupInspection,
    ownerPublicKey: String, walletEndpoint: String, now: UInt64, publishHierarchy: Bool = false) throws -> Self {
    guard inspection.healthy, inspection.resource == resource else { throw OwnerSetupError.changed }
    return try Self(resource: resource, registrationSHA256: inspection.registrationSHA256,
      configurationSHA256: inspection.configurationSHA256, ownerPublicKey: ownerPublicKey,
      walletEndpoint: walletEndpoint, preset: .projectManager,
      writeOperations: OwnerPermissionPreset.allOperations, global: true, paths: [],
      notBefore: now, notAfter: nil, publishHierarchy: publishHierarchy,
      readOperations: CredentialPresetRevision.allReads)
  }
  public static func localWalletAddress(_ value: String) -> Bool {
    guard let url = try? WorkServerSettings.address(value), url.absoluteString == value,
      let host = url.host, let port = url.port, (1024...65535).contains(port), ![8080, 7687].contains(port) else { return false }
    if host == "127.0.0.1" || host == "localhost" { return true }
    let parts = host.split(separator: ".").compactMap { UInt8($0) }
    return parts.count == 4 && parts.map(String.init).joined(separator: ".") == host && (parts[0] == 10 || (parts[0] == 172 && (16...31).contains(parts[1])) || (parts[0] == 192 && parts[1] == 168))
  }
  public static func normalized(_ values: [OwnerScopeNode]) -> [OwnerScopeNode] {
    let unique = Dictionary(values.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a }).values
    return unique.filter { node in !unique.contains { other in
      other.id != node.id && other.path.count < node.path.count && node.path.starts(with: other.path)
    }}.sorted { $0.id < $1.id }
  }
  public func validate() throws {
    func hex(_ value: String) -> Bool { value.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil }
    guard ["zenith.devgraph-owner-setup.v1", "zenith.devgraph-owner-setup.v2", "zenith.devgraph-owner-setup.v3"].contains(schema), status == "prepared_not_applied",
      UUID(uuidString: resourceID)?.uuidString.lowercased() == resourceID,
      !resourceName.isEmpty, resourceName.unicodeScalars.count <= 80,
      hex(registrationSHA256), hex(configurationSHA256), hex(ownerPublicKey),
      scopeMode == "global" || scopeMode == "paths", paths.count <= 16,
      notBefore <= 9_007_199_254_740_991,
      notAfter.map({ $0 > notBefore && $0 <= 9_007_199_254_740_991 }) ?? true,
      Set(writeOperations).count == writeOperations.count,
      Set(writeOperations).isSubset(of: Set(OwnerPermissionPreset.allOperations)),
      preset == .custom || writeOperations == preset.operations,
      Self.localWalletAddress(walletEndpoint)
    else { throw OwnerSetupError.invalid }
    if schema == "zenith.devgraph-owner-setup.v3" {
      guard let source = URLComponents(string:localEndpoint), source.scheme == "http", source.host == "127.0.0.1",
        let port = source.port, (1024...65535).contains(port), localEndpoint == "http://127.0.0.1:\(port)",
        URL(string:walletEndpoint)?.host == "127.0.0.1", preset == .projectManager,
        scopeMode == "global", paths.isEmpty, notAfter == nil, !publishHierarchy, presetSnapshot == nil,
        writeOperations == OwnerPermissionPreset.allOperations, readOperations == CredentialPresetRevision.allReads
      else { throw OwnerSetupError.invalid }
    } else if localEndpoint != "http://127.0.0.1:8080" { throw OwnerSetupError.invalid }
    if schema == "zenith.devgraph-owner-setup.v1" {
      guard readOperations == nil, presetSnapshot == nil else { throw OwnerSetupError.invalid }
    } else {
      guard let reads = readOperations, reads == CredentialPresetRevision.allReads.filter({ reads.contains($0) }),
        !reads.isEmpty || !writeOperations.isEmpty else { throw OwnerSetupError.invalid }
      if let snapshot = presetSnapshot {
        try snapshot.validate()
        guard !snapshot.archived, preset == .custom, snapshot.readOperations == reads,
          snapshot.writeOperations == writeOperations else { throw OwnerSetupError.invalid }
      }
    }
    guard (scopeMode == "global" && paths.isEmpty) || (scopeMode == "paths" && !paths.isEmpty)
    else { throw OwnerSetupError.emptyScope }
    for node in paths { _ = try OwnerScopeNode(kind: node.kind, resourceID: node.resourceID, title: node.title, path: node.path) }
    guard paths == Self.normalized(paths) else { throw OwnerSetupError.invalid }
  }
  public static func decode(_ data: Data) throws -> OwnerSetupPlan {
    var reader = OwnerPlanJSON(data); try reader.validate()
    guard let raw = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw OwnerSetupError.invalid }
    let required: Set<String> = ["schema", "resource_id", "resource_name", "local_endpoint", "registration_sha256", "configuration_sha256", "owner_public_key", "wallet_endpoint", "preset", "write_operations", "scope_mode", "paths", "not_before", "publish_hierarchy", "status"]
    let v2 = ["zenith.devgraph-owner-setup.v2","zenith.devgraph-owner-setup.v3"].contains(raw["schema"] as? String ?? "")
    let allowed = required.union(v2 ? ["not_after", "read_operations", "preset_snapshot"] : ["not_after"])
    guard required.isSubset(of: Set(raw.keys)), Set(raw.keys).isSubset(of: allowed), !v2 || raw["read_operations"] != nil,
      let paths = raw["paths"] as? [[String: Any]], paths.allSatisfy({ Set($0.keys) == ["kind", "resource_id", "title", "path"] }) else { throw OwnerSetupError.invalid }
    if let snapshot = raw["preset_snapshot"] {
      guard let row = snapshot as? [String: Any] else { throw OwnerSetupError.invalid }
      try CredentialPresetRevision.checkKeys(row)
    }
    let result = try JSONDecoder().decode(Self.self, from: data); try result.validate(); return result
  }
  public func encoded() throws -> Data {
    try validate(); let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    let data = try encoder.encode(self)
    guard data.count <= 65536 else { throw OwnerSetupError.invalid }; return data
  }
  public var digest: String { (try? encoded()).map(Self.sha256) ?? "" }
  public static func sha256(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
}

public struct OwnerScopePage: Sendable {
  public let nodes: [OwnerScopeNode]
  public let after: String?
}

public struct OwnerSetupInspection: Sendable {
  public let resource: LocalResource
  public let registrationSHA256: String
  public let configurationSHA256: String
  public let healthy: Bool
}

/// Only fixed read commands to the installed per-user CLI. No caller-selected
/// executable, data root, credential, environment, shell or remote endpoint.
public struct OwnerSetupInspector: Sendable {
  public init() { }
  static func privateData(_ url: URL, maximum: Int = 32768) throws -> Data {
    let fd = Darwin.open(url.path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK)
    guard fd >= 0 else { throw OwnerSetupError.unavailable }
    let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true); defer { try? handle.close() }
    var info = stat()
    guard fstat(fd, &info) == 0, info.st_uid == getuid(), info.st_nlink == 1,
      info.st_mode & S_IFMT == S_IFREG, info.st_mode & 0o077 == 0, info.st_size <= maximum
    else { throw OwnerSetupError.unavailable }
    return try handle.read(upToCount: maximum + 1) ?? Data()
  }
  public func inspect(_ selected: LocalResource) async throws -> OwnerSetupInspection {
    let base = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/Zenith/Devgraph")
    let registration = try Self.privateData(base.appendingPathComponent("resource-registration.json"))
    let current = try LocalResource.decode(registration)
    guard current.id == selected.id, current.endpoint == selected.endpoint,
      current.name == selected.name, current.connection == selected.connection else { throw OwnerSetupError.changed }
    let configuration = try Self.privateData(base.appendingPathComponent("local.json"))
    let raw = try await run(["local", "status"])
    return try Self.verifiedInspection(selected, registration: registration, configuration: configuration, status: raw)
  }
  /// Verify the fixed CLI's actual reported endpoint against the selected
  /// registration. Never treat a healthy different local server as this target.
  static func verifiedInspection(_ selected: LocalResource, registration: Data,
    configuration: Data, status raw: Data) throws -> OwnerSetupInspection {
    let current = try LocalResource.decode(registration)
    guard current == selected else { throw OwnerSetupError.changed }
    guard let status = try JSONSerialization.jsonObject(with: raw) as? [String: Any],
      status["healthy"] as? Bool == true else { throw OwnerSetupError.unavailable }
    guard let api = status["api"] as? [String: Any],
      let checks = api["api"] as? [String: Any], checks["base_url"] as? String == selected.endpoint
    else { throw OwnerSetupError.changed }
    return OwnerSetupInspection(resource: current, registrationSHA256: OwnerSetupPlan.sha256(registration),
      configurationSHA256: OwnerSetupPlan.sha256(configuration), healthy: true)
  }
  public func page(parent: OwnerScopeNode?, after: String? = nil) async throws -> OwnerScopePage {
    var args: [String]
    if let parent {
      _ = try OwnerScopeNode(kind: parent.kind, resourceID: parent.resourceID, title: parent.title, path: parent.path)
      guard parent.expandable else { return OwnerScopePage(nodes: [], after: nil) }
      args = parent.kind == "Arena" ? ["query", "arena-members", parent.resourceID] : ["query", "children", "Initiative", parent.resourceID]
      args += ["--limit", "100"]
      if let after { args += ["--after-resource", after] }
    } else {
      args = ["query", "arena", "--limit", "100"]
      if let after { args += ["--after-id", after] }
    }
    let data = try await run(args)
    guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any], let items = object["items"] as? [[String: Any]], items.count <= 100 else { throw OwnerSetupError.unavailable }
    let kind = parent == nil ? "Arena" : (parent!.kind == "Arena" ? "Initiative" : "Project")
    let nodes = try items.compactMap { item -> OwnerScopeNode? in
      guard item["kind"] as? String == kind, item["archived"] as? Bool != true,
        let id = item["id"] as? String, let title = item["title"] as? String else { return nil }
      return try OwnerScopeNode(kind: kind, resourceID: id, title: title, path: (parent?.path ?? []) + [kind + "/" + id])
    }
    var cursor: String?
    if items.count == 100, let last = items.last, let id = last["id"] as? String,
      OwnerScopeNode.identifier(id) {
      cursor = parent == nil ? id : (last["kind"] as? String).map { $0 + "/" + id }
    }
    return OwnerScopePage(nodes: nodes, after: cursor)
  }
  private func run(_ arguments: [String]) async throws -> Data {
    try await Task.detached {
      let executable = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".local/bin/devgraph")
      var info = stat()
      guard lstat(executable.path, &info) == 0, info.st_uid == getuid(), info.st_nlink == 1,
        info.st_mode & S_IFMT == S_IFREG, info.st_mode & 0o022 == 0, info.st_mode & 0o100 != 0 else { throw OwnerSetupError.unavailable }
      let process = Process(); let output = Pipe()
      process.executableURL = executable; process.arguments = arguments
      process.environment = ["PATH":"/usr/bin:/bin:/usr/sbin:/sbin", "LANG":"en_US.UTF-8", "PYTHONDONTWRITEBYTECODE":"1"]
      process.standardInput = FileHandle.nullDevice; process.standardOutput = output; process.standardError = FileHandle.nullDevice
      try process.run()
      let deadline = DispatchWorkItem { if process.isRunning { process.terminate() } }
      DispatchQueue.global().asyncAfter(deadline: .now() + 15, execute: deadline)
      defer { deadline.cancel() }
      var data = Data()
      while let part = try output.fileHandleForReading.read(upToCount: 65536), !part.isEmpty {
        data.append(part)
        guard data.count <= 4_194_304 else { if process.isRunning { process.terminate() }; throw OwnerSetupError.unavailable }
      }
      process.waitUntilExit()
      guard process.terminationStatus == 0 else { throw OwnerSetupError.unavailable }
      return data
    }.value
  }
}

/// Pending setup lives separately from connections and active server policies.
public final class OwnerSetupStore {
  private let directory: URL
  public init(directory: URL) throws {
    self.directory = directory
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    var info = stat()
    guard lstat(directory.path, &info) == 0, info.st_uid == getuid(), info.st_mode & S_IFMT == S_IFDIR,
      info.st_mode & 0o077 == 0 else { throw OwnerSetupError.unavailable }
  }
  public func load(resourceID: String) throws -> OwnerSetupPlan? {
    guard UUID(uuidString: resourceID)?.uuidString.lowercased() == resourceID else { throw OwnerSetupError.invalid }
    let file = directory.appendingPathComponent(resourceID + ".json")
    guard FileManager.default.fileExists(atPath: file.path) else { return nil }
    let value = try OwnerSetupPlan.decode(OwnerSetupInspector.privateData(file, maximum: 65536))
    try value.validate(); guard value.resourceID == resourceID else { throw OwnerSetupError.changed }; return value
  }
  public func save(_ plan: OwnerSetupPlan, replacing expected: OwnerSetupPlan?) throws {
    try plan.validate()
    let file = directory.appendingPathComponent(plan.resourceID + ".json")
    var error: NSError?; var result: Result<Void, Error> = .failure(OwnerSetupError.unavailable)
    NSFileCoordinator().coordinate(writingItemAt: file, options: .forMerging, error: &error) { coordinated in
      result = Result {
        guard try load(resourceID: plan.resourceID) == expected else { throw OwnerSetupError.changed }
        try plan.encoded().write(to: coordinated, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: coordinated.path)
      }
    }
    if error != nil { throw OwnerSetupError.unavailable }; try result.get()
  }
}

/// Bounded integer-only JSON; decode escaped keys before duplicate detection.
struct OwnerPlanJSON {
  let bytes: [UInt8]; var cursor = 0
  let maximumBytes: Int, maximumKeys: Int, maximumArray: Int, maximumDepth: Int
  let allowNegativeIntegers: Bool
  init(_ data: Data, maximumBytes: Int = 65536, maximumKeys: Int = 20, maximumArray: Int = 64, maximumDepth: Int = 8, allowNegativeIntegers: Bool = false) {
    bytes = Array(data); self.maximumBytes = maximumBytes; self.maximumKeys = maximumKeys
    self.maximumArray = maximumArray; self.maximumDepth = maximumDepth; self.allowNegativeIntegers = allowNegativeIntegers
  }
  mutating func space() { while cursor < bytes.count && [9,10,13,32].contains(bytes[cursor]) { cursor += 1 } }
  mutating func take(_ byte: UInt8) throws {
    space(); guard cursor < bytes.count, bytes[cursor] == byte else { throw OwnerSetupError.invalid }; cursor += 1
  }
  mutating func string() throws -> String {
    space(); let start = cursor; try take(34); var escaped = false
    while cursor < bytes.count {
      let byte = bytes[cursor]; cursor += 1
      if escaped { escaped = false; continue }
      if byte == 92 { escaped = true; continue }
      if byte == 34 { return try JSONDecoder().decode(String.self, from: Data(bytes[start..<cursor])) }
    }
    throw OwnerSetupError.invalid
  }
  mutating func value(_ depth: Int) throws {
    space(); guard depth <= maximumDepth, cursor < bytes.count else { throw OwnerSetupError.invalid }
    switch bytes[cursor] {
    case 34: _ = try string()
    case 123:
      try take(123); space(); var keys: Set<String> = []
      if cursor < bytes.count && bytes[cursor] == 125 { cursor += 1; return }
      while true {
        let key = try string(); guard keys.insert(key).inserted, keys.count <= maximumKeys else { throw OwnerSetupError.invalid }
        try take(58); try value(depth+1); space()
        guard cursor < bytes.count else { throw OwnerSetupError.invalid }
        if bytes[cursor] == 125 { cursor += 1; break }; try take(44)
      }
    case 91:
      try take(91); space(); var count = 0
      if cursor < bytes.count && bytes[cursor] == 93 { cursor += 1; return }
      while true {
        count += 1; guard count <= maximumArray else { throw OwnerSetupError.invalid }
        try value(depth+1); space(); guard cursor < bytes.count else { throw OwnerSetupError.invalid }
        if bytes[cursor] == 93 { cursor += 1; break }; try take(44)
      }
    default:
      for literal in ["true", "false", "null"] {
        if bytes[cursor...].starts(with: Array(literal.utf8)) { cursor += literal.utf8.count; return }
      }
      let negative = allowNegativeIntegers && bytes[cursor] == 45
      if negative { cursor += 1 }
      let start = cursor
      while cursor < bytes.count && (48...57).contains(bytes[cursor]) { cursor += 1 }
      guard cursor > start, cursor - start == 1 || bytes[start] != 48,
        let value = UInt64(String(decoding: bytes[start..<cursor], as: UTF8.self)), value <= 9_007_199_254_740_991,
        !negative || value != 0 else { throw OwnerSetupError.invalid }
    }
  }
  mutating func validate() throws {
    guard !bytes.isEmpty, bytes.count <= maximumBytes else { throw OwnerSetupError.invalid }
    try value(0); space(); guard cursor == bytes.count else { throw OwnerSetupError.invalid }
  }
}
#endif
