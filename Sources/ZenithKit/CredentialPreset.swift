#if os(macOS)
import Foundation
import Darwin

public enum CredentialPresetError: LocalizedError {
  case invalid, changed, storage, revisionLimit
  public var errorDescription: String? {
    switch self {
    case .invalid: return "Check the preset name, permissions and ontology references."
    case .changed: return "This preset changed elsewhere. Reload before saving another revision."
    case .storage: return "The preset library could not be read safely. Existing files are preserved."
    case .revisionLimit: return "This preset has reached its revision limit. Duplicate it to continue."
    }
  }
}

/// Descriptive association only. No class, seat assignment or label grants authority.
/// Both IRIs must come from the shared ontology; Transfer never synthesizes a Seat class.
public struct PresetSeatAssociation: Codable, Equatable, Sendable {
  public static let sharedSeatClassIRI = "https://zenith-research.ca/ontology/terms/Seat"
  public let seatClassIRI: String
  public let seatTypeIRI: String
  public let label: String
  enum CodingKeys: String, CodingKey { case seatClassIRI = "seat_class_iri", seatTypeIRI = "seat_type_iri", label }
  public init(seatClassIRI: String, seatTypeIRI: String, label: String) throws {
    self.seatClassIRI = seatClassIRI; self.seatTypeIRI = seatTypeIRI; self.label = label
    try validate()
  }
  public func validate() throws {
    func iri(_ raw: String) -> Bool {
      guard raw.unicodeScalars.count <= 2048, !raw.unicodeScalars.contains(where: { $0.properties.isWhitespace || $0.value < 32 }),
        let url = URLComponents(string: raw), url.user == nil, url.password == nil else { return false }
      return (url.scheme == "https" && url.host?.isEmpty == false) || (raw.hasPrefix("urn:") && raw.count > 4)
    }
    guard seatClassIRI == Self.sharedSeatClassIRI, iri(seatTypeIRI), !label.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
      label.unicodeScalars.count <= 80 else { throw CredentialPresetError.invalid }
  }
}

/// Presentation only. These remain the existing Work-read operations; no new
/// authority is encoded by the labels or by selecting an Arena as a scope.
public enum WorkReadPermission: String, CaseIterable, Sendable {
  case list, get, relationships
  public var title: String {
    switch self {
    case .list: return "List Work"
    case .get: return "Read Work details"
    case .relationships: return "Read Work relationships"
    }
  }
  public var explanation: String {
    switch self {
    case .list: return "See permitted Work in the selected scope."
    case .get: return "Open the details of permitted Work in the selected scope."
    case .relationships: return "Read links between permitted Work. Related resources outside the scope stay inaccessible."
    }
  }
  public static let arenaAvailability = "Choosing an Arena as a Work scope limits its descendants. Reading the Arena record itself requires a separate Arena permission."
}

/// An immutable permission recipe. Scope, holder, validity and server approval are separate.
public struct CredentialPresetRevision: Codable, Equatable, Identifiable, Sendable {
  public let schema: String
  public let presetID: String
  public let revision: UInt64
  public let name: String
  public let description: String
  public let readOperations: [String]
  public let writeOperations: [String]
  public let arenaRead: Bool?
  public let seat: PresetSeatAssociation?
  public let archived: Bool
  public var id: String { presetID + ":" + String(revision) }
  public static let allReads = ["list", "get", "relationships"]
  enum CodingKeys: String, CodingKey {
    case schema, revision, name, description, seat, archived
    case arenaRead = "arena_read"
    case presetID = "preset_id", readOperations = "read_operations", writeOperations = "write_operations"
  }
  public init(presetID: String, revision: UInt64, name: String, description: String = "",
    readOperations: [String], writeOperations: [String], seat: PresetSeatAssociation? = nil, archived: Bool = false, arenaRead: Bool = false) throws {
    schema = arenaRead ? "zenith.credential-preset.v2" : "zenith.credential-preset.v1"; self.arenaRead = arenaRead ? true : nil; self.presetID = presetID; self.revision = revision
    self.name = name; self.description = description; self.readOperations = readOperations
    self.writeOperations = writeOperations; self.seat = seat; self.archived = archived
    try validate()
  }
  public func validate() throws {
    guard (schema == "zenith.credential-preset.v1" && arenaRead == nil || schema == "zenith.credential-preset.v2" && arenaRead == true), presetID.range(of: "^[a-z][a-z0-9-]{0,63}$", options: .regularExpression) != nil,
      revision > 0, revision <= 9_007_199_254_740_991,
      !name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty, name.unicodeScalars.count <= 80, description.unicodeScalars.count <= 2000,
      !readOperations.isEmpty || !writeOperations.isEmpty || arenaRead == true,
      Set(readOperations).count == readOperations.count, Set(writeOperations).count == writeOperations.count,
      readOperations == Self.allReads.filter({ readOperations.contains($0) }),
      writeOperations == OwnerPermissionPreset.allOperations.filter({ writeOperations.contains($0) })
    else { throw CredentialPresetError.invalid }
    try seat?.validate()
  }
  public func encoded() throws -> Data {
    try validate(); let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    return try encoder.encode(self)
  }
  public var digest: String { (try? encoded()).map(OwnerSetupPlan.sha256) ?? "" }
  public static func decode(_ data: Data) throws -> Self {
    var reader = OwnerPlanJSON(data); try reader.validate()
    guard let raw = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw CredentialPresetError.invalid }
    try checkKeys(raw)
    let value = try JSONDecoder().decode(Self.self, from: data); try value.validate(); return value
  }
  static func checkKeys(_ raw: [String: Any]) throws {
    let required: Set<String> = ["schema", "preset_id", "revision", "name", "description", "read_operations", "write_operations", "archived"]
    guard required.isSubset(of: Set(raw.keys)), Set(raw.keys).isSubset(of: required.union(raw["schema"] as? String == "zenith.credential-preset.v2" ? ["seat", "arena_read"] : ["seat"])) else { throw CredentialPresetError.invalid }
    if let seat = raw["seat"] {
      guard let seat = seat as? [String: Any], Set(seat.keys) == ["seat_class_iri", "seat_type_iri", "label"] else { throw CredentialPresetError.invalid }
    }
  }
  public static var builtins: [Self] {
    [OwnerPermissionPreset.reader, .contributor, .projectManager].map { preset in
      // Fixed application constants, verified through the same validator as custom recipes.
      try! Self(presetID: preset.rawValue, revision: 1, name: preset.title,
        description: "Built-in DevGraph permission recipe", readOperations: allReads, writeOperations: preset.operations)
    }
  }
}

/// Append-only revisions within one private, coordinated file per preset.
/// Editing cannot mutate snapshots already embedded in a reviewed setup or grant.
public final class CredentialPresetStore {
  private let directory: URL
  public init(directory: URL) throws {
    self.directory = directory
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    try checkDirectory()
  }
  private func checkDirectory() throws {
    var st = stat()
    guard lstat(directory.path, &st) == 0, st.st_uid == getuid(), st.st_mode & S_IFMT == S_IFDIR,
      st.st_mode & 0o077 == 0 else { throw CredentialPresetError.storage }
  }
  private func file(_ id: String) throws -> URL {
    guard id.range(of: "^custom-[a-f0-9-]{36}$", options: .regularExpression) != nil,
      UUID(uuidString: String(id.dropFirst(7)))?.uuidString.lowercased() == String(id.dropFirst(7)) else { throw CredentialPresetError.invalid }
    return directory.appendingPathComponent(id + ".json")
  }
  public func history(_ id: String) throws -> [CredentialPresetRevision] {
    try checkDirectory(); let url = try file(id)
    var st = stat()
    if lstat(url.path, &st) != 0 { if errno == ENOENT { return [] }; throw CredentialPresetError.storage }
    let data = try OwnerSetupInspector.privateData(url, maximum: 65536)
    var reader = OwnerPlanJSON(data); try reader.validate()
    guard let raw = try JSONSerialization.jsonObject(with: data) as? [String: Any],
      Set(raw.keys) == ["schema", "revisions"], raw["schema"] as? String == "zenith.credential-preset-history.v1",
      let rows = raw["revisions"] as? [[String: Any]], !rows.isEmpty, rows.count <= 32 else { throw CredentialPresetError.storage }
    let values = try rows.map { row -> CredentialPresetRevision in
      try CredentialPresetRevision.decode(JSONSerialization.data(withJSONObject: row, options: [.sortedKeys, .withoutEscapingSlashes]))
    }
    guard values.enumerated().allSatisfy({ $0.element.presetID == id && $0.element.revision == UInt64($0.offset + 1) }) else { throw CredentialPresetError.storage }
    return values
  }
  public func latest() throws -> [CredentialPresetRevision] {
    try checkDirectory()
    let entries = try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)
      .filter { $0.pathExtension == "json" }
    guard entries.count <= 128 else { throw CredentialPresetError.storage }
    return try entries.compactMap { try history($0.deletingPathExtension().lastPathComponent).last }
      .sorted { $0.name == $1.name ? $0.presetID < $1.presetID : $0.name < $1.name }
  }
  public func append(_ value: CredentialPresetRevision, replacing expected: CredentialPresetRevision?) throws {
    try value.validate(); try checkDirectory(); let url = try file(value.presetID)
    var error: NSError?; var result: Result<Void, Error> = .failure(CredentialPresetError.storage)
    NSFileCoordinator().coordinate(writingItemAt: url, options: .forMerging, error: &error) { coordinated in
      result = Result {
        let old = try history(value.presetID)
        guard old.last == expected, value.revision == UInt64(old.count + 1) else { throw CredentialPresetError.changed }
        guard old.count < 32 else { throw CredentialPresetError.revisionLimit }
        if old.isEmpty { guard try latest().count < 128 else { throw CredentialPresetError.storage } }
        let rows = try (old + [value]).map { try JSONSerialization.jsonObject(with: $0.encoded()) }
        let data = try JSONSerialization.data(withJSONObject: ["schema": "zenith.credential-preset-history.v1", "revisions": rows], options: [.sortedKeys, .withoutEscapingSlashes])
        guard data.count <= 65536 else { throw CredentialPresetError.revisionLimit }
        // 0600 staging ensures newly-created recipe files are never briefly world-readable.
        let staging = directory.appendingPathComponent("." + UUID().uuidString)
        guard FileManager.default.createFile(atPath: staging.path, contents: nil, attributes: [.posixPermissions: 0o600]) else { throw CredentialPresetError.storage }
        defer { try? FileManager.default.removeItem(at: staging) }
        try data.write(to: staging)
        guard rename(staging.path, coordinated.path) == 0 else { throw CredentialPresetError.storage }
      }
    }
    if error != nil { throw CredentialPresetError.storage }; try result.get()
  }
}
#endif
