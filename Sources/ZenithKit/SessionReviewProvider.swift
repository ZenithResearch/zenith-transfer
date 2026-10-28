#if os(macOS)
import Foundation
import Darwin

/// Broker-internal context from a configured local provider, never MCP input.
/// This contains public review bytes and pins, not keys, grants or proofs.
public struct SessionReviewPreparation: Codable, Sendable {
  public let review: Data, capabilities: Data, trustedProvider: Data, holder: Data
  public let authority: ReadAuthorityPin
  public init(review: Data, capabilities: Data, trustedProvider: Data, holder: Data, authority: ReadAuthorityPin) {
    self.review = review; self.capabilities = capabilities; self.trustedProvider = trustedProvider; self.holder = holder; self.authority = authority
  }
  public func checked(now: UInt64, retained: Bool = false) throws -> SessionAccessReview {
    let capability = try SessionAccessCapabilities.decode(capabilities, trustedProvider: trustedProvider)
    guard capability.readAvailable || capability.writeAvailable else { throw SessionAccessReviewError.unavailable }
    guard let pin = try JSONSerialization.jsonObject(with: trustedProvider) as? [String: Any],
      pin["issuer"] as? String == authority.issuer, pin["key_id"] as? String == authority.key_id,
      pin["public_key"] as? String == authority.public_key else { throw SessionAccessReviewError.changed }
    var time = now
    if retained {
      // A retained review is display/reconciliation data only. Before signing,
      // the controller checks its real current deadline again.
      var reader = OwnerPlanJSON(review, maximumKeys: 256, maximumArray: 256, maximumDepth: 24, allowNegativeIntegers: true)
      try reader.validate()
      guard let value = try JSONSerialization.jsonObject(with: review) as? [String: Any],
        let manifest = value["manifest"] as? [String: Any], let deadline = manifest["review_deadline"] as? UInt64,
        deadline > 0 else { throw SessionAccessReviewError.invalid }
      time = deadline - 1
    }
    return try SessionAccessReview.decode(review, trustedProvider: trustedProvider, expectedHolder: holder, limits: capability.expiryLimits, now: time)
  }
}

public struct SessionReviewService: Codable, Sendable {
  public let service: String, name: String
  public let read_available: Bool, write_available: Bool
  public init(service: String, name: String, readAvailable: Bool, writeAvailable: Bool) {
    self.service = service; self.name = name; read_available = readAvailable; write_available = writeAvailable
  }
}

/// Private, configured application handlers. No URL, executable, provider pin,
/// signature or owner approval is accepted from a model tool argument.
public protocol SessionReviewProvider: Sendable {
  func closeClient(_ clientID: String) async throws
  func shutdown() async
  func services() async throws -> [SessionReviewService]
  func prepare(clientID: String, request: Data) async throws -> SessionReviewPreparation
  func updateExpiry(_ preparation: SessionReviewPreparation, expiresAt: UInt64) async throws -> SessionReviewPreparation
  func ownerChallenge(_ preparation: SessionReviewPreparation, ownerIdentity: Data) async throws -> Data
  func submit(_ preparation: SessionReviewPreparation, ownerProof: Data) async throws -> Data
  func reconcile(_ preparation: SessionReviewPreparation) async throws -> Data
  func execute(_ preparation: SessionReviewPreparation, credentialHandle: String, requestID: String, call: Data) async throws -> Data
}
public extension SessionReviewProvider {
  func shutdown() async {}
  func execute(_ preparation: SessionReviewPreparation, credentialHandle: String, requestID: String, call: Data) async throws -> Data { throw SessionAccessReviewError.unavailable }
}

public struct UnavailableSessionReviewProvider: SessionReviewProvider {
  public init() {}
  public func closeClient(_ clientID: String) async throws {}
  public func services() async throws -> [SessionReviewService] { [] }
  public func prepare(clientID: String, request: Data) async throws -> SessionReviewPreparation { throw SessionAccessReviewError.unavailable }
  public func updateExpiry(_ preparation: SessionReviewPreparation, expiresAt: UInt64) async throws -> SessionReviewPreparation { throw SessionAccessReviewError.unavailable }
  public func ownerChallenge(_ preparation: SessionReviewPreparation, ownerIdentity: Data) async throws -> Data { throw SessionAccessReviewError.unavailable }
  public func submit(_ preparation: SessionReviewPreparation, ownerProof: Data) async throws -> Data { throw SessionAccessReviewError.unavailable }
  public func reconcile(_ preparation: SessionReviewPreparation) async throws -> Data { throw SessionAccessReviewError.unavailable }
}

/// Application recovery only, deliberately separate from Wallet/backup storage.
public struct SessionReviewRecord: Codable, Sendable {
  public let schema: String
  public let clientID: String, originalRequest: Data, preparation: SessionReviewPreparation
  public var version: UInt64
  public var dispatched: Bool
  public var state: SessionAccessState
  public var result: Data?
  public init(clientID: String, originalRequest: Data, preparation: SessionReviewPreparation) {
    schema = "zenith.session-review-record.v1"; self.clientID = clientID; self.originalRequest = originalRequest
    self.preparation = preparation; version = 1; dispatched = false; state = .awaitingHuman; result = nil
  }
  public func replacing(_ preparation: SessionReviewPreparation) -> Self {
    var next = Self(clientID: clientID, originalRequest: originalRequest, preparation: preparation)
    next.version = version + 1; return next
  }
}

public final class SessionReviewJournal: @unchecked Sendable {
  private let directory: URL
  public init(directory: URL) throws {
    self.directory = directory
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    var info = stat()
    guard lstat(directory.path, &info) == 0, info.st_uid == getuid(), info.st_mode & S_IFMT == S_IFDIR,
      info.st_mode & 0o077 == 0 else { throw SessionReviewBridgeError.unauthorized }
  }
  public func load() throws -> [SessionReviewRecord] {
    let files = try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)
      .filter { $0.pathExtension == "json" && $0.lastPathComponent != "provider.json" }
    guard files.count <= 64 else { throw SessionReviewBridgeError.unavailable }
    return try files.map { file in
      guard let data = try read(file) else { throw SessionReviewBridgeError.unavailable }
      return try decode(data)
    }
  }
  public func save(_ record: SessionReviewRecord, replacing expected: SessionReviewRecord?) throws {
    let checked = try decode(JSONEncoder().encode(record))
    let review = try checked.preparation.checked(now: UInt64(Date().timeIntervalSince1970), retained: true)
    let file = directory.appendingPathComponent(OwnerSetupPlan.sha256(Data((checked.clientID + ":" + review.requestID).utf8)) + ".json")
    var failure: NSError?, outcome: Result<Void, Error> = .failure(SessionReviewBridgeError.unavailable)
    NSFileCoordinator().coordinate(writingItemAt: file, options: .forMerging, error: &failure) { _ in
      outcome = Result {
        let prior = try read(file)
        if let expected {
          guard let prior,
            try stable(decode(prior)) == stable(expected), record.version == expected.version + 1 else { throw SessionAccessReviewError.changed }
          guard record.clientID == expected.clientID, record.originalRequest == expected.originalRequest else { throw SessionAccessReviewError.changed }
          if expected.dispatched {
            guard record.dispatched, try stable(record.preparation) == stable(expected.preparation),
              record.originalRequest == expected.originalRequest, record.clientID == expected.clientID else { throw SessionAccessReviewError.changed }
          }
        } else {
          guard prior == nil, record.version == 1, !record.dispatched, try load().count < 64 else { throw SessionAccessReviewError.changed }
        }
        let bytes = try stable(record)
        try bytes.write(to: file, options: [.atomic])
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
        let fd = open(file.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw SessionReviewBridgeError.unavailable }
        defer { close(fd) }
        guard fsync(fd) == 0 else { throw SessionReviewBridgeError.unavailable }
        let parent = open(directory.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard parent >= 0 else { throw SessionReviewBridgeError.unavailable }
        defer { close(parent) }
        guard fsync(parent) == 0 else { throw SessionReviewBridgeError.unavailable }
      }
    }
    if failure != nil { throw SessionReviewBridgeError.unavailable }; try outcome.get()
  }
  private func stable<T: Encodable>(_ value: T) throws -> Data {
    let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]; return try encoder.encode(value)
  }
  private func read(_ file: URL) throws -> Data? {
    let fd = open(file.path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK)
    if fd < 0 { if errno == ENOENT { return nil }; throw SessionReviewBridgeError.unauthorized }
    let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
    var info = stat()
    guard fstat(fd, &info) == 0, info.st_uid == getuid(), info.st_mode & S_IFMT == S_IFREG,
      info.st_nlink == 1, info.st_mode & 0o077 == 0, info.st_size <= 524288 else { throw SessionReviewBridgeError.unauthorized }
    return try handle.readToEnd()
  }
  private func decode(_ data: Data) throws -> SessionReviewRecord {
    var strict = OwnerPlanJSON(data, maximumBytes: 524288, maximumKeys: 32, maximumArray: 64, maximumDepth: 8)
    try strict.validate()
    guard let raw = try JSONSerialization.jsonObject(with: data) as? [String: Any],
      Set(raw.keys).isSubset(of: ["schema", "clientID", "originalRequest", "preparation", "version", "dispatched", "state", "result"])
    else { throw SessionReviewBridgeError.invalid }
    let value = try JSONDecoder().decode(SessionReviewRecord.self, from: data)
    guard value.schema == "zenith.session-review-record.v1", value.clientID.range(of: "\\A[0-9a-f]{32}\\z", options: .regularExpression) != nil,
      value.version > 0, value.originalRequest.count <= 65536, (value.result?.count ?? 0) <= 65536 else { throw SessionReviewBridgeError.invalid }
    let review = try value.preparation.checked(now: UInt64(Date().timeIntervalSince1970), retained: true)
    let request = try SessionReviewWire.object(value.originalRequest)
    guard request["request_id"] as? String == review.requestID, request["service"] as? String == review.service else { throw SessionReviewBridgeError.invalid }
    if let result = value.result {
      let outcome = try SessionAccessOutcome.decode(result, review: review, now: review.notBefore)
      guard outcome.state == value.state, value.dispatched || value.state == .denied else { throw SessionReviewBridgeError.invalid }
    } else {
      guard value.dispatched ? [.submitting, .outcomeUnknown].contains(value.state) : value.state == .awaitingHuman else { throw SessionReviewBridgeError.invalid }
    }
    return value
  }
}

public enum SessionReviewWire {
  public static func object(_ data: Data) throws -> [String: Any] {
    var strict = OwnerPlanJSON(data, maximumBytes: 65536, maximumKeys: 256, maximumArray: 256, maximumDepth: 24, allowNegativeIntegers: true)
    try strict.validate()
    guard let raw = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw SessionReviewBridgeError.invalid }
    return raw
  }
  public static func encode(_ value: Any) throws -> Data { try OwnerReviewCanonicalJSON.encode(value) }
  public static func publicOutcome(_ review: SessionAccessReview, state: SessionAccessState) throws -> Data {
    guard state != .issued else { throw SessionReviewBridgeError.invalid }
    return try encode(["schema": "zenith.session-access-result.v1", "request_handle": review.requestHandle,
      "request_id": review.requestID, "review_digest_sha256": review.digest, "provider_service": review.service,
      "holder_public_key": review.holderPublicKey, "state": state.rawValue, "credential_handle": NSNull(),
      "expires_at": NSNull(), "reconcile_required": state == .outcomeUnknown])
  }
}
#endif
