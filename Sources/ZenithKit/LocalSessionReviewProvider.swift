#if os(macOS)
import CoreFoundation
import Foundation

/// Binds the private process interface to one explicitly configured canonical
/// service. Production discovery/registration is a separate reviewed action.
public actor LocalSessionReviewProvider: SessionReviewProvider {
  private let process: SessionProviderProcess
  private let pin: HolderIssuerPin
  private let authority: ReadAuthorityPin
  private let profileDigest: String
  private let expectedMode: String
  private let clock: @Sendable () -> UInt64
  private var clients: [String: String] = [:]
  private var originalRequests: [String: Data] = [:]
  private var proposedDefaultLifetime: UInt64?
  private var modeVerified = false
  public init(process: SessionProviderProcess, pin: HolderIssuerPin, authority: ReadAuthorityPin,
    profileDigest: String, expectedMode: String = "disposable", clock: @escaping @Sendable () -> UInt64 = { UInt64(Date().timeIntervalSince1970) }) {
    self.process = process; self.pin = pin; self.authority = authority; self.profileDigest = profileDigest; self.expectedMode = expectedMode; self.clock = clock
  }
  private func invoke(_ operation: String, client: String, _ arguments: [String: Any]) async throws -> Data {
    try await process.exchange(clientID: client, operation: operation, arguments: SessionReviewWire.encode(arguments))
  }
  private func context(_ value: [String: Any]) throws -> (Data, Data, ReadAuthorityPin) {
    guard let provider = value["trusted_provider"] as? [String: Any], let capabilities = value["capabilities"] as? [String: Any], let receiver = value["receiver_pin"] as? [String: Any],
      provider["service"] as? String == pin.service, provider["issuer"] as? String == pin.issuer,
      provider["key_id"] as? String == pin.key_id, provider["public_key"] as? String == pin.public_key,
      provider["profile_digest_sha256"] as? String == profileDigest else { throw SessionAccessReviewError.changed }
    let actual = try JSONDecoder().decode(ReadAuthorityPin.self, from: SessionReviewWire.encode(receiver))
    guard actual == authority else { throw SessionAccessReviewError.changed }
    let p = try SessionReviewWire.encode(provider), c = try SessionReviewWire.encode(capabilities)
    _ = try SessionAccessCapabilities.decode(c, trustedProvider: p)
    return (p, c, actual)
  }
  private func prepared(_ data: Data) throws -> SessionReviewPreparation {
    let value = try SessionReviewWire.object(data)
    guard Set(value.keys) == ["review", "capabilities", "trusted_provider", "holder", "receiver_pin"],
      let review = value["review"], let holder = value["holder"] else { throw SessionReviewBridgeError.invalid }
    let (p,c,a) = try context(value)
    let result = SessionReviewPreparation(review: try SessionReviewWire.encode(review), capabilities: c, trustedProvider: p,
      holder: try SessionReviewWire.encode(holder), authority: a)
    _ = try result.checked(now: clock())
    return result
  }
  public func services() async throws -> [SessionReviewService] {
    let value = try SessionReviewWire.object(await invoke("services", client: String(repeating: "0", count: 32), [:]))
    guard Set(value.keys) == ["services"], let services = value["services"] as? [[String: Any]], services.count <= 64 else { throw SessionReviewBridgeError.invalid }
    let result = try services.map { service in
      guard ["disposable", "production"].contains(expectedMode), service["mode"] as? String == expectedMode,
        service["service"] as? String == pin.service, let name = service["name"] as? String else { throw SessionAccessReviewError.changed }
      let (p,c,_) = try context(service), capabilities = try SessionAccessCapabilities.decode(c, trustedProvider: p)
      proposedDefaultLifetime = capabilities.expiryLimits.proposedDefault
      return SessionReviewService(service: pin.service, name: name, readAvailable: capabilities.readAvailable, writeAvailable: capabilities.writeAvailable)
    }
    modeVerified = !result.isEmpty
    return result
  }
  public func prepare(clientID: String, request: Data) async throws -> SessionReviewPreparation {
    if !modeVerified { _ = try await services() }
    guard modeVerified else { throw SessionReviewBridgeError.unavailable }
    let input = try SessionReviewWire.object(request)
    guard input["service"] as? String == pin.service, let id = input["request_id"] as? String,
      let permissions = input["permissions"], let label = input["session_label"], let purpose = input["purpose"] else { throw SessionReviewBridgeError.invalid }
    let key = clientID + ":" + id
    if let previous = originalRequests[key] { guard previous == request else { throw SessionAccessReviewError.changed } }
    else { guard originalRequests.count < 64 else { throw SessionReviewBridgeError.unavailable }; originalRequests[key] = request }
    var args: [String: Any] = ["service": pin.service, "request_id": id, "permissions": permissions,
      "display": ["session_label": label, "purpose": purpose]]
    // Relative lifetime is anchored by the provider, not by a client clock or
    // the time spent creating a helper. The returned absolute expiry is final.
    if let lifetime = input["lifetime_seconds"] {
      guard let value = lifetime as? NSNumber, CFGetTypeID(value) != CFBooleanGetTypeID(), value.uint64Value > 0 else { throw SessionReviewBridgeError.invalid }
      args["lifetime_seconds"] = lifetime
    } else {
      if proposedDefaultLifetime == nil { _ = try await services() }
      guard let lifetime = proposedDefaultLifetime else { throw SessionReviewBridgeError.unavailable }
      args["lifetime_seconds"] = lifetime
    }
    let result = try prepared(await invoke("prepare", client: clientID, args))
    let reviewed = try result.checked(now: clock())
    guard reviewed.requestID == id else { throw SessionAccessReviewError.changed }
    if let previous = clients[reviewed.requestHandle], previous != clientID { throw SessionAccessReviewError.changed }
    clients[reviewed.requestHandle] = clientID
    return result
  }
  private func binding(_ preparation: SessionReviewPreparation) throws -> (SessionAccessReview, String) {
    let review = try preparation.checked(now: clock(), retained: true)
    guard review.service == pin.service, let client = clients[review.requestHandle] else { throw SessionReviewBridgeError.unavailable }
    return (review, client)
  }
  public func updateExpiry(_ preparation: SessionReviewPreparation, expiresAt: UInt64) async throws -> SessionReviewPreparation {
    let (review, client) = try binding(preparation)
    let next = try prepared(await invoke("update_expiry", client: client, ["request_handle": review.requestHandle, "expires_at": expiresAt]))
    _ = try review.updatedExpiry(next.review, requestedExpiry: expiresAt, now: clock())
    return next
  }
  public func ownerChallenge(_ preparation: SessionReviewPreparation, ownerIdentity: Data) async throws -> Data {
    let (review, client) = try binding(preparation), identity = try SessionReviewWire.object(ownerIdentity)
    guard let owner = identity["subject_public_key"] as? String, let installation = identity["installation_id"] as? String else { throw SessionReviewBridgeError.invalid }
    return try await invoke("owner_challenge", client: client, ["request_handle": review.requestHandle, "owner_public_key": owner, "installation_id": installation])
  }
  public func submit(_ preparation: SessionReviewPreparation, ownerProof: Data) async throws -> Data {
    let (review, client) = try binding(preparation)
    // Owner proof stays on the private process channel and is not journaled.
    let proof = try JSONSerialization.jsonObject(with: ownerProof)
    return try await invoke("submit", client: client, ["request_handle": review.requestHandle, "owner_proof": proof])
  }
  public func reconcile(_ preparation: SessionReviewPreparation) async throws -> Data {
    let (review, client) = try binding(preparation)
    return try await invoke("reconcile", client: client, ["request_handle": review.requestHandle])
  }
  public func execute(_ preparation: SessionReviewPreparation, credentialHandle: String, requestID: String, call: Data) async throws -> Data {
    let (_, client) = try binding(preparation)
    return try await invoke("execute", client: client, ["credential_handle": credentialHandle, "request_id": requestID, "call": SessionReviewWire.object(call)])
  }
  public func closeClient(_ clientID: String) async throws {
    let result = try SessionReviewWire.object(await invoke("close_client", client: clientID, [:]))
    guard Set(result.keys) == ["schema", "closed", "server_revocation_confirmed"],
      result["schema"] as? String == "zenith.session-client-closed.v1",
      let closed = result["closed"] as? NSNumber, CFGetTypeID(closed) == CFBooleanGetTypeID(), closed.boolValue,
      let revoked = result["server_revocation_confirmed"] as? NSNumber, CFGetTypeID(revoked) == CFBooleanGetTypeID(), !revoked.boolValue
    else { throw SessionReviewBridgeError.invalid }
    clients = clients.filter { $0.value != clientID }
    originalRequests = originalRequests.filter { !$0.key.hasPrefix(clientID + ":") }
  }
  public func shutdown() async { await process.stop() }
}
#endif
