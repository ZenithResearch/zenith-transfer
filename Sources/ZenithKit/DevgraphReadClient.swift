import Foundation

public struct ReadAuthorityPin: Codable, Sendable, Hashable {
  public let issuer: String
  public let key_id: String
  public let public_key: String
  public let receiver: String
  public let audience: String
}
public struct WorkAccessConfiguration: Codable, Sendable, Hashable {
  public let name: String
  public let receiver: URL
  public let issuer: String
  public let authority: ReadAuthorityPin
  public let network: WorkNetwork?
  public let tls_certificate_sha256: String?
  public init(
    name: String, receiver: URL, issuer: String, keyID: String,
    publicKey: String, network: WorkNetwork? = nil, tlsCertificateSHA256: String? = nil
  ) throws {
    self.name = name
    self.receiver = receiver
    self.issuer = issuer
    self.network = network
    self.tls_certificate_sha256 = tlsCertificateSHA256
    let origin =
      receiver.absoluteString.hasSuffix("/")
      ? String(receiver.absoluteString.dropLast()) : receiver.absoluteString
    self.authority = ReadAuthorityPin(
      issuer: issuer, key_id: keyID,
      public_key: publicKey, receiver: origin, audience: "devgraph")
    try validate()
  }
  public func validate() throws {
    guard
      (network == .lan || network == .local)
        ? tls_certificate_sha256?.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil
        : tls_certificate_sha256 == nil
    else { throw WalletFailure.core("service_setup_required") }
    if network == .local, receiver.host != "127.0.0.1" {
      throw WalletFailure.core("service_setup_required")
    }
    guard !name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
      name.count <= 80, !issuer.isEmpty, issuer.count <= 256, receiver.scheme == "https",
      receiver.host != nil,
      receiver.path.isEmpty || receiver.path == "/", receiver.query == nil,
      receiver.fragment == nil,
      receiver.user == nil, receiver.password == nil, authority.issuer == issuer,
      authority.receiver == origin, authority.audience == "devgraph", !authority.key_id.isEmpty,
      authority.key_id.count <= 256,
      authority.public_key.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil
    else { throw WalletFailure.core("service_setup_required") }
  }
  public var origin: String {
    receiver.absoluteString.hasSuffix("/")
      ? String(receiver.absoluteString.dropLast()) : receiver.absoluteString
  }
}
public struct WorkReadGrant: Codable, Sendable, Equatable {
  public let schema: String?
  public let resource_paths: [WorkResourcePath]?
  public let scope: String
  public let operations: [String]
  public let relationship_types: [String]
  public let work_kinds: [String]
  public let work_ids: [String]?
  public let arena_ids: [String]?
  public let include_archived: Bool
  func validate(protocol version: WorkReadProtocol = .nativeV2) throws {
    if let paths = resource_paths {
      guard version == .pathV4, schema == "devgraph.path-read-grant.v1", !paths.isEmpty,
        paths.count <= 16, Set(paths).count == paths.count
      else { throw WalletFailure.core("unsupported_read_scope") }
      for path in paths { try path.validate() }
    } else if schema != nil {
      throw WalletFailure.core("unsupported_read_scope")
    }

    guard scope == "devgraph.work.read", !operations.isEmpty,
      Set(operations).isSubset(of: version.operations), Set(operations).count == operations.count,
      !work_kinds.isEmpty,
      Set(work_kinds).isSubset(of: version.workKinds),
      Set(work_kinds).count == work_kinds.count,
      !relationship_types.isEmpty,
      Set(relationship_types).isSubset(of: [
        "parent", "children", "dependencies", "dependents", "blockers", "blocked",
      ]), work_ids.map({ !$0.isEmpty && $0.count <= 256 }) ?? true,
      arena_ids.map({ !$0.isEmpty && $0.count <= 256 }) ?? true
    else { throw WalletFailure.core("unsupported_read_scope") }
  }
}
public struct ReadAccessProposal: Sendable {
  public let readProtocol: WorkReadProtocol
  public let requestID: String
  public let issuer: String
  public let receiver: String
  public let expires: Date
  public let grants: [WorkReadGrant]
  let challenge: Data
  let owner: String
  let installation: String
  let policy: String
  let challengeExpiry: UInt64
}
public struct NativeReadManifest: Decodable, Sendable {
  public let readProtocol: WorkReadProtocol
  public let schema: String
  public let credential_id: String
  public let subject_public_key: String
  public let installation_id: String
  public let issuer: String
  public let receiver: String
  public let policy_digest: String
  public let audience: String
  public let resource: String
  public let issued_at: UInt64
  public let expires_at: UInt64
  public let read_grants: [WorkReadGrant]
}
public struct WorkRecord: Decodable, Identifiable, Sendable {
  public let kind: String
  public let id: String
  public let title: String
  public let description: String
  public let priority: Int
  public let version: Int
  public let progress: String?
  enum CodingKeys: String, CodingKey {
    case kind, id, title, description, priority, version, progress
  }
  public init(from decoder: Decoder) throws {
    let values = try decoder.container(keyedBy: CodingKeys.self)
    kind = try values.decode(String.self, forKey: .kind)
    id = try values.decode(String.self, forKey: .id)
    title = try values.decode(String.self, forKey: .title)
    description = try values.decodeIfPresent(String.self, forKey: .description) ?? ""
    func integer(_ key: CodingKeys) throws -> Int {
      if let number = try? values.decode(Int.self, forKey: key) { return number }
      let text = try values.decode(String.self, forKey: key)
      guard let number = Int(text), String(number) == text else {
        throw WalletFailure.core("invalid_response")
      }
      return number
    }
    priority = try integer(.priority)
    version = try integer(.version)
    progress = try values.decodeIfPresent(String.self, forKey: .progress)
    guard WorkReadProtocol.monitorV3.workKinds.contains(kind), validWorkID(id) else {
      throw WalletFailure.core("invalid_response")
    }
  }
  public var rowID: String { kind + "/" + id }
  public var progressLabel: String {
    switch progress {
    case "not_started": return "Not started"
    case "in_progress": return "In progress"
    case "done": return "Done"
    default: return "Progress not recorded"
    }
  }
}

public final class DevgraphReadClient: @unchecked Sendable {
  private let holderRecovery = HolderReadRecovery()
  let repository: any WalletSession
  let configuration: WorkAccessConfiguration
  let transport: PrivateTransport
  public init(
    repository: any WalletSession, configuration: WorkAccessConfiguration,
    transport: PrivateTransport? = nil
  ) throws {
    try configuration.validate()
    self.repository = repository
    self.configuration = configuration
    guard configuration.network != .tailscale || transport != nil else {
      throw PrivateNetworkError.disconnected
    }
    if configuration.network == .lan || configuration.network == .local, let transport,
      !transport.verifiesLAN(configuration)
    {
      throw WalletFailure.core("service_setup_required")
    }
    self.transport = try transport ?? PrivateTransport(workServer: configuration)
  }
  public var connection: WorkAccessConfiguration { configuration }
  public func cancel() { transport.cancel() }
  /// A credential-free reachability check, not an authority or membership check.
  public func checkConnection() async throws {
    do { try await transport.checkReadReceiver(at: configuration.receiver) } catch let error
      as URLError
    {
      throw WorkConnectionFailure(code: error.code, network: configuration.network)
    }
  }
  private func response(_ request: URLRequest, maximum: Int = 1_048_576, readView: Bool = false)
    async throws -> Data
  {
    do {
      return try await transport.request(request, maximum: maximum, viewChangedOnConflict: readView)
    } catch let error as URLError {
      throw WorkConnectionFailure(code: error.code, network: configuration.network)
    }
  }
  private var now: UInt64 { UInt64(Date().timeIntervalSince1970) }
  private func request(path: String, body: Data? = nil) -> URLRequest {
    var request = URLRequest(url: URL(string: configuration.origin + path)!)
    if let body {
      request.httpMethod = "POST"
      request.httpBody = body
      request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    }
    return request
  }
  public func prepare() async throws -> ReadAccessProposal {
    let identity = try await repository.graphAccessIdentityV2()
    let response = try await response(
      request(path: "/devgraph/native-read/v2/challenges", body: identity), maximum: 16_384)
    return try decodeReadProposal(
      response, identity: identity, configuration: configuration, now: now)
  }
  public func connect(_ proposal: ReadAccessProposal) async throws {
    guard proposal.receiver == configuration.origin, proposal.issuer == configuration.issuer,
      now < proposal.challengeExpiry
    else { throw WalletFailure.core("access_expired") }
    let ticket = repository.lifecycleTicket()
    let approved = try await repository.approveGraphReadCredentialV2(
      proposal.challenge, pin: configuration.authority, now: now)
    try repository.checkLifecycle(ticket)
    let response = try await response(
      request(path: "/devgraph/native-read/v2/enrollments", body: approved), maximum: 65_536)
    let v = try object(response)
    try exact(v, ["schema", "credential", "manifest"])
    guard v["schema"] as? String == proposal.readProtocol.resultSchema,
      let credential = v["credential"] as? [String: Any]
    else { throw WalletFailure.core("invalid_credential") }
    // The shared Rust core verifies issuer signature, holder, device, policy,
    // exact approved permissions and expiry before preparing durable storage.
    try await repository.storeReadCredential(
      requestID: proposal.requestID,
      credential: JSONSerialization.data(withJSONObject: credential), now: now, ticket: ticket)
  }
  public func manifest() async throws -> NativeReadManifest {
    if let reusable = try await reusableManifest() { return reusable }
    let access = try object(
      await repository.graphReadCredentialV2(receiver: configuration.origin, now: now))
    guard let credential = access["credential"] as? [String: Any],
      let claims = credential["claims"] as? [String: Any],
      let permissions = claims["permissions"] as? [[String: Any]]
    else { throw WalletFailure.core("invalid_credential") }
    guard let details = access["details"] as? [String: Any],
      let schema = details["schema"] as? String,
      let readProtocol = WorkReadProtocol(rawValue: schema)
    else { throw WalletFailure.core("unsupported_read_scope") }
    let parsed = try parseGrants(
      permissions.map { $0["constraints"] as Any }, protocol: readProtocol)
    let grants = parsed.reduce(into: [WorkReadGrant]()) { if !$0.contains($1) { $0.append($1) } }
    let value: [String: Any] = [
      "schema": "devgraph.native-read-manifest.v2", "readProtocol": readProtocol.rawValue,
      "credential_id": claims["credential_id"] as Any,
      "subject_public_key": claims["holder_public_key"] as Any,
      "installation_id": claims["installation_id"] as Any, "issuer": claims["issuer"] as Any,
      "receiver": claims["receiver"] as Any, "policy_digest": claims["policy_digest"] as Any,
      "audience": claims["audience"] as Any, "resource": "https://work.zenith-research.ca/devgraph",
      "issued_at": claims["issued_at"] as Any, "expires_at": claims["expires_at"] as Any,
      "read_grants": try JSONSerialization.jsonObject(with: JSONEncoder().encode(grants)),
    ]
    return try JSONDecoder().decode(
      NativeReadManifest.self, from: JSONSerialization.data(withJSONObject: value))
  }
  public func page(kind: String, after: WorkPageCursor? = nil) async throws -> WorkPage {
    let access = try await manifest()
    guard
      access.read_grants.contains(where: {
        $0.operations.contains("list") && $0.work_kinds.contains(kind)
      })
    else {
      throw WalletFailure.core("unsupported_read_scope")
    }
    if access.readProtocol != .nativeV2 {
      var query = URLComponents()
      query.queryItems = [
        URLQueryItem(name: "kind", value: kind), URLQueryItem(name: "limit", value: "20"),
      ]
      if let after {
        guard let revision = after.revision, after.after.hasPrefix(kind + "/"),
          validWorkID(String(after.after.dropFirst(kind.count + 1))),
          revision.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil
        else { throw WalletFailure.core("invalid_response") }
        query.queryItems! += [
          URLQueryItem(name: "after", value: after.after),
          URLQueryItem(name: "revision", value: revision),
        ]
      }
      let data = try await read(
        operation: "list", parameters: ["path": "/todos/v2?" + (query.percentEncodedQuery ?? "")],
        protocol: access.readProtocol)
      return try decodeMonitorPage(data, kind: kind, after: after)
    }
    var parameters: [String: Any] = ["kind": kind, "limit": 20]
    if let after {
      guard after.revision == nil, validWorkID(after.after) else {
        throw WalletFailure.core("invalid_response")
      }
      parameters["after_id"] = after.after
    }
    let data = try await read(operation: "list", parameters: parameters, protocol: .nativeV2)
    struct Page: Decodable { let items: [WorkRecord] }
    let page = try JSONDecoder().decode(Page.self, from: data)
    guard page.items.count <= 20, page.items.allSatisfy({ $0.kind == kind }),
      Set(page.items.map(\.rowID)).count == page.items.count,
      page.items.allSatisfy({ item in after.map { item.id > $0.after } ?? true })
    else { throw WalletFailure.core("invalid_response") }
    return WorkPage(
      items: page.items,
      next: page.items.count == 20
        ? page.items.last.map { WorkPageCursor(after: $0.id, revision: nil) } : nil)
  }
  /// Retained for callers using the historical ID-based pagination API.
  public func list(kind: String, after: String? = nil) async throws -> [WorkRecord] {
    try await page(kind: kind, after: after.map { WorkPageCursor(after: $0, revision: nil) }).items
  }
  public func get(kind: String, id: String) async throws -> WorkRecord {
    let access = try await manifest()
    guard validWorkID(id),
      access.read_grants.contains(where: {
        $0.operations.contains("get") && $0.work_kinds.contains(kind)
      })
    else {
      throw WalletFailure.core("unsupported_read_scope")
    }
    let parameters: [String: Any] =
      access.readProtocol != .nativeV2
      ? ["path": "/todos/v2/" + kind + "/" + id] : ["kind": kind, "work_id": id]
    let data = try await read(
      operation: "get", parameters: parameters, protocol: access.readProtocol)
    let result = try JSONDecoder().decode(WorkRecord.self, from: data)
    guard result.kind == kind, result.id == id else { throw WalletFailure.core("invalid_response") }
    return result
  }
  public func related(kind: String, id: String, relationship: String, after: WorkPageCursor? = nil)
    async throws -> WorkPage
  {
    let access = try await manifest()
    guard access.readProtocol != .nativeV2, validWorkID(id),
      access.read_grants.contains(where: {
        $0.operations.contains("relationships") && $0.work_kinds.contains(kind)
          && $0.relationship_types.contains(relationship)
      })
    else { throw WalletFailure.core("unsupported_read_scope") }
    var query = URLComponents()
    query.queryItems = [URLQueryItem(name: "limit", value: "20")]
    if let after {
      let parts = after.after.split(separator: "/", omittingEmptySubsequences: false)
      guard after.revision == nil, parts.count == 2,
        access.readProtocol.workKinds.contains(String(parts[0])), validWorkID(String(parts[1]))
      else { throw WalletFailure.core("invalid_response") }
      query.queryItems!.append(URLQueryItem(name: "after_resource", value: after.after))
    }
    let path =
      "/work/" + kind + "/" + id + "/relationships/" + relationship + "?"
      + (query.percentEncodedQuery ?? "")
    let data = try await read(
      operation: "relationships", parameters: ["path": path], protocol: access.readProtocol)
    struct Page: Decodable { let items: [WorkRecord] }
    let page = try JSONDecoder().decode(Page.self, from: data)
    let keys = page.items.map(\.rowID)
    guard keys.count <= 20, keys == keys.sorted(), Set(keys).count == keys.count,
      after.map({ cursor in keys.allSatisfy { $0 > cursor.after } }) ?? true
    else { throw WalletFailure.core("invalid_response") }
    return WorkPage(
      items: page.items,
      next: keys.count == 20
        ? keys.last.map { WorkPageCursor(after: $0, revision: nil) } : nil)
  }
  private func read(
    operation: String, parameters: [String: Any], protocol version: WorkReadProtocol
  ) async throws -> Data {
    let ticket = repository.lifecycleTicket()
    let call: [String: Any] = [
      "operation": "devgraph.work." + operation,
      "resource": "https://work.zenith-research.ca/devgraph", "parameters": parameters,
    ]
    let proof: Data
    if let (service, credential) = try await holderCredential() {
      proof = try await repository.presentHolderCredential(
        service: service, credential: credential,
        call: JSONSerialization.data(withJSONObject: call), now: now)
    } else {
      proof = try await repository.signGraphReadCallV2(
        receiver: configuration.origin, call: JSONSerialization.data(withJSONObject: call), now: now
      )
    }
    try repository.checkLifecycle(ticket)
    let data = try await response(request(path: version.requestPath, body: proof), readView: true)
    try repository.checkLifecycle(ticket)
    return data
  }
  public func disconnect() async throws {
    let state = try await repository.state()
    if state.holderGrantProtocol == "secs.holder-grant.v1",
      let endpoint = try await holderEndpoint()
    {
      try await repository.forgetHolderGrant(service: endpoint.service)
    }
    try await repository.forgetReadAccess(receiver: configuration.origin)
  }
}
private func object(_ data: Data) throws -> [String: Any] {
  guard let value = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
    throw WalletFailure.core("invalid_response")
  }
  return value
}
private func exact(_ value: [String: Any], _ keys: Set<String>) throws {
  guard Set(value.keys) == keys else { throw WalletFailure.core("invalid_response") }
}
private func integer(_ value: Any?) throws -> UInt64 {
  guard let n = value as? NSNumber, String(cString: n.objCType) != "c", n.doubleValue >= 0,
    n.doubleValue.rounded() == n.doubleValue, n.doubleValue <= 9_007_199_254_740_991
  else { throw WalletFailure.core("invalid_response") }
  return n.uint64Value
}
private func parseGrants(_ value: Any?, protocol version: WorkReadProtocol) throws
  -> [WorkReadGrant]
{
  guard let values = value as? [[String: Any]], !values.isEmpty, values.count <= 32 else {
    throw WalletFailure.core("invalid_response")
  }
  for value in values {
    let base: Set<String> = [
      "scope", "operations", "relationship_types", "work_kinds", "include_archived",
    ]
    guard base.isSubset(of: Set(value.keys)),
      Set(value.keys).isSubset(
        of: base.union(["work_ids", "arena_ids"]).union(
          version == .pathV4 ? ["schema", "resource_paths"] : []))
    else { throw WalletFailure.core("invalid_response") }
  }
  let grants = try JSONDecoder().decode(
    [WorkReadGrant].self, from: JSONSerialization.data(withJSONObject: values))
  for raw in values {
    if let paths = raw["resource_paths"] as? [[String: Any]] {
      guard paths.allSatisfy({ Set($0.keys) == ["schema", "path"] }) else {
        throw WalletFailure.core("unsupported_read_scope")
      }
    } else if raw["resource_paths"] != nil {
      throw WalletFailure.core("unsupported_read_scope")
    }
  }
  for grant in grants { try grant.validate(protocol: version) }
  return grants
}

/// Shared by production setup and cross-language contract tests. Does not sign or store authority.
func decodeReadProposal(
  _ response: Data, identity: Data, configuration: WorkAccessConfiguration, now: UInt64
) throws -> ReadAccessProposal {
  let v = try object(response)
  try exact(
    v,
    [
      "schema", "request_id", "nonce", "subject_public_key", "installation_id", "issuer",
      "receiver", "details", "issued_at", "expires_at", "credential_expires_at",
    ])
  let identityValue = try object(identity)
  guard v["schema"] as? String == "castalia.read-access-challenge.v1",
    v["receiver"] as? String == configuration.origin,
    v["issuer"] as? String == configuration.issuer,
    v["subject_public_key"] as? String == identityValue["subject_public_key"] as? String,
    v["installation_id"] as? String == identityValue["installation_id"] as? String,
    let details = v["details"] as? [String: Any], let id = v["request_id"] as? String,
    let owner = v["subject_public_key"] as? String,
    let installation = v["installation_id"] as? String
  else { throw WalletFailure.core("invalid_read_challenge") }
  try exact(details, ["schema", "policy_digest", "read_grants", "authority_policy"])
  guard let schema = details["schema"] as? String,
    let readProtocol = WorkReadProtocol(rawValue: schema),
    let policy = details["policy_digest"] as? String
  else { throw WalletFailure.core("invalid_read_challenge") }
  let grants = try parseGrants(details["read_grants"], protocol: readProtocol)
  guard let authority = details["authority_policy"] as? [String: Any],
    authority["issuer"] as? String == configuration.authority.issuer,
    authority["key_id"] as? String == configuration.authority.key_id,
    authority["public_key"] as? String == configuration.authority.public_key,
    authority["receiver"] as? String == configuration.origin,
    authority["audience"] as? String == "devgraph",
    let permissions = authority["permissions"] as? [[String: Any]]
  else { throw WalletFailure.core("issuer_setup_required") }
  // The disclosure must describe the exact signed permission records. A
  // receiver cannot show a narrow grant while asking the core to approve more.
  let decoded = try permissions.map { permission -> WorkReadGrant in
    try exact(permission, ["operation", "resource", "constraints"])
    guard permission["resource"] as? String == "https://work.zenith-research.ca/devgraph",
      let constraint = permission["constraints"] as? [String: Any]
    else { throw WalletFailure.core("unsupported_read_scope") }
    let grant = try parseGrants([constraint], protocol: readProtocol)[0]
    guard let operation = permission["operation"] as? String,
      grant.operations.map({ "devgraph.work." + $0 }).contains(operation)
    else { throw WalletFailure.core("unsupported_read_scope") }
    return grant
  }
  guard permissions.count == grants.reduce(0, { $0 + $1.operations.count }),
    decoded.allSatisfy({ grants.contains($0) }),
    grants.allSatisfy({ grant in
      grant.operations.allSatisfy { operation in
        zip(permissions, decoded).contains {
          $0.0["operation"] as? String == "devgraph.work." + operation && $0.1 == grant
        }
      }
    })
  else { throw WalletFailure.core("invalid_read_challenge") }
  let expiry = try integer(v["credential_expires_at"])
  let challengeExpiry = try integer(v["expires_at"])
  let issued = try integer(v["issued_at"])
  guard issued <= now, now < challengeExpiry, challengeExpiry - issued <= 120, expiry > now,
    expiry - issued <= 3_600
  else { throw WalletFailure.core("access_expired") }
  return ReadAccessProposal(
    readProtocol: readProtocol, requestID: id, issuer: configuration.issuer,
    receiver: configuration.origin,
    expires: Date(timeIntervalSince1970: Double(expiry)), grants: grants, challenge: response,
    owner: owner, installation: installation, policy: policy, challengeExpiry: challengeExpiry)
}

// Shared native consumer of the same provider/service grant contract as Chrome.
private struct HolderGrantEndpoint: Decodable {
  let schema: String
  let service: String
  let endpoint: String
}
extension DevgraphReadClient {
  public func supportsReusableGrants() async throws -> Bool {
    guard try await repository.state().holderGrantProtocol == "secs.holder-grant.v1" else {
      return false
    }
    return try await holderEndpoint() != nil
  }
  private func holderEndpoint() async throws -> HolderGrantEndpoint? {
    let data = try await response(request(path: "/monitor/wallet-access/v1"), maximum: 65536)
    let value = try object(data)
    guard let raw = value["holder_grants"] else { return nil }
    let endpoint = try JSONDecoder().decode(
      HolderGrantEndpoint.self, from: JSONSerialization.data(withJSONObject: raw))
    guard endpoint.schema == "secs.holder-grant.v1", !endpoint.service.isEmpty,
      endpoint.service.count <= 256, endpoint.endpoint == "/monitor/wallet-access/v1/grants"
    else { throw WalletFailure.core("invalid_holder_service") }
    return endpoint
  }
  /// Retrieves the provider-signed root. It is not stored or used until review.
  public func requestReusableGrant(_ proposal: ReadAccessProposal) async throws -> HolderGrantReview
  {
    guard let endpoint = try await holderEndpoint(), proposal.receiver == configuration.origin,
      proposal.issuer == configuration.issuer, now < proposal.challengeExpiry
    else { throw WalletFailure.core("holder_grants_unavailable") }
    let ticket = repository.lifecycleTicket()
    let approval = try await repository.approveGraphReadCredentialV2(
      proposal.challenge, pin: configuration.authority, now: now)
    try repository.checkLifecycle(ticket)
    // Keep the exact original body in the client before dispatch. A recovery
    // resends these bytes only; it never signs a second issuance request.
    await holderRecovery.retain(approval, service: endpoint.service, owner: proposal.owner)
    return try await recoverReusableGrant()
  }
  public func hasPendingReusableGrant() async -> Bool { await holderRecovery.original() != nil }
  public func recoverReusableGrant() async throws -> HolderGrantReview {
    guard let original = await holderRecovery.original() else {
      throw WalletFailure.core("original_grant_request_missing")
    }
    let currentState = try await repository.state()
    guard currentState.unlocked, currentState.publicKey == original.owner else {
      throw WalletFailure.core("wallet_changed_or_locked")
    }
    let ticket = repository.lifecycleTicket()
    let data = try await response(
      request(path: "/monitor/wallet-access/v1/grants", body: original.body), maximum: 131072)
    try repository.checkLifecycle(ticket)
    let value = try object(data)
    try exact(value, ["schema", "grant"])
    guard value["schema"] as? String == "devgraph.holder-grant-result.v1",
      let grant = value["grant"] as? [String: Any]
    else { throw WalletFailure.core("invalid_holder_grant") }
    let pin = HolderIssuerPin(
      issuer: configuration.issuer, keyID: configuration.authority.key_id,
      publicKey: configuration.authority.public_key, service: original.service)
    return try await repository.reviewHolderGrant(
      JSONSerialization.data(withJSONObject: grant), pin: pin, now: now)
  }
  public func saveReusableGrant(_ review: HolderGrantReview) async throws {
    guard review.pin.issuer == configuration.issuer,
      review.pin.key_id == configuration.authority.key_id,
      review.pin.public_key == configuration.authority.public_key
    else { throw WalletFailure.core("issuer_setup_required") }
    try await repository.saveHolderGrant(review, now: now)
    await holderRecovery.clear()
  }
  private func holderCredential() async throws -> (String, Data)? {
    let state = try await repository.state()
    guard state.holderGrantProtocol == "secs.holder-grant.v1" else { return nil }
    let summaries = try await repository.holderGrantSummaries()
    guard summaries.contains(where: { $0.issuer == configuration.issuer }) else { return nil }
    guard let endpoint = try await holderEndpoint() else {
      throw WalletFailure.core("holder_grants_unavailable")
    }
    let stored = try object(await repository.holderGrant(service: endpoint.service, now: now))
    let pin = try JSONDecoder().decode(
      HolderIssuerPin.self, from: JSONSerialization.data(withJSONObject: stored["pin"] as Any))
    guard pin.issuer == configuration.issuer, pin.key_id == configuration.authority.key_id,
      pin.public_key == configuration.authority.public_key, pin.service == endpoint.service
    else { throw WalletFailure.core("issuer_setup_required") }
    guard let grant = stored["grant"] as? [String: Any],
      let claims = grant["claims"] as? [String: Any],
      let validity = claims["validity"] as? [String: Any]
    else { throw WalletFailure.core("invalid_holder_grant") }
    let end = min(now + 3600, try validity["not_after"].map { try integer($0) } ?? UInt64.max)
    let maximum = try integer(claims["max_credential_lifetime_seconds"])
    return (
      endpoint.service,
      try await repository.deriveHolderCredential(
        service: endpoint.service, permissions: nil, expires: min(end, now + maximum), now: now)
    )
  }
  private func reusableManifest() async throws -> NativeReadManifest? {
    guard let (_, data) = try await holderCredential() else { return nil }
    let value = try object(data)
    let claims = try object(JSONSerialization.data(withJSONObject: value["claims"] as Any))
    let grant = try object(JSONSerialization.data(withJSONObject: value["grant"] as Any))
    let root = try object(JSONSerialization.data(withJSONObject: grant["claims"] as Any))
    guard let permissions = claims["permissions"] as? [[String: Any]] else {
      throw WalletFailure.core("invalid_holder_credential")
    }
    let converted = try holderReadConstraints(permissions)
    let grants = try parseGrants(converted, protocol: .pathV4)
    let manifest: [String: Any] = [
      "schema": "devgraph.native-read-manifest.v2",
      "readProtocol": WorkReadProtocol.pathV4.rawValue,
      "credential_id": claims["credential_id"] as Any,
      "subject_public_key": claims["holder_public_key"] as Any,
      "installation_id": claims["installation_id"] as Any, "issuer": root["issuer"] as Any,
      "receiver": configuration.origin, "policy_digest": claims["grant_digest"] as Any,
      "audience": "devgraph", "resource": "https://work.zenith-research.ca/devgraph",
      "issued_at": claims["issued_at"] as Any, "expires_at": claims["expires_at"] as Any,
      "read_grants": try JSONSerialization.jsonObject(with: JSONEncoder().encode(grants)),
    ]
    return try JSONDecoder().decode(
      NativeReadManifest.self, from: JSONSerialization.data(withJSONObject: manifest))
  }
}
private func holderReadConstraints(_ permissions: [[String: Any]]) throws -> [[String: Any]] {
  try permissions.compactMap { p in
    guard let operation = p["operation"] as? String, operation.hasPrefix("devgraph.work.") else {
      return nil
    }
    guard p["resource"] as? String == "https://work.zenith-research.ca/devgraph",
      var c = p["constraints"] as? [String: Any], let scope = p["scope"] as? [String: Any]
    else { throw WalletFailure.core("invalid_holder_scope") }
    c["operations"] = [String(operation.dropFirst("devgraph.work.".count))]
    if scope["mode"] as? String == "paths" {
      guard let roots = scope["roots"] as? [[[String: String]]] else {
        throw WalletFailure.core("invalid_holder_scope")
      }
      c["resource_paths"] = try roots.map { root in
        [
          "schema": "devgraph.resource-path.v1",
          "path": try root.map { n -> String in
            guard let kind = n["kind"], let id = n["id"] else {
              throw WalletFailure.core("invalid_holder_scope")
            }
            return kind + "/" + id
          },
        ] as [String: Any]
      }
      c["schema"] = "devgraph.path-read-grant.v1"
    } else if scope["mode"] as? String != "all" {
      throw WalletFailure.core("invalid_holder_scope")
    }
    return c
  }
}
private actor HolderReadRecovery {
  struct Original: Sendable {
    let body: Data
    let service: String
    let owner: String
  }
  var retained: Original?
  func retain(_ body: Data, service: String, owner: String) {
    retained = Original(body: body, service: service, owner: owner)
  }
  func original() -> Original? { retained }
  func clear() { retained = nil }
}
