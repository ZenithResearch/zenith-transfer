#if os(macOS)
import Darwin
import Foundation

/// First-owner configuration binds the launched service, not another interface
/// discovered for the same graph. Historical setup plans remain unchanged.
public struct ServiceOwnerPreparation: Sendable {
  public let plan: OwnerSetupPlan
  public let review: OwnerInstallationReview
  public let service: LocalService

  public static func decode(_ data: Data, service: LocalService) throws -> Self {
    let envelope = try serviceOwnerObject(data)
    guard Set(envelope.keys) == ["schema", "plan", "preparation"],
      envelope["schema"] as? String == "devgraph.service-owner-preparation.v1",
      let rawPlan = envelope["plan"], let rawReview = envelope["preparation"],
      service.interface == .walletAPI, OwnerSetupPlan.localWalletAddress(service.endpoint),
      let connection = service.connection, connection.network == .local
    else { throw OwnerSetupError.changed }
    let plan = try OwnerSetupPlan.decode(serviceOwnerJSON(rawPlan))
    let review = try OwnerInstallationReview.decode(serviceOwnerJSON(rawReview), plan: plan)
    let value = try serviceOwnerObject(review.publicJSON)
    guard let existing = value["existing_service"] as? [String: Any],
      Set(existing.keys) == ["root", "instance_id", "endpoint", "label", "plist_sha256", "connection", "launch_review_digest"],
      existing["instance_id"] as? String == service.id,
      existing["endpoint"] as? String == service.endpoint,
      existing["label"] as? String == "ca.zenith.devgraph.wallet-service." + service.id,
      let rawConnection = existing["connection"],
      try WorkServerSettings.decode(serviceOwnerJSON(rawConnection)) == connection,
      plan.schema == "zenith.devgraph-owner-setup.v3", plan.resourceID == service.resource_id,
      plan.resourceName == service.name, plan.walletEndpoint == service.endpoint,
      review.connection == connection, review.endpoint == service.endpoint,
      review.certificateSHA256 == connection.tls_certificate_sha256
    else { throw OwnerSetupError.changed }
    return Self(plan: plan, review: review, service: service)
  }
  public var binding: ResourceOwnerBinding {
    ResourceOwnerBinding(resourceID: service.resource_id, endpoint: service.endpoint,
      configurationSHA256: plan.configurationSHA256, registrationSHA256: plan.registrationSHA256)
  }
}

public struct ServiceOwnerStatus: Sendable {
  public let preparation: ServiceOwnerPreparation?
  public let blocked: Bool
  public let ownerRegistered: Bool
  public let activationAttempted: Bool
  public let active: Bool
  public static func decode(_ data: Data, service: LocalService) throws -> Self {
    let raw = try serviceOwnerObject(data)
    guard raw["schema"] as? String == "devgraph.service-owner-status.v1",
      Set(raw.keys).isSubset(of: ["schema", "prepared", "blocked", "owner_registered", "activation_attempted", "active", "plan", "preparation"]),
      let prepared = raw["prepared"] as? Bool, let blocked = raw["blocked"] as? Bool,
      let owner = raw["owner_registered"] as? Bool, let attempted = raw["activation_attempted"] as? Bool,
      let active = raw["active"] as? Bool, !active || (owner && prepared && attempted)
    else { throw OwnerSetupError.changed }
    let preparation: ServiceOwnerPreparation?
    if prepared, let plan = raw["plan"], let review = raw["preparation"] {
      preparation = try .decode(serviceOwnerJSON(["schema": "devgraph.service-owner-preparation.v1", "plan": plan, "preparation": review]), service: service)
    } else {
      guard !prepared, !owner, !attempted, !active, raw["preparation"] == nil else { throw OwnerSetupError.changed }
      preparation = nil
    }
    return Self(preparation: preparation, blocked: blocked, ownerRegistered: owner, activationAttempted: attempted, active: active)
  }
}

public struct ServiceOwnerCoordinator: Sendable {
  public let service: LocalService
  public init(service: LocalService) throws {
    guard service.interface == .walletAPI, OwnerSetupPlan.localWalletAddress(service.endpoint),
      URL(string: service.endpoint)?.host == "127.0.0.1", service.connection?.network == .local,
      service.connection?.origin == service.endpoint else { throw OwnerSetupError.invalid }
    self.service = service
  }
  public func inspect() async throws -> ServiceOwnerStatus {
    try ServiceOwnerStatus.decode(await run("inspect"), service: service)
  }
  public func prepare(ownerPublicKey: String) async throws -> ServiceOwnerPreparation {
    guard ownerPublicKey.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil else { throw OwnerSetupError.invalid }
    let value = try ServiceOwnerPreparation.decode(await run("prepare", ["--owner-public-key", ownerPublicKey]), service: service)
    guard value.plan.ownerPublicKey == ownerPublicKey else { throw OwnerSetupError.changed }
    return value
  }
  private func check(_ preparation: ServiceOwnerPreparation) throws {
    guard preparation.service == service else { throw OwnerSetupError.changed }
  }
  public func challenge(_ preparation: ServiceOwnerPreparation, refresh: Bool = false) async throws -> ResourceOwnerChallenge {
    try check(preparation)
    let data = try await run(refresh ? "claim-refresh" : "claim-prepare", ["--review-digest", preparation.review.digest])
    let value = try ResourceOwnerChallenge.decode(data, binding: preparation.binding, now: UInt64(Date().timeIntervalSince1970))
    guard value.adminGrant.grantID == preparation.review.digest,
      value.adminGrant.holderPublicKey == preparation.plan.ownerPublicKey else { throw OwnerSetupError.changed }
    return value
  }
  private func proofFile(_ preparation: ServiceOwnerPreparation) throws -> URL {
    try check(preparation)
    let directory = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/ZenithTransfer/ServiceOwnerProofs")
    _ = try OwnerSetupStore(directory: directory)
    return directory.appendingPathComponent(service.id + "-" + preparation.review.digest + ".json")
  }
  private func checkedProof(_ proof: Data, preparation: ServiceOwnerPreparation) throws -> ResourceOwnerChallenge {
    let raw = try serviceOwnerObject(proof)
    guard let value = raw["challenge"] else { throw OwnerSetupError.invalid }
    let bytes = try serviceOwnerJSON(value)
    let parsed = try JSONDecoder().decode(ResourceOwnerChallenge.self, from: bytes)
    let challenge = try ResourceOwnerChallenge.decode(bytes, binding: preparation.binding, now: parsed.issuedAt)
    guard challenge.adminGrant.grantID == preparation.review.digest,
      challenge.adminGrant.holderPublicKey == preparation.plan.ownerPublicKey else { throw OwnerSetupError.changed }
    try challenge.validateProof(proof)
    return challenge
  }
  public func retainedProof(_ preparation: ServiceOwnerPreparation) throws -> Bool {
    let file = try proofFile(preparation)
    guard FileManager.default.fileExists(atPath: file.path) else { return false }
    _ = try checkedProof(OwnerSetupInspector.privateData(file, maximum: 16384), preparation: preparation)
    return true
  }
  public func completeOwner(_ preparation: ServiceOwnerPreparation, proof: Data) async throws {
    let challenge = try checkedProof(proof, preparation: preparation)
    let file = try proofFile(preparation)
    if FileManager.default.fileExists(atPath: file.path) {
      guard try OwnerSetupInspector.privateData(file, maximum: 16384) == proof else { throw OwnerSetupError.changed }
    } else {
      let fd = Darwin.open(file.path, O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW, 0o600)
      guard fd >= 0 else { throw OwnerSetupError.unavailable }
      let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
      try handle.write(contentsOf: proof); try handle.synchronize(); try handle.close()
    }
    let raw = try serviceOwnerObject(await run("claim-complete", ["--review-digest", preparation.review.digest, "--proof-file", file.path]))
    guard let duplicate = raw["duplicate"] as? Bool else { throw OwnerSetupError.changed }
    let expected: [String: Any] = ["schema": "zenith.resource-owner-result.v1", "active": true,
      "owner_public_key": preparation.plan.ownerPublicKey, "admin_grant": try JSONSerialization.jsonObject(with: JSONEncoder().encode(challenge.adminGrant)), "duplicate": duplicate]
    guard try serviceOwnerJSON(raw) == serviceOwnerJSON(expected) else { throw OwnerSetupError.changed }
  }
  public func activate(_ preparation: ServiceOwnerPreparation) async throws -> WorkAccessConfiguration {
    try check(preparation)
    let raw = try serviceOwnerObject(await run("activate", ["--review-digest", preparation.review.digest]))
    guard raw["schema"] as? String == "devgraph.owner-install-result.v1", raw["active"] as? Bool == true,
      raw["resource_id"] as? String == service.resource_id, raw["endpoint"] as? String == service.endpoint,
      raw["owner_public_key"] as? String == preparation.plan.ownerPublicKey,
      raw["member_grants_created"] as? Int == 0, raw["native_key_unchanged"] as? Bool == true,
      raw["database_restarted"] as? Bool == false, raw["private_api_unchanged"] as? Bool == true,
      raw["owner_wallet_confirmation_required"] as? Bool == true, let connection = raw["connection"],
      try WorkServerSettings.decode(serviceOwnerJSON(connection)) == preparation.review.connection
    else { throw OwnerSetupError.changed }
    return preparation.review.connection
  }
  private func run(_ command: String, _ arguments: [String] = []) async throws -> Data {
    let selection = ["--resource-id", service.resource_id, "--instance-id", service.id, "--endpoint", service.endpoint]
    return try await Task.detached {
      let url = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/Zenith/Devgraph/bin/devgraph-service-owner")
      var info = stat()
      guard lstat(url.path, &info) == 0, info.st_uid == getuid(), info.st_nlink == 1,
        url.resolvingSymlinksInPath().path == url.path, info.st_mode & S_IFMT == S_IFREG,
        info.st_mode & 0o077 == 0, info.st_mode & 0o100 != 0 else { throw OwnerSetupError.unavailable }
      let process = Process(), output = Pipe()
      process.executableURL = url; process.arguments = [command] + selection + arguments
      process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "en_US.UTF-8", "PYTHONDONTWRITEBYTECODE": "1"]
      process.standardInput = FileHandle.nullDevice; process.standardOutput = output; process.standardError = FileHandle.nullDevice
      try process.run()
      let timeout = DispatchWorkItem { if process.isRunning { process.terminate() } }
      DispatchQueue.global().asyncAfter(deadline: .now() + 180, execute: timeout)
      defer { timeout.cancel() }
      var data = Data()
      while let bytes = try output.fileHandleForReading.read(upToCount: 65536), !bytes.isEmpty {
        data.append(bytes)
        guard data.count <= 1_048_576 else { if process.isRunning { process.terminate() }; throw OwnerSetupError.unavailable }
      }
      process.waitUntilExit()
      guard process.terminationStatus == 0 else { throw OwnerSetupError.unavailable }
      return data
    }.value
  }
}

private func serviceOwnerObject(_ data: Data) throws -> [String: Any] {
  var strict = OwnerPlanJSON(data, maximumBytes: 1_048_576, maximumKeys: 6000, maximumArray: 6000, maximumDepth: 20)
  try strict.validate()
  guard let value = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw OwnerSetupError.invalid }
  return value
}
private func serviceOwnerJSON(_ value: Any) throws -> Data {
  try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys, .withoutEscapingSlashes])
}
#endif
