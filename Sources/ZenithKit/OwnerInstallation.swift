#if os(macOS)
import CryptoKit
import Darwin
import Foundation

public struct OwnerInstallationReview: Sendable {
  public let digest: String
  public let resourceID: String
  public let ownerPublicKey: String
  public let endpoint: String
  public let certificateSHA256: String
  public let previousNativeVersion: Int
  public let nativeVersion: Int
  public let preservedRules: Int
  public let nativeKeyDeadline: Int
  public let operations: [String]
  public let connection: WorkAccessConfiguration
  public let publicJSON: Data

  public static func decode(_ data: Data, plan: OwnerSetupPlan) throws -> Self {
    var raw = OwnerPlanJSON(data, maximumBytes: 1_048_576, maximumKeys: 6000, maximumArray: 6000, maximumDepth: 20)
    try raw.validate()
    guard data.count <= 1_048_576,
      let envelope = try JSONSerialization.jsonObject(with: data) as? [String: Any],
      Set(envelope.keys) == ["review", "review_digest"],
      let value = envelope["review"] as? [String: Any], let digest = envelope["review_digest"] as? String,
      value["schema"] as? String == "devgraph.owner-install-review.v1",
      value["status"] as? String == "prepared_not_activated",
      value["resource_id"] as? String == plan.resourceID,
      value["owner_public_key"] as? String == plan.ownerPublicKey,
      value["endpoint"] as? String == plan.walletEndpoint,
      value["plan_digest"] as? String == plan.digest,
      value["members_preassigned"] as? Int == 0,
      value["onward_delegation"] as? Bool == false,
      value["native_key_unchanged"] as? Bool == true,
      value["private_api_unchanged"] as? Bool == true,
      value["database_restart"] as? Bool == false,
      value["certificate_trust_changed"] as? Bool == false,
      value["owner_wallet_confirmation_required"] as? Bool == true,
      let cert = value["tls_certificate_sha256"] as? String,
      cert.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil,
      let previous = value["previous_native_version"] as? Int, let version = value["native_policy_version"] as? Int,
      previous > 0, version == previous + 1,
      let preserved = value["existing_rules_preserved"] as? Int, preserved > 0,
      let keyDeadline = value["native_key_not_after"] as? Int, keyDeadline > 0,
      value["native_holders"] as? [String] == [],
      value["native_admission_on_grant"] as? Bool == true,
      let operations = value["operations"] as? [String],
      operations == plan.writeOperations.map({ "devgraph.work." + $0 + ".v2" }),
      let config = value["connection"] as? [String: Any]
    else { throw OwnerSetupError.invalid }
    let canonical = try OwnerReviewCanonicalJSON.encode(value)
    guard OwnerSetupPlan.sha256(canonical) == digest else { throw OwnerSetupError.changed }
    let connection = try WorkServerSettings.decode(JSONSerialization.data(withJSONObject: config))
    guard connection.origin == plan.walletEndpoint, connection.network == (plan.schema == "zenith.devgraph-owner-setup.v3" ? .local : .lan),
      connection.tls_certificate_sha256 == cert else { throw OwnerSetupError.changed }
    if plan.schema == "zenith.devgraph-owner-setup.v3" {
      guard value["owner_claim_required"] as? Bool == true, value["local_only"] as? Bool == true,
        value["source_endpoint"] as? String == plan.localEndpoint else { throw OwnerSetupError.changed }
    }
    return Self(digest: digest, resourceID: plan.resourceID, ownerPublicKey: plan.ownerPublicKey,
      endpoint: plan.walletEndpoint, certificateSHA256: cert, previousNativeVersion: previous,
      nativeVersion: version, preservedRules: preserved, nativeKeyDeadline: keyDeadline,
      operations: operations, connection: connection, publicJSON: canonical)
  }
}

/// Fixed owner-local helper. No arbitrary executable, network target, key or shell
/// is supplied by a resource page. Only the saved private plan and review digest.
public struct OwnerInstallationCoordinator: Sendable {
  public init() {}
  public static func planDirectory(for plan: OwnerSetupPlan? = nil) -> URL {
    FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/ZenithTransfer/" + (plan?.schema == "zenith.devgraph-owner-setup.v3" || plan == nil ? "WalletAdminUpgrades" : "OwnerSetups"))
  }
  private func planFile(_ plan: OwnerSetupPlan) throws -> URL {
    let root = Self.planDirectory(for:plan)
    guard try OwnerSetupStore(directory: root).load(resourceID: plan.resourceID) == plan else { throw OwnerSetupError.changed }
    return root.appendingPathComponent(plan.resourceID + ".json")
  }
  public func propose(_ target: OwnerRegistrationTarget) async throws -> WalletAdminUpgradeProposal {
    try WalletAdminUpgradeProposal.decode(await run(["propose","--resource-id",target.resourceID,"--source-endpoint",target.endpoint]),target:target)
  }
  private func binding(_ plan: OwnerSetupPlan) -> ResourceOwnerBinding {
    ResourceOwnerBinding(resourceID:plan.resourceID,endpoint:plan.localEndpoint,
      configurationSHA256:plan.configurationSHA256,registrationSHA256:plan.registrationSHA256)
  }
  public func ownerChallenge(_ plan: OwnerSetupPlan, review: OwnerInstallationReview, refresh: Bool = false) async throws -> ResourceOwnerChallenge {
    let data = try await run([refresh ? "claim-refresh" : "claim-prepare","--plan-file",try planFile(plan).path,"--review-digest",review.digest])
    let challenge = try ResourceOwnerChallenge.decode(data,binding:binding(plan),now:UInt64(Date().timeIntervalSince1970))
    guard challenge.adminGrant.grantID == review.digest, challenge.adminGrant.holderPublicKey == plan.ownerPublicKey else { throw OwnerSetupError.changed }
    return challenge
  }
  private func proofFile(_ plan: OwnerSetupPlan, review: OwnerInstallationReview) throws -> URL {
    _ = try planFile(plan)
    let root=Self.planDirectory(for:plan).appendingPathComponent("Claims")
    _ = try OwnerSetupStore(directory:root)
    return root.appendingPathComponent(plan.resourceID + "-" + review.digest + ".json")
  }
  public func retainedOwnerProof(_ plan: OwnerSetupPlan, review: OwnerInstallationReview) throws -> Data? {
    let file=try proofFile(plan,review:review)
    guard FileManager.default.fileExists(atPath:file.path) else { return nil }
    let data=try OwnerSetupInspector.privateData(file,maximum:16384)
    _ = try checkedProof(data,plan:plan,review:review)
    return data
  }
  private func checkedProof(_ data: Data, plan: OwnerSetupPlan, review: OwnerInstallationReview) throws -> ResourceOwnerChallenge {
    var checked=OwnerPlanJSON(data,maximumBytes:16384);try checked.validate()
    guard let raw=try JSONSerialization.jsonObject(with:data) as? [String:Any],let value=raw["challenge"] else { throw OwnerSetupError.invalid }
    let bytes=try JSONSerialization.data(withJSONObject:value,options:[.sortedKeys,.withoutEscapingSlashes])
    let parsed=try JSONDecoder().decode(ResourceOwnerChallenge.self,from:bytes)
    let challenge=try ResourceOwnerChallenge.decode(bytes,binding:binding(plan),now:parsed.issuedAt)
    guard challenge.adminGrant.grantID==review.digest,challenge.adminGrant.holderPublicKey==plan.ownerPublicKey else { throw OwnerSetupError.changed }
    try challenge.validateProof(data);return challenge
  }
  private func checkOwnerResult(_ data: Data, challenge: ResourceOwnerChallenge) throws {
    var checked=OwnerPlanJSON(data,maximumBytes:16384);try checked.validate()
    struct Result: Decodable { let duplicate: Bool }
    let duplicate=try JSONDecoder().decode(Result.self,from:data).duplicate
    let raw=try JSONSerialization.jsonObject(with:data)
    let grant=try JSONSerialization.jsonObject(with:JSONEncoder().encode(challenge.adminGrant))
    let expected: [String:Any] = ["schema":"zenith.resource-owner-result.v1","active":true,
      "owner_public_key":challenge.adminGrant.holderPublicKey,"admin_grant":grant,"duplicate":duplicate]
    guard try JSONSerialization.data(withJSONObject:raw,options:[.sortedKeys,.withoutEscapingSlashes]) == JSONSerialization.data(withJSONObject:expected,options:[.sortedKeys,.withoutEscapingSlashes]) else { throw OwnerSetupError.changed }
  }
  public func completeOwner(_ plan: OwnerSetupPlan, review: OwnerInstallationReview, proof: Data) async throws {
    let challenge=try checkedProof(proof,plan:plan,review:review)
    let file=try proofFile(plan,review:review)
    if let old=try retainedOwnerProof(plan,review:review) {
      guard old==proof else { throw OwnerSetupError.changed }
    } else {
      let fd=Darwin.open(file.path,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0o600)
      guard fd>=0 else { throw OwnerSetupError.unavailable }
      let handle=FileHandle(fileDescriptor:fd,closeOnDealloc:true)
      try handle.write(contentsOf:proof);try handle.synchronize();try handle.close()
    }
    // Original signed bytes are durable before possible registration dispatch.
    let result=try await run(["claim-complete","--plan-file",try planFile(plan).path,"--review-digest",review.digest,"--proof-file",file.path])
    try checkOwnerResult(result,challenge:challenge)
  }
  public func inspectOwner(_ plan: OwnerSetupPlan, review: OwnerInstallationReview) async throws {
    guard let proof=try retainedOwnerProof(plan,review:review) else { throw OwnerSetupError.unavailable }
    let challenge=try checkedProof(proof,plan:plan,review:review)
    let result=try await run(["claim-status","--plan-file",try planFile(plan).path,"--review-digest",review.digest,"--proof-file",try proofFile(plan,review:review).path])
    try checkOwnerResult(result,challenge:challenge)
  }
  public func prepare(_ plan: OwnerSetupPlan) async throws -> OwnerInstallationReview {
    let file = try planFile(plan)
    let args = ["prepare", "--plan-file", file.path]
    return try OwnerInstallationReview.decode(await run(args), plan: plan)
  }
  public func status(_ plan: OwnerSetupPlan) async throws -> OwnerInstallationState {
    let data = try await run(["status", "--plan-file", try planFile(plan).path])
    var checked = OwnerPlanJSON(data, maximumBytes: 1_048_576, maximumKeys: 6000, maximumArray: 6000, maximumDepth: 20)
    try checked.validate()
    guard let value = try JSONSerialization.jsonObject(with: data) as? [String: Any],
      value["schema"] as? String == "devgraph.owner-install-status.v1",
      let prepared = value["prepared"] as? Bool, let active = value["active"] as? Bool,
      let phases = value["phases"] as? [String], phases.count <= 30 else { throw OwnerSetupError.invalid }
    let review: OwnerInstallationReview?
    if prepared, let preparation = value["preparation"] {
      review = try OwnerInstallationReview.decode(JSONSerialization.data(withJSONObject: preparation), plan: plan)
    } else { review = nil }
    return OwnerInstallationState(prepared: prepared, activationAttempted: phases.contains("activation-started"),
      activationRecorded: active, phases: phases, review: review)
  }
  public func activate(_ plan: OwnerSetupPlan, review: OwnerInstallationReview) async throws -> WorkAccessConfiguration {
    guard review.ownerPublicKey == plan.ownerPublicKey, review.resourceID == plan.resourceID else { throw OwnerSetupError.changed }
    let data = try await run(["activate", "--plan-file", try planFile(plan).path, "--review-digest", review.digest])
    guard let result = try JSONSerialization.jsonObject(with: data) as? [String: Any],
      result["schema"] as? String == "devgraph.owner-install-result.v1",
      result["active"] as? Bool == true, result["resource_id"] as? String == plan.resourceID,
      result["endpoint"] as? String == review.endpoint,
      result["owner_public_key"] as? String == plan.ownerPublicKey,
      result["member_grants_created"] as? Int == 0,
      result["native_key_unchanged"] as? Bool == true,
      result["database_restarted"] as? Bool == false,
      result["private_api_unchanged"] as? Bool == true,
      result["owner_wallet_confirmation_required"] as? Bool == true,
      let connection = result["connection"] as? [String: Any],
      try WorkServerSettings.decode(JSONSerialization.data(withJSONObject: connection)) == review.connection
    else { throw OwnerSetupError.changed }
    return review.connection
  }
  private func run(_ args: [String]) async throws -> Data {
    try await Task.detached {
      let url = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/Zenith/Devgraph/bin/devgraph-owner-setup")
      var info = stat()
      guard lstat(url.path, &info) == 0, info.st_uid == getuid(), info.st_nlink == 1,
        url.resolvingSymlinksInPath().path == url.path,
        info.st_mode & S_IFMT == S_IFREG, info.st_mode & 0o077 == 0,
        info.st_mode & 0o100 != 0 else { throw OwnerSetupError.unavailable }
      let process = Process(), output = Pipe()
      process.executableURL = url; process.arguments = args
      process.environment = ["PATH":"/usr/bin:/bin:/usr/sbin:/sbin", "LANG":"en_US.UTF-8", "PYTHONDONTWRITEBYTECODE":"1"]
      process.standardInput = FileHandle.nullDevice; process.standardOutput = output; process.standardError = FileHandle.nullDevice
      try process.run()
      // A timed-out activation remains a retained run; never auto-retry it.
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

public struct OwnerInstallationState: Sendable {
  public let prepared: Bool
  public let activationAttempted: Bool
  public let activationRecorded: Bool
  public let phases: [String]
  public let review: OwnerInstallationReview?
}
#endif
