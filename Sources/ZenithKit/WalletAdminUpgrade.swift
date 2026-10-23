#if os(macOS)
import Foundation

/// Explicit upgrade of the selected resource, with a separately reviewed
/// loopback Wallet channel. Never a replacement graph or a guessed LAN target.
public struct WalletAdminUpgradeProposal: Sendable {
  public let resourceID: String
  public let sourceEndpoint: String
  public let walletEndpoint: String
  public static func decode(_ data: Data, target: OwnerRegistrationTarget) throws -> Self {
    var strict = OwnerPlanJSON(data); try strict.validate()
    guard let raw = try JSONSerialization.jsonObject(with:data) as? [String:Any],
      Set(raw.keys) == ["schema","resource_id","source_endpoint","wallet_endpoint","local_only","authority_changed"],
      raw["schema"] as? String == "devgraph.wallet-admin-upgrade-proposal.v1",
      raw["resource_id"] as? String == target.resourceID, raw["source_endpoint"] as? String == target.endpoint,
      raw["local_only"] as? Bool == true, raw["authority_changed"] as? Bool == false,
      let endpoint = raw["wallet_endpoint"] as? String,
      OwnerSetupPlan.localWalletAddress(endpoint), URL(string:endpoint)?.host == "127.0.0.1"
    else { throw OwnerSetupError.changed }
    return Self(resourceID:target.resourceID,sourceEndpoint:target.endpoint,walletEndpoint:endpoint)
  }
}

extension OwnerSetupPlan {
  public static func walletAdminUpgrade(resource: LocalResource, inspection: OwnerSetupInspection,
    ownerPublicKey: String, proposal: WalletAdminUpgradeProposal, now: UInt64) throws -> Self {
    guard inspection.healthy, inspection.resource == resource,
      proposal.resourceID == resource.id, proposal.sourceEndpoint == resource.endpoint
    else { throw OwnerSetupError.changed }
    return try Self(resource:resource,registrationSHA256:inspection.registrationSHA256,
      configurationSHA256:inspection.configurationSHA256,ownerPublicKey:ownerPublicKey,
      walletEndpoint:proposal.walletEndpoint,preset:.projectManager,writeOperations:OwnerPermissionPreset.allOperations,
      global:true,paths:[],notBefore:now,notAfter:nil,publishHierarchy:false,
      readOperations:CredentialPresetRevision.allReads,walletAdminUpgrade:true)
  }
}
#endif
