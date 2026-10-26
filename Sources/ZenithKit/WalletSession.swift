import Foundation

public struct WalletState: Decodable, Sendable {
  public let configured: Bool
  public let unlocked: Bool
  public let revision: UInt64
  public let publicKey: String?
  public let backupVerified: Bool
  public let membershipActive: Bool
  public let backupEligible: Bool?
  public let graphAccessProtocol: String?
  public let operatorAccessProtocol: String?
  public let resourceOwnerProtocol: String?
  public var holderGrantProtocol: String? = nil
  public var canRequestWorkAccess: Bool {
    unlocked && (backupEligible ?? backupVerified)
      && graphAccessProtocol == "castalia.graph-access.v2"
  }
  enum CodingKeys: String, CodingKey {
    case membershipActive = "membership_active"
    case backupEligible = "backup_eligible"
    case graphAccessProtocol = "graph_access_protocol"
    case operatorAccessProtocol = "operator_access_protocol"
    case resourceOwnerProtocol = "resource_owner_protocol"
    case holderGrantProtocol = "holder_grant_protocol"
    case configured, unlocked, revision
    case publicKey = "public_key"
    case backupVerified = "backup_verified"
  }
}
public struct RestorePreview: Decodable, Sendable, Identifiable {
  public var id: String { token }
  public var holderGrants: [HolderGrantSummary]? = nil
  public let token: String
  public let expectedRevision: UInt64
  public let publicKey: String
  public let backupVerified: Bool
  public let profile: PortableProfile?
  public let chainAccounts: PublicAccounts?
  public let walletIdentities: WalletIdentitySection?
  public let importedWalletIdentities: Int?
  public let memberships: PortableSections?
  public let replacesProfile: Bool?
  public let replacedProofs: [String]?
  enum CodingKeys: String, CodingKey {
    case profile, memberships
    case chainAccounts = "chain_accounts"
    case walletIdentities = "wallet_identities"
    case importedWalletIdentities = "imported_wallet_identities"
    case replacesProfile = "replaces_profile"
    case replacedProofs = "replaced_proofs"
    case holderGrants = "holder_grants"
    case token
    case expectedRevision = "expected_revision"
    case publicKey = "public_key"
    case backupVerified = "backup_verified"
  }
}
/// Shared Swift abstraction, not an IPC interface. Maintenance passwords
/// belong exclusively in signer-owned UI after the process cutover.
public protocol WalletSession: Actor {
  func holderGrantSummaries() async throws -> [HolderGrantSummary]
  func holderGrant(service: String, now: UInt64) async throws -> Data
  func reviewHolderGrant(_ grant: Data, pin: HolderIssuerPin, now: UInt64) async throws
    -> HolderGrantReview
  func saveHolderGrant(_ review: HolderGrantReview, now: UInt64) async throws
  func deriveHolderCredential(service: String, permissions: Data?, expires: UInt64, now: UInt64)
    async throws -> Data
  func presentHolderCredential(service: String, credential: Data, call: Data, now: UInt64)
    async throws -> Data
  func forgetHolderGrant(service: String) async throws
  func exportHolderGrantBackup() async throws -> Data
  func prepareHolderGrantBackup(_ file: Data) async throws -> RestorePreview

  nonisolated func lifecycleTicket() -> UInt64
  nonisolated func checkLifecycle(_ ticket: UInt64) throws
  nonisolated func invalidatePendingWork()
  nonisolated func pauseForBackground() -> Task<Void, Never>
  func state() async throws -> WalletState
  func create(password: String) async throws -> WalletState
  func prepareRestore(
    file: Data, filePassword: String, password: String, dataFile: Data?, dataPassword: String?
  ) async throws -> RestorePreview
  func commit(_ preview: RestorePreview) async throws -> WalletState
  func unlock(password: String, expectedLifecycle: UInt64?, expectedIdentity: String?) async throws
    -> WalletState
  func exportRecovery(password: String) async throws -> Data
  func verifyBackup(file: Data, password: String) async throws -> WalletState
  func prepareData(file: Data, password: String) async throws -> RestorePreview
  func exportData(password: String) async throws -> Data
  func prepareLegacy(key: String, password: String) async throws -> RestorePreview
  func approveTrust(_ trust: Data) async throws -> WalletState
  func membershipRequest(scope: String?) async throws -> Data
  func activateMembership(_ proof: Data, scoped: Bool) async throws -> WalletState
  func trustMatches(_ trust: Data) async throws -> Bool
  func importedMemberships(scope: String?) async throws -> [Data]
  func walletIdentitySnapshot() async throws -> WalletIdentitySnapshot
  func prepareWalletIdentities(_ identities: WalletIdentitySection, expectedRevision: UInt64)
    async throws -> RestorePreview
  func dataSummary() async throws -> Data
  func portableMembershipProofs() async throws -> [PortableSections.Proof]
  func readAccessIdentity() async throws -> Data
  func approveReadAccess(_ challenge: Data, receiver: String, now: UInt64) async throws -> Data
  func storeReadAccess(
    requestID: String, secret: String, expires: UInt64, metadata: Data, now: UInt64, ticket: UInt64)
    async throws
  func prepareAccessRequest(_ challenge: Data, pin: ReadAuthorityPin, now: UInt64) async throws
    -> NativeAccessRequestPreview
  func approveAccessRequest(_ preview: NativeAccessRequestPreview, now: UInt64, ticket: UInt64)
    async throws -> Data
  func approveReadCredential(_ challenge: Data, pin: ReadAuthorityPin, now: UInt64) async throws
    -> Data
  func storeReadCredential(requestID: String, credential: Data, now: UInt64, ticket: UInt64)
    async throws
  func readCredential(receiver: String, now: UInt64) async throws -> Data
  func signReadCall(receiver: String, call: Data, now: UInt64) async throws -> Data
  func graphAccessIdentityV2() async throws -> Data
  func prepareGraphAccessRequestV2(_ challenge: Data, pin: ReadAuthorityPin, now: UInt64)
    async throws -> NativeAccessRequestPreview
  func approveGraphAccessRequestV2(
    _ preview: NativeAccessRequestPreview, now: UInt64, ticket: UInt64
  ) async throws -> Data
  #if os(macOS)
    func prepareResourceOwner(_ challenge: Data, binding: ResourceOwnerBinding, now: UInt64)
      async throws -> ResourceOwnerConsent
    func approveResourceOwner(_ consent: ResourceOwnerConsent, now: UInt64) async throws -> Data
  #endif
  func prepareOperatorAccess(_ challenge: Data, pin: ReadAuthorityPin, now: UInt64) async throws
    -> OperatorConsent
  func approveOperatorAccess(_ consent: OperatorConsent, now: UInt64) async throws -> Data
  func approveGraphReadCredentialV2(_ challenge: Data, pin: ReadAuthorityPin, now: UInt64)
    async throws -> Data
  func graphReadCredentialV2(receiver: String, now: UInt64) async throws -> Data
  func signGraphReadCallV2(receiver: String, call: Data, now: UInt64) async throws -> Data
  func readAccess(receiver: String, now: UInt64) async throws -> Data
  func forgetReadAccess(receiver: String) async throws
  func approveRestoreTrust(_ trust: Data) async throws
  func cancel() async
  func lock() async
}
extension WalletSession {
  public func prepareRestore(file: Data, filePassword: String, password: String) async throws
    -> RestorePreview
  {
    try await prepareRestore(
      file: file, filePassword: filePassword, password: password, dataFile: nil, dataPassword: nil)
  }
  public func unlock(password: String) async throws -> WalletState {
    try await unlock(password: password, expectedLifecycle: nil, expectedIdentity: nil)
  }
  public func unlock(password: String, expectedLifecycle: UInt64?) async throws -> WalletState {
    try await unlock(
      password: password, expectedLifecycle: expectedLifecycle, expectedIdentity: nil)
  }
}

extension WalletSession {
  public func holderGrantSummaries() async throws -> [HolderGrantSummary] {
    throw WalletFailure.core("holder_grants_unavailable")
  }
  public func holderGrant(service: String, now: UInt64) async throws -> Data {
    throw WalletFailure.core("holder_grants_unavailable")
  }
  public func reviewHolderGrant(_ grant: Data, pin: HolderIssuerPin, now: UInt64) async throws
    -> HolderGrantReview
  { throw WalletFailure.core("holder_grants_unavailable") }
  public func saveHolderGrant(_ review: HolderGrantReview, now: UInt64) async throws {
    throw WalletFailure.core("holder_grants_unavailable")
  }
  public func deriveHolderCredential(
    service: String, permissions: Data?, expires: UInt64, now: UInt64
  ) async throws -> Data { throw WalletFailure.core("holder_grants_unavailable") }
  public func presentHolderCredential(service: String, credential: Data, call: Data, now: UInt64)
    async throws -> Data
  { throw WalletFailure.core("holder_grants_unavailable") }
  public func forgetHolderGrant(service: String) async throws {
    throw WalletFailure.core("holder_grants_unavailable")
  }
  public func exportHolderGrantBackup() async throws -> Data {
    throw WalletFailure.core("holder_grants_unavailable")
  }
  public func prepareHolderGrantBackup(_ file: Data) async throws -> RestorePreview {
    throw WalletFailure.core("holder_grants_unavailable")
  }
}
