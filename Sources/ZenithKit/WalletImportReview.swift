import Foundation

/// Presentation only. The immutable context describes the files used to prepare
/// this exact token; a synthesized/merged identity section is not file provenance.
/// Core still owns authentication, revision checks, cancellation and commit.
public struct WalletImportReview: Identifiable, Sendable {
  public enum DataVersion: Sendable { case v1, v2 }
  public enum Context: Equatable, Sendable {
    case recovery, olderRecoveryKey
    case castaway(DataVersion), recoveryAndCastaway(DataVersion)

    public static func dataFile(_ file: Data, recovering: Bool) throws -> Self {
      let format = try RecoveryFileFormat.inspect(file, filename: "data.castaway")
      guard format.kind == .castaway else { throw RecoveryTransferError.invalidFile }
      let version: DataVersion = format.version == "v2" ? .v2 : .v1
      return recovering ? .recoveryAndCastaway(version) : .castaway(version)
    }
    fileprivate var dataVersion: DataVersion? {
      switch self {
      case .recovery, .olderRecoveryKey: return nil
      case .castaway(let version), .recoveryAndCastaway(let version): return version
      }
    }
  }
  public let preview: RestorePreview
  public let context: Context
  public var id: String { preview.token }
  public init(preview: RestorePreview, context: Context) {
    self.preview = preview; self.context = context
  }
  public var recoversWallet: Bool {
    if case .castaway = context { return false }
    return true
  }
  public var hasCastawayData: Bool { context.dataVersion != nil }
  public var derivedAccounts: [PublicAccounts.Account] {
    recoversWallet ? preview.chainAccounts?.accounts ?? [] : []
  }
  public var profile: PortableProfile? { hasCastawayData ? preview.profile : nil }
  public var proofs: [PortableSections.Proof] { hasCastawayData ? preview.memberships?.proofs ?? [] : [] }
  public var savedAccounts: [PublicAccounts.Account] {
    hasCastawayData ? preview.memberships?.chainAccounts?.accounts ?? [] : []
  }
  public var replacesProfile: Bool { hasCastawayData && preview.replacesProfile == true }
  public var replacedProofCount: Int { hasCastawayData ? preview.replacedProofs?.count ?? 0 : 0 }
  public var savedIdentities: WalletIdentitySection? {
    context.dataVersion == .v2 ? preview.walletIdentities : nil
  }
  public var identityImportNote: String? {
    guard let version = context.dataVersion else { return nil }
    if version == .v1 {
      return "This older Castaway file has no saved account identities. Existing identities are preserved."
    }
    let count = preview.importedWalletIdentities ?? preview.walletIdentities?.accounts.count ?? 0
    return "This file contains \(count) saved account identities. Existing nonconflicting identities are preserved; the review shows the result after import."
  }
}
