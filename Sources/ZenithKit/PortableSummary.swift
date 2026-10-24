import Foundation

public struct PortableProfile: Decodable, Sendable {
  public struct Claim: Decodable, Sendable {
    public let value: String
    public let disclosure: String
  }
  public struct Subject: Decodable, Sendable {
    public let memberKey: String
    public let fields: [String: Claim]
  }
  public let subject: Subject
}
public struct PublicAccounts: Decodable, Sendable {
  public struct Account: Decodable, Identifiable, Sendable {
    public let accountId: String
    public let networkId: String
    public let address: String
    public var id: String { accountId }
  }
  public let accounts: [Account]
}
public struct PortableSections: Decodable, Sendable {
  public struct Proof: Decodable, Identifiable, Sendable {
    public let membershipId: String
    public let issuerId: String
    public let scopeId: String?
    public var id: String { membershipId }
  }
  public let memberships: [Proof]?
  public let scopedMemberships: [Proof]?
  public let walletIdentities: WalletIdentitySection?
  public var proofs: [Proof] { (memberships ?? []) + (scopedMemberships ?? []) }
}
