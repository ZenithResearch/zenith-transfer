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
  public let feeds: PortableFeedSection?
  public let chainAccounts: PublicAccounts?
  public var proofs: [Proof] { (memberships ?? []) + (scopedMemberships ?? []) }
}

/// Read-only presentation of a Rust-validated section. These values must never
/// be encoded to reconstruct persisted contents or used as fetch authorization.
public struct PortableFeedSection: Decodable, Sendable {
  public struct Subscription: Decodable, Identifiable, Sendable {
    public let id: String
    public let url: String
    public let format: String
    public let title: String
    public let enabled: Bool
    public let collectionIds: [String]
    public let disclosure: String
    public var reviewTitle: String {
      title.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? "Untitled subscription" : title
    }
  }
  public struct Collection: Decodable, Identifiable, Sendable {
    public let id: String
    public let title: String
    public var reviewTitle: String {
      title.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? "Untitled collection" : title
    }
  }
  public struct Preferences: Decodable, Sendable {
    public let order: String
  }
  public let schema: String
  public let version: Int
  public let subscriptions: [Subscription]
  public let collections: [Collection]
  public let preferences: Preferences
}
