import SwiftUI

/// One review policy and wording for iOS and Transfer. Confirmation stays with
/// the caller, which commits the unchanged preview exactly once.
public struct WalletImportReviewContent: View {
  let review: WalletImportReview
  public init(review: WalletImportReview) { self.review = review }
  public var body: some View {
    VStack(alignment: .leading, spacing: 20) {
      if review.recoversWallet {
        Text("Wallet recovery").font(.headline).accessibilityAddTraits(.isHeader)
        Text(review.preview.backupVerified ? "Recovery file checked" : "Save and check a recovery file after importing.")
          .font(.footnote).foregroundStyle(.secondary)
        publicKey
        accounts(review.derivedAccounts, title: "Derived blockchain accounts")
        Text("These public addresses are derived from your recovered Wallet. Transaction signing is not available here.")
          .font(.footnote).foregroundStyle(.secondary)
      } else {
        Text("Matching Wallet").font(.headline).accessibilityAddTraits(.isHeader)
        publicKey
      }
      if review.hasCastawayData {
        Divider()
        Text("Castaway data").font(.headline).accessibilityAddTraits(.isHeader)
        Text("Review the saved data after import. This file cannot restore signing keys.")
          .font(.footnote).foregroundStyle(.secondary)
        if review.replacesProfile { Text("Your saved profile will be replaced.") }
        if review.replacedProofCount > 0 {
          Text("\(review.replacedProofCount) membership proof(s) will be replaced. Other saved proofs are kept.")
        }
        if let profile = review.profile {
          DisclosureGroup("Profile after import") {
            ForEach(profile.subject.fields.keys.sorted(), id: \.self) { key in
              if let field = profile.subject.fields[key] {
                VStack(alignment: .leading, spacing: 4) {
                  Text(key).font(.caption).foregroundStyle(.secondary)
                  Text(field.value).textSelection(.enabled)
                }.frame(maxWidth: .infinity, alignment: .leading).padding(.vertical, 4)
              }
            }
          }
        }
        if !review.proofs.isEmpty {
          DisclosureGroup("Membership proofs after import (\(review.proofs.count))") {
            ForEach(review.proofs) { proof in
              VStack(alignment: .leading, spacing: 4) {
                Text(proof.issuerId)
                Text(proof.membershipId).font(.caption.monospaced())
                if let scope = proof.scopeId { Text(scope).font(.caption) }
              }.textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading).padding(.vertical, 4)
            }
          }
        }
        if let section = review.savedIdentities {
          DisclosureGroup("Saved account identities (\(section.accounts.count))") {
            if section.accounts.isEmpty { Text("No saved account identities after import.").foregroundStyle(.secondary) }
            else { WalletIdentityReviewRows(section: section, showsHeading: false) }
          }
        }
        if let note = review.identityImportNote { Text(note).font(.footnote).foregroundStyle(.secondary) }
        if !review.savedAccounts.isEmpty { accounts(review.savedAccounts, title: "Saved account descriptors") }
      } else {
        Text("Saved account identities, profile and membership proofs are backed up separately in Castaway data. You can import that file after recovering your Wallet.")
          .font(.footnote).foregroundStyle(.secondary)
      }
    }.frame(maxWidth: .infinity, alignment: .leading)
  }
  private var publicKey: some View {
    DisclosureGroup("Wallet public key") {
      Text(review.preview.publicKey).font(.caption.monospaced()).textSelection(.enabled)
        .frame(maxWidth: .infinity, alignment: .leading)
    }
  }
  private func accounts(_ values: [PublicAccounts.Account], title: String) -> some View {
    DisclosureGroup("\(title) (\(values.count))") {
      ForEach(values) { account in
        VStack(alignment: .leading, spacing: 4) {
          Text(account.networkId)
          Text(account.address).font(.caption.monospaced())
        }.textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading).padding(.vertical, 4)
      }
    }
  }
}
