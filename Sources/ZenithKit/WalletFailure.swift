import Foundation

public enum WalletFailure: Error, Equatable, LocalizedError {
  case storage, conflict, locked
  case core(String)
  case invalidFile
  public var errorDescription: String? {
    switch self {
    case .storage: return "Could not save. Your wallet is unchanged."
    case .conflict: return "Your wallet changed. Unlock it again before continuing."
    case .locked: return "Unlock your wallet to continue."
    case .invalidFile: return "This file could not be read. Choose an encrypted recovery file."
    case .core(let code):
      switch code {
      case "identity_conflict", "duplicate_or_invalid_identity":
        return "An identity conflicts with a saved record. Nothing was overwritten; review the records separately."
      case "invalid_wallet_identities", "unsupported_identity_fields", "invalid_identity_text", "invalid_provider_identity", "identities_too_large", "identity_limit":
        return "Check the public identity fields. Passwords, tokens, private keys and session data are not accepted here."
      case "password_minimum_12": return "Use a password with at least 12 characters."
      case "backup_verification_required": return "Check your saved recovery file first."
      case "wallet_already_exists":
        return
          "This installation already has a wallet. Restore another wallet in a separate installation."
      case "backup_identity_mismatch": return "This recovery file belongs to a different wallet."
      case "wallet_locked": return "Unlock your wallet to continue."
      case "trust_setup_required", "untrusted_issuer":
        return
          "This file needs an approved membership provider. Set up Membership before importing it."
      case "data_file_requires_recovery":
        return "This is a data file. Choose your recovery file to restore your wallet."
      case "data_file_invalid":
        return "Could not open this data file. Check its password and try again."
      case "access_expired", "access_denied", "invalid_read_authority":
        return "This Wallet does not currently have usable access to this graph. Check your access request or ask the server operator."
      case "membership_required":
        return "This server requires a membership proof it accepts. Review its membership requirements before reconnecting."
      case "service_setup_required": return "This build needs an approved service configuration."
      case "issuer_setup_required": return "The access provider has changed. An updated connection configuration is needed."
      case "invalid_response", "invalid_credential", "invalid_read_challenge":
        return "The service returned an unexpected response. No connection was saved."
      case "work_view_changed": return "Work changed while loading. Return to Work and pull to refresh before loading more."
      case "unsupported_read_scope": return "Your current access does not include this kind of work or action."
      case "service_rejected_request":
        return "The service could not complete this request. Try again later."
      case "recovery_file_invalid", "unlock_failed":
        return "Could not unlock. Check the file and its password."
      case "preview_stale", "preview_expired":
        return "This preview expired. Choose your file again."
      default: return "Could not complete this step. Your saved wallet is unchanged."
      }
    }
  }
}
