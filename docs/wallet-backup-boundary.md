# Wallet and application backup boundary

Everything presented as Wallet data must have an implemented Wallet recovery,
Wallet data, or Wallet database backup/restore path. A database row, a screen
location, or association with a public key does not establish backup coverage.
The Wallet home is filtered through `WalletDestination.backupCoverage`; adding a
destination requires an explicit coverage decision and restore verification.

| Data / screen | Current backup coverage | Current navigation |
| --- | --- | --- |
| Signing identity | Encrypted recovery file | Wallet → Identities & accounts |
| Derived chain accounts | Same identity recovery; supported Castaway descriptors | Wallet → Identities & accounts |
| Portable Matrix/Nostr/GitHub/X descriptors | Castawayv2 | Wallet → Identities & accounts |
| Saved membership proofs | Encrypted Castaway data file | Wallet → Membership |
| Backup export/check/import | Recovery / Castaway | Wallet → Recovery |
| Local app account records | No Wallet backup | Settings → Application accounts |
| Tailnet enrollment / node keys | Device-local; no Wallet backup | Settings → Network |
| Saved server addresses / connection files | Application configuration | Settings → Network / service management |
| Unlock timeout / biometric setup | Application/device settings | Settings → Unlock & security |
| Membership provider setup / active session | Application configuration | Settings → Membership provider |
| DevGraph requests and grant administration | Service/application state | Resources & requests or Work access |
| Saved installation-bound read credentials | Encrypted local Wallet database; no exposed database backup/restore | Service access outside Wallet home |
| Work objects / cached lists | Service/application data | Work |

The existing recovery format and v1 Castaway files remain supported. Portable identity descriptors use versioned Castawayv2; see [portable identities](portable-wallet-identities.md). Full database backup
and safe restore are not implemented by this navigation change. In particular,
restoring device identities, sessions, installation-bound credentials and replay
state must not be inferred from restoring the signing identity.

Public app account records remain preserved in their existing local registry;
this change moves navigation, not data. Tailscale authentication secrets are not
moved into custody or portable exports. Current derived-chain descriptors remain
preview, descriptor-only accounts; no chain transaction signing is implied.

Before adding Wallet data: define its owner and schema, backup format/version,
export inclusion, import validation, restore semantics and compatibility; prove a
round trip. Until that exists, keep the data outside Wallet navigation.
