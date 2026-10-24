# Native Wallet experience

Transfer and Zenith on iPad/iPhone share the Wallet home, destination names,
status descriptions, password visibility/Copy controls, account-record parser,
password rules and inactivity policy. `ZenithKit/WalletComponents.swift` is the
shared SwiftUI surface. Run `scripts/check-wallet-experience-parity.py` against
the other native repository before releasing either application.

## Navigation and custody

Wallet opens on backup-covered identity, membership proofs and recovery.
Application accounts, Network, membership provider setup, unlock preferences and
explanatory help live in Settings. Service access and administration stay in the
application. See [the backup boundary](wallet-backup-boundary.md).
Transfer's application access screen selects a registered resource and its administrative
inbox; iOS opens the member Work-access flow. This platform-specific action does
not change the meaning of Wallet possession, membership or a credential.

Both applications protect their own encrypted local copy of the same recovered
identity. Import can reuse the backup password, or choose a separate local unlock
password. The original backup is unchanged. The authenticated public identity is
reviewed before committing an import. Password rules use Unicode scalars and a
UTF-8 byte ceiling matching the native core; passwords are not normalized.

Public Matrix, Nostr and Tailscale account records are separate from custody.
They do not authenticate providers, sign events, connect a Tailnet, or grant
service permissions. iOS records are excluded from backup and protected while the
device is locked. Editing requires the matching unlocked Wallet.

## Inactivity and consent

New preferences default to one hour without interaction. Normal choices are
15 minutes, one hour, four hours, or Until I lock or quit. Existing saved
preferences remain unchanged, including older two/five/thirty-minute choices;
those appear while selected so a legacy choice is never silently overwritten.

Only local app input resets inactivity. Metadata reads, polling, timers,
network responses and app activation do not. Time spent asleep or in another app
counts toward inactivity. An overdue click locks before it can renew the timer.
Clock rollback does not prolong custody. Lock/quit always ends local custody.
App-local observers do not read text, key contents, pointer positions or history.

Unlock is not consent. Connection, issuer trust, membership and signing decisions
retain their own review. Lock invalidates pending work immediately. iOS cancels
pending approvals in the background and checks expiry before resuming; automatic
Touch ID on iPad and button-triggered unlock on iPhone retain their existing rules.
