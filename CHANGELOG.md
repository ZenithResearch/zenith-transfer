## Portable Wallet identities — unreleased

- Pin shared public core0.3.0 at `054b372d686e2f8dba0ad8bbd166adbde9ebab38`.
- Add core-owned Matrix/Nostr/GitHub/X public identity descriptors with reviewed
  edits and explicit copying of legacy app records; preserve originals/Tailscale.
- Read and review Castawayv2 before writing it, preserve v1 files and newer records
  during old-file imports, and show existing derived crypto account addresses.
- Cover descriptor bounds, conflicts, encryption, actual backup/restore and
  lock/stale-revision behavior with native C ABI integration tests.

## Wallet backup boundary — unreleased

- Restrict Wallet navigation to data covered by implemented recovery or Castaway
  backup paths. Show portable membership proofs instead of provider setup.
- Move application account records, Network, provider setup and unlock settings
  into Settings; preserve existing storage and exports.
- Keep service access outside Wallet until database backup/restore coverage exists.

## Native Wallet consistency — unreleased

- Share the Wallet home, public account records, password visibility/Copy controls
  and recovery-password reuse across macOS, iPad and iPhone.
- Default automatic lock to one hour of inactivity, with 15-minute, four-hour and
  until-lock-or-quit choices; preserve existing timeout preferences.
- Keep unlock separate from every connection and signing review; expired input
  cannot revive custody, and background refreshes cannot extend it.
- Pin the native core to public Castalia `575895f70e4cbdc982b7c9271b468470271dbb0b`.

# Changelog

All notable changes to this project are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)

## [Unreleased]

### Fixed

- Recheck protected local RPC v3 registrations for LAN, Tailnet and public service profiles — locally registered administration must use its pinned host adapter and fail closed when the binding changes.
- Accept bounded hierarchical grant-review envelopes and report safe protocol errors — valid path selections exceeded the setup parser's smaller nesting budget and otherwise produced an opaque failure.
- Follow the verified public Wallet packaging revision — its source-integrity checks now pin the reviewed workspace lockfile.
- Pin the public native Wallet source and document a complete build from public repositories — the previous private-only revision prevented installation.
- Allow locked Cargo downloads by default and make offline mode explicit — fresh machines do not yet have the dependency cache required by forced offline builds.

### Changed

- Pin the public Wallet revision `7d81c5b0a9f74271fb5b2d5ea8d2711df40bf485` and label the development app build 33 — native Transfer and the public Chrome extension now build from the same canonical Wallet source revision.

### Added

- Document canonical service credentials and future owner-controlled endpoints — access points must not be mistaken for distinct credential authorities while existing URL-bound contracts remain unchanged.
