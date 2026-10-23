# Build 30 verification — October 23, 2026

- Xcode toolchain native package: **177 tests, 6 opt-in installed/live checks
  skipped, 0 failures**. Includes existing Wallet consent, cancellation, recovery,
  native operator selection and transport tests.
- New account tests cover closed schema/secret-field rejection, provider formats,
  credential-bearing URLs, bounded input/catalogs, linked records, 0600 writes,
  Wallet partitioning, compare-and-swap/stale deletion, and lock/relaunch behavior.
- Native SwiftUI/AppKit workspace rendered using a disposable test Wallet and
  synthetic Tailscale account. The resulting layout was visually inspected.
  This did not open, unlock or replace the user's active Transfer session.
- Build 30 packaged with the existing app identity/logo and verified by
  `codesign --verify --strict`. Development ad-hoc signature; not notarized.
- Binary SHA-256:
  `fbe008daf5d9f8968b5bbd52ac61f3a7a90f7d8f2d589f2627370cea2816f8d5`.
- Staged repository inventory and Gitleaks scan passed. Five initial findings
  were verified SHA-256 file checksums in provenance/synthetic fixture manifests;
  only those exact checksum values are allowlisted. No broad path exclusions.
- Original iOS worktree was not modified. Pending opt-in LAN RPC v2 support was
  excluded: this extraction retains installed local RPC v1 semantics.

No real provider login, token, graph write, grant activation, host configuration,
or installed-user-session interaction was exercised. The six opt-in checks cover
live Hermes, installed owner status, Tailscale, LAN receiver, local RPC and local
owner inspection. Inherited Swift-6-mode warnings in async test locking remain;
the package currently builds in its declared Swift 5 language mode.

The exact pinned native Wallet revision is not publicly mirrored yet. The public
repository is source, not a fully self-contained public-only build distribution.
Its README states the authorized-checkout build prerequisite explicitly.
