# Build 33 integration baseline

Development preview: application version 0.2.0, build 33. This records a tested
source baseline, not a production security certification or an LTS support policy.

## Source composition

Public installation fixes from Transfer `28c069d21f9cc22c19778295b16709b7419624e4`
are combined with protected secondary-endpoint local RPC v3, hierarchical
credential preparation and bounded protocol diagnostics. Existing endpoint-bound
contracts, operator consent, original-action recovery and onward-delegation
restrictions are preserved.

`Dependencies.json` pins the public organization Wallet repository at
`7d81c5b0a9f74271fb5b2d5ea8d2711df40bf485`, also used for Chrome 0.0.2. All 37
tracked production/build files in the three native Wallet crates match the
previous core source exactly; the two changed crate files are sanitized owner
bootstrap tests/fixtures. Workspace members, resolver and lockfile are unchanged.
The public workspace adds explicit exclusions for independent source workspaces.
The native XCFramework was rebuilt from the pinned public checkout.

## Verification

- Full Swift suite: 182 tests, seven opt-in checks skipped, zero failures.
- Public core build harness: four tests passed, including locked dependency
  resolution, explicit offline mode, and rejection before artifact replacement
  when revision or inputs change.
- Native Wallet release library and macOS arm64 XCFramework built successfully.
- Transfer executable packaged and ad-hoc signature verified strictly.
- Public privacy and secret-history checks passed before publication; neutral
  contributor metadata is retained.

The full suite covers local RPC and network operator transports with synthetic
custody, bounded hierarchical selections, stale/changed binding rejection and
uncertain original-action recovery. Skipped checks require explicit live Hermes,
LAN, installed discovery/RPC, private offline-inbox or selected owner fixtures.
Existing Swift 6 concurrency warnings in test helpers remain; this package uses
its declared Swift 5.9 language contract.

No real Wallet unlock, signing, grant, owner registration, listener, certificate
trust, Tailscale mapping or production policy was changed by this qualification.
The packaged app was not launched into an existing user session. Native UI and
physical-device acceptance remain separate from the component regression suite.

## Deliberate limits

Arena paths can scope Work descendants. Reading Arena records themselves remains
gated on the coordinated versioned DevGraph/native read-scope contract. This
baseline does not silently add Arena to historical Work-kind enums or reinterpret
existing credentials. Canonical service credentials shared across access points
remain specified separately; legacy URL-bound grants retain their semantics.
Provider authentication and executable service-publication controls are still
separate work. Public app binaries are not included in this source release;
distribution signing, notarization and artifact privacy qualification are separate.
