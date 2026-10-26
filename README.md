# Zenith Transfer

Native macOS companion for a Castalia Wallet: manage DevGraph access requests and
custom scoped credentials, organize identities and accounts, discover local
services, and transfer encrypted recovery files by QR.

Development preview, not a notarized or generally qualified distribution. The app
keeps the existing `ca.zenith.preview.transfer` bundle identifier and
`Application Support/ZenithTransfer` storage, so moving the source repository does
not migrate or replace your Wallet. It starts locked. Existing grants remain on
their servers.

## Build

Apple Silicon Mac, macOS 13+, Xcode and Swift 5.9+, Python 3, and Rust/Cargo.
The native Wallet dependency is public source, pinned to an exact revision in
`Dependencies.json`. Start in a clean checkout of this repository and build it:

```sh
git clone https://github.com/ZenithResearch/castalia-wallet.git ../castalia-wallet
wallet_revision=$(python3 -c 'import json; print(json.load(open("Dependencies.json"))["wallet"]["revision"])')
git -C ../castalia-wallet checkout --detach "$wallet_revision"
rustup target add aarch64-apple-darwin
scripts/build-core.sh ../castalia-wallet
swift test
scripts/build-transfer-app.sh
open 'Artifacts/Zenith Transfer.app'
```

The builder verifies the dependency revision and clean Rust inputs. It packages
only the macOS arm64 slice. Cargo downloads dependencies as needed while preserving
the committed lockfile. For a previously populated Cargo cache, opt into offline
mode with `ZENITH_CARGO_OFFLINE=1 scripts/build-core.sh ../castalia-wallet`.
Native build manifests and binaries are local ignored
outputs. `scripts/build-transfer-app.sh` creates an ad-hoc signed development app
with the established Zenith artwork. Distribution signing/notarization is separate.

The public dependency preserves the native ABI, encrypted recovery format, and
graph/operator/owner consent used by the earlier private pin. Source provenance
is recorded in the Wallet repository's `TRANSFER-NATIVE-SOURCE.json`.

The current development app is **0.2.0 build 43**. Its pinned Wallet revision is
`0c889e7a993f48d7b34321359d1949cf8ddc4eb8`, the common public Castalia core
0.4.0 baseline also used for the native iOS build. Native and browser clients expose
different interfaces over the shared core; aligning the source does not enable
new credential schemas or grant permissions.

## Identities & accounts

Application account records are managed in **Settings → Application accounts**.
Wallet itself contains backup-covered identity, membership proofs and recovery. Add, edit or remove Matrix IDs/homeservers, Nostr public keys/relays
and Tailscale account/Tailnet records. Records are local public metadata, partitioned
by the Castalia public key; they do not prove account ownership or authenticate.
Editing requires the matching unlocked Wallet. Readable records stay visible
while locked. Nostr currently accepts lowercase 64-character hex public keys.

Authentication is explicitly **Not connected**. Provider login, session handling,
external signer connections and Keychain secret references are follow-up adapters.
Do not enter passwords, API tokens, auth keys or private keys in account fields.
Tailscale host status uses the existing installed host CLI read-only; it is
separate from saved Tailscale account identity and is never an access grant.

**Settings → Network → API access tokens** separately saves named Tailscale API
tokens in this Mac’s non-synchronizing login Keychain. Choose a saved token in
**Generate auth key**, then review and explicitly generate a one-time device
enrollment key. Saved tokens are application network secrets, excluded from Wallet
and connection-file exports. See [network setup](docs/network-onboarding.md).

DevGraph credentials remain in **Resources & requests**, with presets/custom
operations and Arena/path scopes. The server verifies Wallet-signed decisions;
an account record, discovery entry, local network connection or unlocked Wallet
alone never creates authority. Onward delegation remains disabled.

Locally registered services use their protected secS RPC binding even when their
advertised HTTPS profile is for LAN or Tailnet access. Transfer rechecks the
registration, full configuration and fixed adapter hash before dispatch, and
does not silently fall back to HTTP when a local binding is missing or changed.
Hierarchical credential selection keeps its original path and recovery checks.
An Arena path can constrain Work access; reading Arena records themselves needs
a separately versioned receiver and native scope contract.

## Boundaries and provenance

- Extracted from the `ZenithResearch/zenith-ios` Transfer target; the iOS repository
  and installed devices are unchanged by this initialization.
- Shared `Sources/ZenithKit` is copied with tests to keep the extraction buildable;
  it is not a new graph runtime or a replacement ontology.
- Vendored DevGraph editor provenance is in
  `Sources/ZenithTransfer/Resources/Operator/provenance.json`.
- Castalia component notices are in `Notices/`. Existing notices are preserved;
  this extraction makes no new licensing/relicensing decision for app code.
- User Wallet databases, recovery files, credentials, journals, machine registries,
  signing profiles and compiled artifacts are excluded from Git.
- Service publication is review-only. This update creates no network listeners,
  owner registrations, grants, public routes or Tailscale configuration changes.

See [update spec](docs/identities-update-spec.md),
[architecture](docs/architecture.md), and [security limits](SECURITY.md).

The [native Wallet experience](docs/native-wallet-experience.md) describes the shared
Wallet home, recovery/password controls and configurable inactivity lock.

Portable identities use the shared [Castaway v2 contract](docs/portable-wallet-identities.md),
with explicit review before copying original application records into Wallet.

Build storage: successful app/Core packaging automatically keeps one previous
build and any older backup still in use. `python3 scripts/prune-build-backups.py`
previews cleanup; add `--apply` to remove eligible backups. If open-file checks
fail, backups are kept. Current/numbered app releases and source/user data are
never candidates. Reuse the same build directories rather than creating a new
dated cache for every run.
