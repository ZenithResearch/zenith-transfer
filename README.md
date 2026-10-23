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

Apple Silicon Mac, macOS 13+, Xcode and Swift 5.9+. The native Wallet dependency
must be built from the exact revision in `Dependencies.json` using an authorized
Wallet checkout. That revision is currently not available from the public Wallet
mirror. This repository publishes the Swift application and vendored editor, not
the private dependency or prebuilt Wallet binaries. A clean public-only build is
therefore not yet available; dependency source publication is a separate release.

```sh
scripts/build-core.sh /absolute/path/to/authorized/castalia-wallet
swift test
scripts/build-transfer-app.sh
open 'Artifacts/Zenith Transfer.app'
```

The builder verifies the dependency revision and clean Rust inputs. It packages
only the macOS arm64 slice. Native build manifests and binaries are local ignored
outputs. `scripts/build-transfer-app.sh` creates an ad-hoc signed development app
with the established Zenith artwork. Distribution signing/notarization is separate.

## Identities & accounts

Wallet has three views: **Identities & accounts**, **Wallet & security**, and
**How it fits**. Add, edit or remove Matrix IDs/homeservers, Nostr public keys/relays
and Tailscale account/Tailnet records. Records are local public metadata, partitioned
by the Castalia public key; they do not prove account ownership or authenticate.
Editing requires the matching unlocked Wallet. Readable records stay visible
while locked. Nostr currently accepts lowercase 64-character hex public keys.

Authentication is explicitly **Not connected**. Provider login, session handling,
external signer connections and Keychain secret references are follow-up adapters.
Do not enter passwords, API tokens, auth keys or private keys in account fields.
Tailscale host status uses the existing installed host CLI read-only; it is
separate from saved Tailscale account identity and is never an access grant.

DevGraph credentials remain in **Resources & requests**, with presets/custom
operations and Arena/path scopes. The server verifies Wallet-signed decisions;
an account record, discovery entry, local network connection or unlocked Wallet
alone never creates authority. Onward delegation remains disabled.

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
