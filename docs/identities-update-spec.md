# Identities & accounts — Transfer build 30

## Outcome

Add a native Wallet workspace matching the reviewed preview: Wallet & security,
Identities & accounts, and How it fits. Retain all existing custody, owner setup,
custom credential selection, service discovery and file-transfer behavior.

## Initial working slice

- Create, edit and remove Matrix, Nostr and Tailscale public account records.
- Partition records by Castalia public key. Reading remains available while locked;
  saving/removing requires the matching unlocked Wallet. This is a local UI guard,
  not a cryptographic attestation that an account belongs to the Wallet.
- Validate provider-specific public identifiers. Store only a closed metadata
  schema in owner-private storage, using bounded reads and compare-and-swap writes.
- Matrix: Matrix ID and HTTPS homeserver origin. Nostr: 32-byte public key in hex
  and optional secure WebSocket relay. Tailscale: account label and Tailnet DNS name.
- Show authentication as **Not connected**; saving a record does not log in, sign,
  obtain a token, change a grant, or prove account ownership.
- Tailscale separately reads the existing host service's live status and mapping
  summary. Host observations do not authenticate a saved Tailscale account.
- Explain protected authentication as a future provider adapter, with no secret
  fields in metadata. Host node keys remain with Tailscale. DevGraph authority
  remains independently verified through its existing signed administration flow.

## Repository

Initialize `ZenithResearch/zenith-transfer` as a public macOS source repository on
`main`, extracted from the existing native app and shared ZenithKit. Preserve the
app bundle ID and Application Support paths. Keep iOS builds, local user data,
compiled artifacts, private keys and machine configuration out of Git. Preserve
third-party notices and document the pinned native Wallet build dependency.
Do not merge unrelated pending LAN runtime experiments into this release.

## Acceptance

Native package builds; existing native suites pass. Test public-record roundtrip,
Wallet partitioning, stale edits, invalid provider fields, unknown secret fields,
size/count limits and linked-file rejection. Inspect the installed layout with
empty and saved accounts. Confirm saved records do not enable authentication or
grant operations. Publication audit scans exactly the staged repository tree.

## Follow-up

Provider login/session adapters and Keychain-backed secret references, account
verification, portable identity export, persistent host configuration activation,
and broader Tailnet API management remain separate changes. Never infer DevGraph
ownership from Matrix/Nostr/Tailscale authentication.
