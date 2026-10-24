# Portable Wallet identities

Native preview: Transfer build36, iOS build32. Common producer:
`ZenithResearch/castalia-wallet` commit
`054b372d686e2f8dba0ad8bbd166adbde9ebab38`, core0.3.0.

Wallet → Identities & accounts reads the core-owned
`castalia.wallet-identities.v1` section. It contains public Matrix, Nostr,
GitHub and X descriptors. Matrix/Nostr use public identifiers and server URLs;
GitHub/X use stable numeric provider IDs, with human-readable labels separate.
There are no provider tokens, passwords, private Nostr keys, active Matrix
sessions, ownership-proof claims or rewards workflows in this section.
Tailscale remains application/network state.

## Backup contract

Records persist through the encrypted Wallet snapshot's existing atomic
candidate/commit/confirm transaction. New Castaway exports containing this
section use `castalia.castaway.v2` / `castalia.castaway-contents.v2`; files without
it remain v1. Both readers are supported and envelope/content versions must
match. Recovery-key files and key derivation are unchanged. Never strip identity
records to make a v2 file open in older software: older readers must fail closed.
Save a new Castaway backup after editing; existing files are never rewritten.

The native SDK also reads the core's existing public chain-account descriptors.
They are recovered from the same signing identity and shown for address access.
No transaction signing, new key derivation scheme or funding workflow is added.

## Explicit legacy migration

Choose Review existing records for Wallet. The preview copies only saved
Matrix/Nostr descriptors associated with the current Wallet, preserving UUIDs
and exact stored fields. The proposed full section is reviewed before Confirm
and save. Original application registry files and all Tailscale records remain
unchanged; no automatic import, deletion or synchronization is performed.

Identical records are idempotent. A changed record with the same ID, or the same
provider+identifier under another ID, stops with a conflict instead of overwriting
or guessing by display name. The original source files remain available after a
failure. The same conflict rules apply to Castaway imports. Importing a v1 file
preserves newer portable identities already present in the Wallet.

Edits and removals also require preview and confirmation. They do not revoke
provider access, establish account control, grant service authority or restore
sessions. Lock/cancellation invalidates pending consent; stale revisions reject
without overwriting a concurrent update. An uncertain confirmation is never
silently repeated.

## Verification

- Shared producer fixture is decoded and re-encoded with the exact closed shape.
- DTO/migration tests cover bounds, canonical IDs, forbidden fields, duplicate
  subjects, numeric provider IDs, URL validation, cancellation and idempotence.
- Native C ABI integration tests create a disposable Wallet, migrate synthetic
  Matrix metadata, prove no write before confirmation and unchanged original
  Matrix/Tailscale files, then check that identity plaintext is absent from SQLite.
- Actual encrypted v2 export + recovery + restore round-trips the exact records
  and derived addresses. An older v1 import preserves the newer records.
- Full native suites pass on both repositories; shared UI and DTO source parity
  is checked before packaging. Private test screenshots/logs are not public
  release assets. Personal Wallet migration remains a separate user action.

The broader proposed connected-accounts standard, general delegation, rewards,
provider authentication and signer-process isolation are not implemented by this
change.

## Legacy application records

Application settings expose original Matrix/Nostr records as read-only history.
There is no application Add/Edit/Remove path for those providers. Open Wallet
identities to review copying existing records; the original files remain intact,
and only the encrypted core is edited afterward. New Matrix/Nostr/GitHub/X records
are created only through Wallet identities. Tailscale remains editable application
configuration and is excluded from portable identity migration and backups.
Application save adapters reject legacy creation, replacement and deletion, even
if an old form is retained. Tailscale edits retain compare-and-swap validation.
