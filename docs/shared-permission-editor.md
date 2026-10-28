# Shared permission configuration

Transfer uses `TransferPermissionEditor` for local credential recipes and individual grant configuration. The component uses canonical action IDs and the same labels for Read, Arena metadata and named writes. Edit details is displayed separately from the other write actions, whose selected count stays visible when collapsed. Current server admission filters the individual action list; existing local recipe versions retain their supported Work-action subset.

An individual request with no permission preferences opens this editor alongside scope and duration. Quick Read/Edit by hierarchy remains available from an empty draft, including the bounded multi-rule union introduced in build57. Entering that shortcut does not discard an existing configured selection.

## Requested fields

`NativeRequestedConfiguration` reads the existing `devgraph.access-intent.v2` preference. It matches the catalog digest and preset ID/version exactly. Requested preset actions are displayed read-only, with normal-contrast Requested/Not requested labels; a disabled form is not used as the readable summary. Requested paths remain the only available path allocations. Unspecified actions, object kinds, scope and validity remain administrator choices as applicable.

A missing or empty path array is unspecified; it never selects all resources. The actual `PresetIntent` producer permits explicit empty `read_grants`/`write_grants` defaults; the reader accepts these only when empty. Unknown fields, nonempty supplemental grants, stale/missing presets, missing catalog branches or unrepresentable requested actions stop configuration with a revised-request message. The original request is retained.

Multiple rules are allowed. For a preset-only request each rule retains the same pinned actions, while scopes can differ. For path-only requests, actions may differ across requested branches, but the aggregate path union must preserve every requested path and contain no other path. Both draft constraints and compiled path coverage are checked before preparing a Wallet action. No missing field is treated as authority, and receiver admission still decides whether the exact selection is permitted.

The final reviewed selection is read-only and has Accept request / decline actions. The current v2 preference does not encode a complete grant including validity and all resource selectors; it must not be labeled a fully specified credential merely because it references a preset. Older v1 non-null explicit grant intents are not converted by this adapter: they are preserved, displayed as unsupported for configuration and require a revised request. This is a known compatibility limit, not full Accept/Deny coverage for every historical explicit intent.

These are presentation and selection checks. Grant schemas, request schemas, signer behavior, Wallet Core, secS, authority, journals and receiver activation remain unchanged. The build56 schema-journal compatibility fix and build57 exact hierarchy-union compiler are retained.

## Preset persistence: concrete follow-up review

Existing `zenith.credential-preset.v1/v2` records store permission recipes, optional Arena-read intent and descriptive Seat references. They do not store Wallets, server identity, scope paths, per-action rules or validity. The shared view adapts their short Work action names to canonical IDs and back, rejecting unsupported actions instead of silently dropping them. Existing revisions and grants are not migrated or changed.

Saving the entire scoped individual configuration as a preset needs a separately versioned record and consumer migration. Before implementing it, review:

1. A new record version retaining v1/v2 readers, with ordered independent action/resource rules rather than a cross-product of action and scope unions.
2. Canonical service identity for any pinned resource paths, plus the behavior when paths disappear, move or belong to another server. Do not save an unqualified path and treat it as portable across arbitrary graphs.
3. Full canonical named action IDs, explicit object IDs versus hierarchy/all-permitted semantics, and any optional duration defaults. Omitted scope must remain unspecified, not unrestricted.
4. Producer and every local preset consumer, including the corresponding iOS/shared model, import/export behavior, preserved revisions and stale-write checks. Readers need explicit version support before writers can emit the new record.
5. Reviewable before/after compiler equivalence and round-trip tests. Saving a recipe never authorizes or modifies an existing grant.

No such record is written in this change. The applicable shared controls are implemented now; full scoped-preset persistence and complete historical explicit-intent conversion remain separate reviewed work.

## Verification

Synthetic tests cover recipe round-trips, unknown-action rejection, no-intent/empty/default-expanded preferences, exact catalog/version matching, read-only action constraints, independent multi-rule scopes, preservation of requested path unions through compilation, and model editing without any RPC or signing. Existing journal, hierarchy and Wallet tests remain part of the full regression suite. Optional render fixtures show the actual shared SwiftUI component with editable versus requested permissions; no real Wallet or request is used.
