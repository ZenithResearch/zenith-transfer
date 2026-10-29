# Native holder sessions

The native consumer is qualified against Wallet Core `72ed5cd` and its additive
opaque custody ABI. Transfer and iOS use the same typed challenge, native review,
finite credential and session lifecycle. Existing v1/v2 grants, encrypted Wallets,
backups, owner inbox and Configure grant behavior remain unchanged.

## Human approval and application access

MCP opens a native signer with proposed permissions and a duration. The human
unlocks Wallet, selects the offered permissions, adjusts duration within the
provider/parent limits, and approves the exact challenge. Each scope or expiry
edit creates a fresh request, temporary key and challenge. No MCP tool approves,
signs, selects configuration/provider files, changes the native source or renews.

Transfer Settings → Session requests explicitly selects **Owner approval**
(the existing default) or **Saved reusable grant** for new requests. They share
one canonical service. Missing grants, missing provider registration, unmatched
services and denials never switch approval source; a new saved-grant request
fails closed before the owner provider is called.
The member signer links to this setting. Old requests keep their original source.

The distinct `zenith.session-access-result.v2` unsigned MCP result allows a null
review digest and session public key while the human is unlocking/preparing.
It never invents a key. An issued result has a verified review digest, public
session key, fixed expiry and opaque client-bound credential handle. The old
owner flow keeps its v1 result. A running MCP process must reload the updated
packaged script to consume the new result; changing its configured path alone
does not restart it.

## Custody and transport

The reusable parent and long-term key stay in Wallet. Transfer uses a separate
pinned `castalia-holder-session-agent` process. iOS uses a separate opaque native
Core custody handle in the application process; this is an API/key-ownership
boundary, not an additional OS process-isolation claim. Neither path exports
private key material or accepts key import, arbitrary signing or onward delegation.

Transfer member management uses the explicitly configured local broker, with
`app://zenith-transfer` context. Its separate protected descriptor is
`SessionReviews/holder-session-provider.json`, schema
`zenith.holder-session-provider-registration.v1`. It pins provider/context,
interpreter/script/profile/source bytes and agent binary/profile; its presence
does not override the human's selected approval source. Existing `provider.json`
remains the owner-bootstrap registration. Registration files are excluded from
the old request journal reader.

iOS uses its saved HTTPS connection and its existing LAN/Tailscale transport.
Session capability metadata must match the saved issuer/key and canonical service,
fixed protocol versions, bounded lifetime and exact route prefix. Session calls
use `Origin: app://zenith-ios`. Access points affect transport, not issuer identity.
The optional advertised `holder_grants.v2_endpoint` enables an explicit fresh
ordinary enrollment and human review/save of a v2 parent, without changing the
operator-approved assignment. Existing v1 paths and original uncertain issuance
requests retain their original endpoint and signed bytes.

## Lifetime and recovery

After issuance, reads and status checks use fresh temporary-key proofs while the
root Wallet may be locked. Recovery checks only the original result with the
original key; it verifies the byte-exact credential and unchanged expiry and never
submits a second approval. Every receiver call checks current parent policy,
revocation, scope, replay and hard expiry. There is no sliding lifetime, background
renewal or automatic root-signing fallback on a denied/expired session.

Temporary keys are memory-only and end on app/helper/process loss, explicit close,
expiry or detected revocation. Root-free public challenge/dispatch audit records
are application data, not Wallet backup or recoverable custody. Separate request
namespaces retain old audit history without exhausting the active request's limit.
A restored record cannot resume a session after restart. Reopening the iOS session
review shows an existing active session rather than asking for another approval.
Account changes and explicit removal of app read access close retained sessions.

## Qualification

Tests use random synthetic Wallets and disposable issuers/graphs. They cover
actual Core/helper and portable Core custody, real HTTPS with an exact fixture
certificate pin and hostname validation, scope/expiry edits with fresh key/request,
root-locked repeated reads, original lost-result recovery, replay, fixed expiry,
revocation, client close, and no repeated acceptance. Existing owner native
controller, inbox, Configure grant and uncertain journal regressions also run.
Installed production signing and personal Wallet approvals stay human-owned.
