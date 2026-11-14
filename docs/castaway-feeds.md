# Castaway feed reader source stage

The shared native source recognizes the proposed matching
`castalia.castaway.v3` / `castalia.castaway-contents.v3` envelopes for transport,
catalog labels and import review. The section name is `feeds`, containing
`castalia.feeds-section.v1` data. This is a reader and presentation stage, not a
released ontology or a qualified native runtime rollout.

## Validation and persistence boundary

Swift transport admission retains the original encrypted bytes and the 1 MiB
whole-file limit, including USB reads and QR framing. It checks the public
envelope only. Rust remains authoritative for raw duplicate keys, inner/outer
version agreement, ownership, the exact section schema, all limits and endpoint
syntax. No Swift decoder or view grants permission to fetch a feed.

The portable profile, feed section and restore preview remain Decodable-only.
They are display projections, never inputs to a persistence encoder. The
repository passes the original file string to Rust and commits the exact opaque
candidate snapshot through the existing revision compare-and-swap and
confirmation flow. No persistence or custody code changes in this stage.

The v1 and v2 paths remain readable. v2 requires walletIdentities in Rust; v3
requires feeds and permits walletIdentities. The review shows saved account
identities for both v2 and v3. A legacy file cannot acquire incoming-feed
provenance from the merged result.

## Inert review

The preview's imported_feed_subscriptions and imported_feed_collections counters
describe the incoming file; the feeds under the preview's sections describe the
full result after additive preservation. The review labels that result "after
import" and presents incoming counts separately. An absent count is not replaced
by the merged collection or subscription count.

Older imports explicitly preserve existing feeds. Empty input does not imply
deletion. Duplicate IDs with differing values must fail in Rust before review.
Subscription URLs are selectable Text, without links, URL opening or fetching.
Saved enabled and disclosure preferences are displayed as metadata. There is no
provider login, subscription activation, cache import or new authority.

Original labels and array order are retained. Empty or whitespace-only titles
use display fallbacks without changing the stored title.

## Qualified development artifacts — 2026-11-14

Both Dependencies.json files now pin the canonical public Wallet source
d688a3859a3fdc602c545790fd7065f9725435de. The documented builders produced
macOS and all three iOS-package slices; source digests and each library hash
match their manifests, and both macOS slices are identical. These are local
verified development artifacts, not a packaged or installed application.

Four actual native encrypted integration tests pass. They cover independent
synthetic v3 files, recovery attachment, incoming counts, no pre-confirm write,
cancellation, older/empty imports, identity edits, conflicts, invalid authenticated
inputs, reopening, stale two-repository CAS and an actual SQLite failed write.
The failure test proves both the attempted snapshot and trigger side effect roll
back, the candidate is not installed, and a fresh retry can succeed. Production
v3 export still refuses with feed_writer_not_qualified and explicit user text.

The complete Transfer SwiftPM suite passed: 416 tests, 20 opt-in/live-environment
skips, zero failures. This is macOS domain/Core qualification; shared modified
files match across the two repositories. Existing unrelated parity drift remains
visible. SwiftPM initially copied a new static archive without relinking its
cached test executable; targeted invalidation/relink verified the actual new
Core before the passing runs.

No app was packaged, installed or launched, and no simulator/physical device,
personal Wallet, key custody, grant or authority was changed. iOS platform/UI,
minimum-runtime and installed/physical-device acceptance remain separate gates.
Keep original import files until the coordinated writer/export rollout qualifies.

## Source tests

PortableFeedReviewTests exercises v1/v2/v3 public-envelope admission and matching
version pairs, unknown-version refusal, owner-field syntax, the exact raw-byte
1 MiB file boundary, QR framing, the byte-identical shared section fixture,
Decodable-only projections, exact Unicode/order preservation, incoming versus
preserved counts, empty input, and v3 with optional saved identities.

The existing review, identity, recovery and repository suites cover the legacy
presentation and opaque candidate/commit behavior. The shared parity checker
includes the new source test and fixture. Pre-existing cross-repository
differences are reported rather than normalized by this work.
