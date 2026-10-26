# Recovery and Castaway import review

A recovery file (or older recovery key) restores the Wallet signing identity and
derived blockchain accounts. Saved account identities, profile fields, membership
proofs and saved public account descriptors are reviewed as **Castaway data**.
An iOS import attaching both files reviews both groups before its single existing
confirmation. Transfer keeps its separate recovery and data import paths.

`WalletImportReview` binds the operation context to the prepared core token. The
context is captured from the selected validated envelope, never inferred from a
synthesized identity section or count. The core preview and commit transaction
are unchanged. Changing files, cancelling, leaving or locking invalidates review.

The data review describes the resulting saved data after import. A v1 file has no
saved account identities section; existing records are preserved. A v2 review
shows the resulting identity records and the number supplied by the file, including
zero. Conflicts still fail without overwriting accounts. Replacement warnings stay
visible. `PortableSections.chainAccounts` decodes an existing optional core field
so saved descriptors are not confused with all derived recovery addresses.

There is no migration, schema change, new signing authority or core dependency
update. Existing encrypted local records, recovery v1, Castaway v1/v2 and identity
v1 remain compatible. Saved identities stay available in the Wallet editor and
Castaway backups. Importing never activates membership or service access.

Validation on 2026-10-26:

- Shared presentation tests cover recovery, combined, data-only, v1 and empty v2.
- Real-core integration verifies derived addresses, identity round trips, v1
  preservation, wrong passwords/owners, cancellation, lock and stale previews.
- Full native suites pass: iOS 241 tests (6 existing skips), Transfer 282 tests
  (8 existing skips), zero failures. Shared native parity: 51 files.
- The production iOS Simulator app builds. The isolated synthetic QA app passes
  four interaction/layout tests on both iPhone 16 and iPad Air 11 M3, including
  disclosure labels, large text and a reachable single confirmation. An additional
  iPad check confirms the last of four saved identities is visibly reachable.
- The same shared component builds and was inspected in the macOS QA host.
- Browser recovery paths were audited; they do not show the misleading synthesized
  empty identity row and need no source changes for this correction.

The QA host does not exercise real passwords or commit data. Its confirmation is
inert; transaction behavior is covered by package tests. This source qualification
is separate from installing updated apps. Preview integration must retain any
separately reviewed Arena work. Do not replace an Arena preview with main-only
apps or infer approval to merge unrelated Arena PRs.
