# Native isolated signer implementation

Scope: Zenith Transfer on macOS and Zenith on iPad/iPhone. Linux and the Chrome
extension are outside this change. Existing Wallet identities, encrypted files,
service grants and historical proof bytes must remain compatible.

## Delivery sequence

1. Reconcile and publish the completed native identity, account-boundary,
   inactivity and connection work without personal machine configuration.
2. Define one versioned, bounded signer request/response contract. Separate
   canonical service identity from access-point URLs; authenticate clients and
   bind consent to the full operation, challenge, nonce, holder and expiry.
3. Implement a macOS XPC signer adapter and a signer-owned approval host. Secrets
   and custody must not traverse the client API. Stable signing, sandbox/file
   entitlements and client authentication must establish a real process boundary.
4. Implement the supported iOS 18 signer-app handoff with a separate app container
   and signer-owned unlock/approval. Requests from URL handoff are untrusted;
   callbacks, one-use correlation and exact reviewed bytes must be bound.
5. Integrate the client boundary in both applications while keeping custody-only
   create/recovery/import/export UI inside the signer. Keep the old installation
   usable until an explicit migration is reviewed; never silently clone roots or
   installation-bound credentials, grants, approvals or replay state.
6. Add application-holder credentials only through an explicitly versioned
   producer/verifier contract. The signer authorizes owner decisions; DevGraph/
   secS issues and enforces credentials. General onward delegation stays off.
7. Prove all gates with disposable Wallets, qualify packaged apps and device
   handoffs, then present the exact real-Wallet cutover for review.

## Required evidence

- Rejected unknown clients, schemas, extra fields, oversized/duplicate-key input,
  stale/cancelled/replayed consent and changed service/holder/operation.
- No raw sign(bytes), root/seed/password, decrypted snapshot or unbounded generic
  core invoke in the client transport. Signer approval UI owns the decision.
- Same canonical request over authorized access points preserves service scope;
  endpoint authentication and approved presentation rules still apply.
- Original recovery/Castaway files restore the same identity; conflicts and
  interrupted migration preserve the original. No two active custodians are
  created automatically, and full database restore is not inferred from recovery.
- Main app cannot access signer-private keys/storage/memory or forge consent;
  missing stable signing or entitlements is reported as unqualified isolation.
- Existing native suite, transport contract tests, real platform process tests,
  synthetic approval/cancellation UI and signed device build checks pass.
- Publish source with neutral attribution, privacy/secret scans and exact pins;
  exclude real Wallet data, profiles, device records and machine configuration.

Status: implementation in progress. Current released clients retain in-process
custody. No isolated-signer security guarantee or production migration is claimed.
