# Native signer boundary v1

This is a source-level implementation of the shared boundary, not a completed
custody migration. The released Transfer and Zenith applications still use
their existing in-process Wallet repository. No new service grant, root copy,
launch agent, Keychain record or device installation is created by these files.

## Modules

`CastaliaSignerProtocol` has no Wallet core, storage, passwords or network client.
It defines closed, signed requests and responses, an application-holder session,
paired-client policy, durable consent transitions and a signer host coordinator.
Only signer-owned code calls approval; the exported exchange cannot approve.
Preparing or requesting a review never signs a root proof automatically.

`CastaliaSignerStorage` is signer-only. Its device-only, non-synchronizing
Keychain keys protect an AES-GCM journal in a private SQLite transaction. Saved
pairing changes invalidate pending reviews. Every transition uses a revision
compare-and-swap. A crash while signing produces an uncertain original operation;
it does not permit another signature. Approved results can be recovered exactly.
Production use requires qualified private app/container and Keychain entitlements.

`CastaliaSignerTransport` provides macOS XPC delivery with both-side code-signing
requirements: Apple anchor, exact Team and exact bundle identifier. Unsigned or
ad-hoc builds cannot satisfy the production peer requirement. This module does
not register a launch agent or present trusted approval UI by itself.

For the iOS 18 baseline, the protocol also provides X25519/HKDF-SHA256/AES-GCM
sealed foreground handoffs. Reviewed pairing pins both signing and agreement
keys. Inner signatures, original request digest, Wallet identity, expiry and
direction remain mandatory after decryption. Custom URL ownership is never an
authentication mechanism. URLs carry ciphertext, not passwords, custody or bare
proofs, accept only the named native callbacks, and refuse payloads above 16 KiB.
A larger-message transport is not silently substituted.

## Identity and compatibility

The authority binding uses issuer, canonical audience and the approved issuer key
descriptor. An access-point URL is not a new service identity. HTTP TLS/origin
verification remains an independent client responsibility. An issuer-key change
requires reviewed trust; it is not inferred from a different network route.

Existing Castalia recovery/data formats and graph/member/operator protocol bytes
are unchanged. The frozen Wallet Core pin is unchanged. No arbitrary core invoke
or `sign(bytes)` is exported. Unsupported maintenance opens signer-owned Wallet
UI; it is not an application-supplied JSON patch.

## Verification and remaining gates

| Claim | Evidence / gate |
| --- | --- |
| Bounded closed wire, escaped duplicate fields rejected | SignerProtocolTests |
| Changed Wallet/client/service/request/expiry cannot reuse consent | SignerProtocolTests; SignerHostCoordinatorTests |
| Client review RPC cannot approve or sign | SignerHostCoordinatorTests, synthetic root engine |
| Approved original result recovered once; cancellation/revocation enforced | SignerProtocolTests; SignerHostCoordinatorTests |
| Current pairing required at prepare and completion | Journal policy comparison and host tests |
| Handoff binds both peers, direction and signed inner bytes | SignerStorageAndHandoffTests |
| Persistent encrypted journal rejects wrong key, stale CAS, symlink, revision tampering | SignerStorageAndHandoffTests, temporary synthetic database |
| macOS XPC requirement refuses wildcard/injection/ad-hoc policy | SignerStorageAndHandoffTests; transport compile |
| Actual authenticated process exchange and signer-owned approval UI | Not qualified yet |
| Separate native signer applications and no custody engine in client executables | Not implemented yet |
| Real Wallet cutover, private storage/Keychain entitlements and recovery parity | Not activated; requires separate packaged qualification |
| Application-holder service credentials usable with root signer locked | Requires versioned receiver/issuer integration; not implied by this transport |

Full native suites pass with these modules: Transfer 223 tests (seven optional
skips), iOS shared package 210 tests (six optional skips), no failures. These
results do not establish the unfinished platform or custody guarantees above.
