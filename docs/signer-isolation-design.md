# Signer isolation and application credentials

Status: assessed design; not implemented. No custody migration, issuer policy,
credential grant, signing permission, or installed application changed.

## Intended guarantee

A compromised main application must not be able to extract the Wallet root key,
unlock password, decrypted custody snapshot or backup secret, or exercise owner
administration merely because it has routine Work access. It may still abuse the
permissions of a credential issued to that application; the server must enforce
its exact ceiling and revocation.

Current code calls the native Rust C ABI from `ZenithKit.NativeCore` inside the
main app. `WalletRepository` serializes access and coordinates durable encrypted
snapshots, but does not create a process security boundary. iOS biometric unlock
currently releases the local unlock credential to the main app. File encryption,
Rust ownership, a Swift actor and module boundaries are useful protections, not
isolation from compromised code in that process.

## Components and ownership

| Component | Owns | Must not receive |
| --- | --- | --- |
| Castalia signer | Root identity, unlocked custody, trusted signing policy, backup import/export and trusted approval UI | Work caches, arbitrary app configuration, unrestricted network access |
| Zenith application | Work/network UI, connections, caches, app credential and its restricted holder key | Root key, unlock/backup passwords, decrypted signer database |
| DevGraph/secS verifier | Authoritative service identity, issuer/grant rules, holder binding, resource scope and revocation | Wallet private keys |

The Wallet UI becomes a client of the signer. Its displayed data still needs a
specified Wallet backup/restore path. Runtime app credentials, device key state,
network enrollment and service caches remain application data unless explicitly
included in an appropriate backup contract. Moving the signer must preserve
recovery identity and existing encrypted files; it must not silently clone
installation IDs or restore stale authorization/replay state.

## Two compatible delivery stages

### 1. Isolate custody while preserving existing proofs

Prototype the signer on macOS using a separately sandboxed XPC service with a
stable signed identity, authenticated client policy, signer-private storage and
Keychain access, and hardened release signing. A subprocess with the same broad
rights or a copied library does not satisfy this stage. Transfer must no longer
link an independently usable custody engine or possess the Wallet password.

Keep the existing Wallet-bound credential and proof semantics. Transfer forwards
structured proof requests; the signer checks the service identity, holder,
operation, scope, nonce, expiry and reviewed policy before signing. It can apply
an explicitly approved routine-use policy while unlocked; it cannot expose an
unrestricted `sign(bytes)` endpoint. Key custody and every approval are owned by
the signer, including the UI that collects unlock and backup passwords.

This stage prevents direct key extraction from the main app. It does not let
Wallet-bound requests work with a locked signer, and does not make an authorized
but malicious app harmless.

### 2. Issue restricted application-held authority

Create an application/installation holder key distinct from the Wallet root.
An explicit owner decision authorizes a credential for that holder and canonical
service, with selected operations/resources, revocation and user-selected expiry
where applicable. Scope must not depend on LAN/Tailnet/HTTPS access-point URLs.
Routine calls use the app holder key. Root ownership, credential issuance,
revocation administration and recovery stay in the signer.

Current native read/write contracts do not establish this app-holder relationship
merely by copying a Wallet credential. Add a versioned producer/verifier/client
contract and explicit holder-key binding; preserve all current decoders, grants
and historical signed bytes. Do not treat this as existing onward delegation,
enable general redelegation, or silently issue a new owner/admin credential.

An app holder credential can remain valid while the root signer is locked, if the
server's grant permits it. Unlock duration and credential validity are separate
policies. Application compromise exposes that app's allowed authority until it is
revoked or expires; it must not expose broader Wallet authority.

## Apple platform assessment

macOS provides XPC service processes and per-target sandbox entitlements. Actual
protection still depends on signed peer authentication, distinct storage rights,
restricted Keychain access and independent consent enforcement; naming a service
"signer" is not proof of isolation. The current ad-hoc development app and broad
local administrative helpers require an entitlement/storage review before making
this guarantee for the deployed product.

The currently supported iPhone/iPad baseline is iOS 18.1. The installed Xcode SDK
marks ExtensionFoundation.AppExtensionProcess as macOS 13 / iOS 26 or later.
Therefore the new generic in-bundle extension-process route is not an equivalent
solution on these devices. A separately sandboxed Castalia signer application
with explicit foreground handoff, an external/hardware signer, or a newer-OS
extension design needs separate validation. Legacy app extension types are not
a pretext for an arbitrary persistent signing daemon. Until an actual route is
proven, label the iOS core as in-process custody.

Apple's documented Secure Enclave signing API uses P-256. The existing recoverable
Castalia identity uses Ed25519 plus other software key material. We must not claim
that moving existing identity keys to Secure Enclave is a transparent migration.
A device P-256 key could protect wrapping or holder operations under a new reviewed
contract, but software roots decrypted into a signer are not themselves
non-exportable enclave keys.

## Pass/fail gates before migrating a real Wallet

- Main app executable no longer contains/loads a usable root custody engine.
- Unlock and backup passwords never cross into the main app, IPC results, URLs,
  pasteboard, logs or crash diagnostics; root custody never enters shared storage.
- An unrelated or incorrectly signed process cannot open the signer session.
- Authorized clients cannot submit arbitrary bytes, replace reviewed requests,
  widen scopes, replay approval tokens, or use them after lock/disconnection.
- The approval UI belongs to the trusted signer; a main-app-only confirmation is
  not sufficient to authorize a new root operation.
- Signer shutdown/crash/lock invalidates sessions and pending approvals; recovery
  uses the original idempotency semantics and never blindly repeats a grant.
- Existing recovery/data files round-trip to the same identity. Failed migrations
  preserve the original encrypted files and never create two active custodians.
- App-key credentials pass scope, canonical-service, expiry/revocation, holder
  substitution and alternate-access-point tests in the actual receiver.
- Prove the expected compromised-client limit using a synthetic Wallet before
  handling real keys. Isolation from the main app is not protection from root,
  a compromised OS, or a compromised signer implementation.

## Sources

- Apple XPC: https://developer.apple.com/documentation/xpc
- Per-target App Sandbox: https://developer.apple.com/library/archive/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/EnablingAppSandbox.html
- App extensions: https://developer.apple.com/documentation/extensionfoundation/adding-support-for-app-extensions-to-your-app
- Secure Enclave: https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave
- Local evidence: NativeCore/WalletRepository, iOS BiometricKeychain, current
  public Castalia recovery_session and read_access implementations; installed
  ExtensionFoundation Swift interface availability declarations.
