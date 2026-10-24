# Reusable provider grants in native Wallets

Status: source integration and disposable native tests; not an installed release.
Both native apps pin the same public Wallet Core 0.4 revision in Dependencies.json.
The secS shared verifier is vendored with exact source hashes in that producer.
Existing keys, memberships, identities and legacy read access retain their formats.

A service supplies a provider-signed root for one Wallet and canonical service.
The native review displays its permissions, path scopes, duration and disabled
onward delegation. Save commits through Core's encrypted prepare/CAS transaction.
Only the same Wallet can derive finite equal or narrower credentials from it.
No private signing material leaves Core. A read request presents the holder-signed
credential and fresh exact-call proof; the server still checks current permission,
revocation and graph ancestry. Different access point URLs do not create authority.

Saved grants and their separate encrypted backup appear under Wallet in both apps.
Restore requires the same recovered Wallet, explicit review and conflict-free merge.
This backup contains no signing key. It does not install runtime issuer trust or
revive revoked access; a device-bound root still needs its original installation.
The application's Work data, network setup and request-recovery state are outside
this Wallet grant backup. The initial signed grant attempt is retained in memory
for explicit same-byte recovery; restart-durable attempt recovery is not yet wired.

The first DevGraph integration covers reads. Existing write credentials stay on
their prior path; this code does not activate onward delegation, a generic write
cutover or the planned isolated signer process. Old snapshots without saved grants
remain readable by the new Core. Older cores cannot read a newly populated grant
snapshot; retain prior encrypted snapshots and versioned rollback evidence.

Before release, qualify the app UI, exact native framework manifest, live provider
save and reuse through Tailscale, denial outside scope, revocation and original
request recovery. Install in place, retaining existing Wallets and settings.
