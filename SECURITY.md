# Security and qualification

This is development software, not a security certification. Never commit Wallets,
recovery files, passwords, native credentials, node keys or machine configuration.
Report security issues privately to the repository maintainers before publishing
secret-bearing evidence.

Identity account records contain public metadata only. They are not signed
ownership assertions, and the unlocked-Wallet edit guard is an application guard,
not protection against another process running as the same OS user.
Do not put provider secrets in identity account fields. Tailscale API tokens have
a separate explicit entry under Settings → Network. Saved tokens use this Mac’s
non-synchronizing login Keychain with the default application ACL; they do not
enter Wallet/recovery/connection-file exports. Ad-hoc development builds may
require renewed Keychain access approval after updates. This is not a provisioned
signer access group or a claim of protection against a compromised OS account.
No plaintext fallback is used when Keychain access fails.

Existing authorization is enforced independently by the selected DevGraph and
native secS/Wallet components. Public network exposure is not qualified by this
UI release. Tailscale enrollment and API key creation each require a separate
explicit action. Listing saved API-token metadata never reads a secret or sends
a request. The generator reads the selected token only after final confirmation
and sends it only to the fixed official API over certificate-validating HTTPS.
Saving does not validate provider-side permissions/expiry; removing locally does
not revoke at Tailscale. Generation does not change Serve/Funnel exposure.

Known inherited hardening work remains: atomic cross-window operator journal
updates, absolute local-RPC subprocess/I/O deadlines, and receiver challenge/result
and denial-audit capacity handling. These are not resolved by the identity editor.
Use a separately reviewed service boundary before publishing a graph publicly.
