# Security and qualification

This is development software, not a security certification. Never commit Wallets,
recovery files, passwords, native credentials, node keys or machine configuration.
Report security issues privately to the repository maintainers before publishing
secret-bearing evidence.

Identity account records contain public metadata only. They are not signed
ownership assertions, and the unlocked-Wallet edit guard is an application guard,
not protection against another process running as the same OS user.
No provider token or private-key entry is supported by this release.

Existing authorization is enforced independently by the selected DevGraph and
native secS/Wallet components. Public network exposure is not qualified by this
UI release. The Tailscale screen reads configuration and saves reviews only.

Known inherited hardening work remains: atomic cross-window operator journal
updates, absolute local-RPC subprocess/I/O deadlines, and receiver challenge/result
and denial-audit capacity handling. These are not resolved by the identity editor.
Use a separately reviewed service boundary before publishing a graph publicly.
