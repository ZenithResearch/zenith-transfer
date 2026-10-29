# Native holder sessions

Disabled foundation candidate. `HolderSessionIntegration.qualified` is false. No new
provider is registered or advertised. The source dependency and local Core
artifact now use `6d8bf278`; the installed app, original owner-bootstrap MCP
flow and existing grants remain unchanged.

## Boundaries

Wallet Core retains the reusable v2 parent grant and long-term holder key.
`WalletSession` has additive typed parent-reference, private preparation, review
and approval APIs. `WalletRepository` checks its lifecycle ticket around these
operations and rejects them before probing an unqualified installed Core.

Transfer owns a separate `castalia-holder-session-agent` process and its
temporary key. Its launch paths/profile hashes come from trusted application
configuration, never MCP arguments. The closed native protocol has no generic
sign operation, key import/export or owner command. Process loss is terminal;
the adapter never restarts under an existing session handle.

The private issuer adapter owns receiver routing. It receives Core's private
prepare/authorization payloads, and the helper's finite presentations/status
proofs. It owns no temporary private key. The canonical service/pin and trusted
caller origin/audience remain distinct from LAN, loopback or Tailscale routes.
The receiver must check current parent authority, scope, policy and replay state
on each call. An issuer signature alone does not prove current authorization.

`HolderSessionFlow` scopes one request to one authenticated local client. The
native UI must explicitly prepare and approve the exact reviewed digest/expiry.
It writes a root-free CAS/fsync dispatch record before sending authorization.
A lost exchange result is recovered with the original temporary key; it cannot
silently sign again, issue again or extend expiry. Calls and status after
issuance do not consult the root Wallet. Closing destroys local custody without
claiming server-side revocation.

## Public versus private data

`HolderSessionPrivatePayload` has no public bytes accessor, Codable conformance
or reflective/debug contents. Only an in-module trusted issuer adapter can use
it. Neither it nor consent tokens enter application journals or model results.
The separate journal stores public challenge bytes and correlation/state only;
it is application audit data, not a Wallet backup or recoverable key store.

The app/MCP layer may expose only an opaque client-bound handle, fixed expiry,
public review/status and business results. It must not return reusable grants,
finite tokens, proofs, signatures, raw issuer payloads or helper handles.

The new contract uses RFC 8785 UTF-16 key ordering. Its encoder is separate from
the existing owner protocol's code-point ordering. This consumer accepts the
contract's bounded safe integer JSON subset and rejects floating-point input.

## Verification and remaining gates

The signed synthetic fixture is byte-pinned from canonical Wallet Core
`6d8bf278bb17586ba535d19fb8fc2cd1fb5f399a`; provenance is recorded beside the
fixture. Tests verify actual issuer/session signatures, exact requested scope,
parent/Wallet/session installation bindings, UTF-16 ordering, fixed expiry and
late installation of an original result.

Flow tests use synthetic Wallet/issuer/custody ports plus a real durable journal
to exercise root-lock independence, original-result recovery, dispatch-fence
failure, client separation and close. These scheduling tests are not an actual
Core-to-HTTP exchange qualification. The opt-in native helper process test uses
real temporary key creation/close/loss with a disposable protected profile.

The real pinned Core/helper integration test creates a disposable Wallet and
v2 parent, checks private preparation, obtains typed Core approval with real
temporary-key possession, then installs a synthetic issuer token. After locking
the root Wallet, the real helper produces two fresh call proofs and a status
proof. This verifies native consumer interoperability, not the HTTP receiver.

The opt-in receiver integration tests run an actual disposable DevGraph issuer
and memory graph over the pinned private NDJSON process. A random Core Wallet
saves that issuer's synthetic v2 parent. The actual Core/helper flow recovers a
deliberately lost committed exchange result, reads only the allowed Task twice
after root locking, rejects an original-proof replay, rechecks original status
without changing expiry, and detects current parent revocation. A separate
short-lived exchange proves actual receiver and client rejection at fixed expiry.
No personal Wallet, installed profile or production graph is used.

Before enabling the feature: connect the native review UI/MCP client lifecycle,
qualify its request routing/expiry-edit/restart behavior and the eventual iOS
native custody port, and review the actual installed configuration. No public
capability or installed update is inferred from the source foundation tests.

```sh
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer \
swift test --scratch-path /path/to/stable/transfer-cache --filter HolderSessionTests
```

Set `HOLDER_SESSION_AGENT_TEST_BINARY` to an explicitly reviewed native helper
to run the opt-in process check. Core's private-file reader rejects symlink
ancestors and allow ACLs: use a protected physical path, including `/private/tmp`
rather than `/tmp`, for disposable profiles. No personal Wallet is used.

The actual receiver tests additionally require explicit paths through
`HOLDER_SESSION_DG_TEST_PYTHON`, `HOLDER_SESSION_DG_TEST_FIXTURE`,
`HOLDER_SESSION_DG_TEST_AUTHORITY` and `HOLDER_SESSION_DG_TEST_READ_AUTHORITY`.
They use the backend's test-only `tests/native_read/holder_session_fixture.py`,
with its exact source closure pinned at process launch. The fixture preprovisions
a synthetic read grant for the random test Wallet's public key. Its `REVOKE`
sentinel is test-only; neither production broker gains a revocation/debug tool.
