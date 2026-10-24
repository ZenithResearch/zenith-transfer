# Secondary endpoint administration through local RPC

Status: development build 31 is installed. Read-only inspection passed through
both the original v1 service and the matching secondary-endpoint v3 service.
Real Wallet inbox consent and grant approval remain user actions; no owner action
or grant is created by this update.

Architecture correction: [canonical service credentials](canonical-service-credentials-spec.md)
defines the target service-scoped authority across all access points. This document
describes the installed legacy URL-bound adapter, whose checks must remain intact
until the shared versioned migration is implemented.

## Consumer expectation

A locally running DevGraph can have a registered HTTPS interface whose portable
profile is LAN, private Tailnet, or public HTTPS. That reachability hint is not
the transport used by its owner on the host. Transfer should use protected local
secS RPC for that exact interface when the matching local binding is installed.
Never change a Tailnet profile to `local` or substitute the loopback receiver.

The existing RPC v1 remains loopback-only; v2 retains its private-IPv4 receiver restriction. The prepared v3 consumer expects:

- Current owner-private `.zenith/services/v1/<instance-id>.json`, with the exact
  resource UUID, canonical derived interface instance ID, origin and full profile.
- Current owner-private `.zenith/rpc/v1/<instance-id>.json`, closed
  `secs.local-admin-config.v3` shape, exact resource/instance/receiver/issuer/profile
  digest, native binary hash and source manifest containing the fixed handler.
- Fixed host executable `secs-local-admin-rpc-v3`; no executable path supplied by
  a remote profile or caller. RPC request/response v1 correlation and the existing
  closed inspect/challenge/execute operations remain unchanged.
- Recheck the entire protected configuration and service registration before each
  command, then verify the fixed executable hash. The native producer independently
  rechecks runtime, source/interpreter hashes, current owner proof and policy.
- A locally registered service with an absent/changed RPC configuration fails
  closed; Transfer does not silently switch its owner operation to HTTP.

The full profile still passes normal HTTPS/pin validation. Network reachability
does not prove owner admission. Discovery metadata alone does not establish owner
registration: the independently validated native inspection must confirm it.
The public/member listener keeps operator HTTP routes closed.

## Producer integration gate

The retained Rust v2 prototype accepts private IPv4 receivers only and rejects
Tailnet DNS origins. Its existing tests do **not** qualify v3. The matching native
v3 source now implements the same closed configuration shape and unchanged wire
envelopes. Before claiming installed compatibility, qualify the fixed binary,
protected configuration and current service registration with a read-only native
inspection from this client. Do not treat packaging as installed qualification.

The matching native implementation must preserve exact parent-owner/endpoint
binding and profile checks for the selected secondary partition. No broad hostname
trust, inherited receiver, rewritten challenge, or automatic cross-origin grant is
introduced by local transport selection. Existing local v1 remains available.

## Synthetic test coverage

- v1 rejects LAN/Tailnet/public profiles; historical loopback semantics remain.
- v2 keeps canonical private-IPv4 semantics and rejects Tailnet DNS/public origins.
- v3 retains exact LAN/Tailnet/public profile values and derived instance IDs.
- Wrong graph, instance, receiver, issuer and profile digest are rejected.
- Empty, traversal-bearing and malformed source manifests are rejected.
- Protected local discovery, config permissions, mutation after discovery and
  missing-config behavior are checked without starting a native process.
- Original request/response correlation tests remain unchanged.

Installed composition verifies the protected binding and pinned native adapter;
the native inspection confirms current owner registration and credential
administration. Still required: real installed signing/inbox and credential
receipt qualification. Synthetic regression tests cover original-action journal
recovery; they do not establish cross-process journal race safety. No real
deployment address belongs in source or these fixtures.

Direct Xcode type checks pass for the library, native app and RPC tests;
changed-file syntax checks also pass. The original SwiftPM run stalled while
starting its generated package manifest. Retrying unchanged sources with compiler
temporary files under `/private/tmp` resolved that harness problem: six RPC tests,
one opt-in installed check skipped, zero failures. This is consumer component
evidence, not matched native producer or installed endpoint qualification.

The full native regression suite also passed with that same temporary-directory
setting: **179 tests, six opt-in checks skipped, zero failures**. A separate
explicit installed check also passed read-only inspection through the original
v1 service and the matched v3 installation with this client. Neither check signs
an owner action. App installation preserves the existing approval journals.

## Hierarchical preparation fix

Build 32 gives RPC request bodies an explicit maximum JSON depth of 16, matching
the native canonical body budget. The shared setup parser's default depth of eight
rejected valid path-scoped review challenges and proof envelopes before dispatch.
Byte, key, array and duplicate-key checks remain in place. Regression coverage
accepts both hierarchical envelope forms and rejects excessive depth and size.
Known server rejection codes and local binding failures now have specific messages;
arbitrary server response text is not copied into the credential editor.
