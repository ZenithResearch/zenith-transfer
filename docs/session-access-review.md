# Session access review adapter (candidate)

This is an unsigned, simulated application interface. It is not a credential,
signer-consent protocol or provider authorization evaluator. No production route,
Wallet flow, installed application, pending request or existing grant is changed.
There is no native popup, custody helper, durable session broker or MCP tool
registered by this slice.

## Producer pin

Canonical producer: `ZenithResearch/devgraph`, commit
`9b2e76914d75e5848bdf9a303c756960daee3973`,
`docs/contracts/session-access-review/v1/fixtures.json`.
The byte-identical consumer copy is
`Tests/ZenithKitTests/Fixtures/session-access-review-v1.json`, SHA-256
`87aea530001e28d7d1bb69b1937c86f800fb996ecccd7e707318355ed10f8262`.
Synthetic identities and addresses are examples, not installed trust or discovery.

## Consumer behavior

`SessionAccessReview` retains the entire canonical manifest and its digest.
Trusted provider and holder inputs must come from reviewed local configuration
and authenticated custody IPC, independently of the proposed request. Provider
policy binding is distinct from its profile digest. Routes do not enter the
authority manifest. The digest checks snapshot coherence; it is not a signature.

Permissions reuse the existing holder permission display decoder. Scope,
hierarchy, original constraints and paired effect authorization must still be
verified by native secS/Core; this adapter adds no selector evaluator.
The bounded JSON reader has an explicit opt-in for signed integer values inside
generic permission constraints. Existing owner/setup readers retain their
nonnegative default. Session timestamps, versions and limits remain nonnegative.

Expiry editing requires a new provider response, revision, challenge and digest.
Other request bindings cannot change silently. The review deadline may equal a
short credential expiry, and is invalid at that deadline. Issued results must
match the exact reviewed expiry and holder/service/request/digest. Undated
credentials, extra result fields and handles in non-issued results are rejected.

`SessionAccessReviewFlow` is only an in-memory preview state machine. After
dispatch it forbids expiry edits, resubmission and regressions to editable state.
An uncertain result reconciles the original binding. Repeated issued results
cannot substitute another credential handle. Closing a window does not produce
an issuer-confirmed cancellation, revocation or outcome.

Capabilities default absent features to false; unknown versions fail closed.
The example read-qualified capability is simulated and keeps write issuance off.
The fixture's one-hour default is a proposal within a provider ceiling, separate
from the Wallet inactivity timer and review challenge deadline.

## Remaining integration

The backend owns session-key custody, native issuance/execution and revocation.
Transfer owns the native review window and thin MCP/local IPC adapter. A future
broker must authenticate its callers, journal the immutable binding before
dispatch, enforce capability and native-verification gates, and recover the
original result across restarts. It must expose request-review/get-result, not an
agent-callable approve/sign endpoint. Live writes remain unavailable until the
entire issuer/holder/receiver chain is qualified. Production authority and app
replacement require their separate review.
