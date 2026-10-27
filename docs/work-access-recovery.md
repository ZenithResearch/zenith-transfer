# Work access recovery and membership disclosure

Work access uses the selected HTTPS origin and its approved issuer pin. Every
read challenge, access request and credential operation must reach the same
canonical service. A longer-prefix reverse-proxy mapping can override a root
mapping; check every credential route when publishing or updating an endpoint.

The public `/monitor/wallet-access/v1` configuration includes an additive
`membership_requirement` field: `optional` or `required`. Native clients show
that choice before consent. When explicitly optional, they omit community
membership from access-request, temporary-read enrollment and reusable-grant
issuance envelopes. The Wallet's membership stays stored and active. Missing
metadata preserves the previous behavior; an unknown value fails closed.
Actual read-call holder signatures are never omitted. Optional receivers still
reject invalid membership proofs if a client supplies one.

A retained request ID is not proof that a request was submitted. After an
uncertain outcome, check that original request. If status is unknown, the
explicit resend action uses the same ID. Operator approval for a different
Wallet or installation does not authorize this device.

Operator consent envelopes have a 128 KiB maximum; member request/status
consent remains limited to 16 KiB. Enclosing local RPC and operator HTTP bodies
have a 512 KiB maximum. Only matched Wallet Core builds accept the larger
operator envelope. Small existing envelopes, signatures, saved grants and
request IDs retain their previous format. Old clients reject larger envelopes
rather than weakening signature or scope checks.

## Credential requests and read enrollment

A credential request requires the Wallet's identity/installation proof and the
service's stated eligibility rules. It does not require an existing Work read
grant. Read enrollment is a separate operation that checks an active assignment.
A request, a prepared approval and an operator review are not read grants.

The iOS request screen keeps read enrollment hidden while choosing or signing a
request. After an active read result it offers **Review approved read access**;
write-only/partially-active write assignments cannot enable that action. The
collapsed **Already have an approved read grant?** check remains available for
users with an existing grant, and a missing grant produces guidance to request
credentials rather than claiming the credential request failed. Existing readers
can also request different credentials without first deleting read access.

Request/status HTTP 401/403 responses use a request-specific identity/policy
rejection message, including rejection of request metadata. They never imply
that a Work read grant is a prerequisite. An uncertain/rejected submission keeps
its original request ID for status recovery; no new request is sent implicitly.
Shared native tests cover real Wallet proof generation with read enrollment
denied, request submission/status, denied preparation/submission and original-ID
recovery. No issuer, scope, signature, membership or revocation check is relaxed.
