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
