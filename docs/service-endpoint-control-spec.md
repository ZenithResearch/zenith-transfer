# Owner-controlled service endpoints in Transfer

Status: integration specification; no endpoint activation is implemented or
authorized by this document. Separate from the build 30 identity-account release.

Authority-model correction: [Provider and canonical-service credentials](canonical-service-credentials-spec.md)
supersedes the earlier per-origin grant partitioning. Access points belong to a
canonical service; they do not define separate credential audiences. Installed
legacy URL-bound protocols retain their existing semantics until a coordinated
versioned migration is implemented.

## User journeys

**Owner:** Resources & requests → select the exact DevGraph service →
Sharing & network → Endpoints. View all registered endpoints and their observed
state. Prepare a change, review the exact before/after configuration, approve the
new narrow service-change consent, then inspect readiness and the committed result.
Programmatic clients use the same service-control contract and validators.

**Public visitor:** open the published HTTPS URL in a browser → review/connect
Wallet → request a credential → wait for an operator decision → accept the issued
credential → access permitted work. Visitors do not register a service, import a
connection file or join a Tailnet for a public endpoint.

**Private visitor:** establish required LAN/Tailnet connectivity, then follow the
same HTTPS Wallet request/access journey. Network connectivity is not authority.

The public DevGraph endpoint is not currently configured. Current Transfer
Sharing & network exports are proposals only; they cannot activate any route.

## Shared contract prerequisites

DevGraph owns the canonical service-control wire schema, state and enforcement.
Transfer consumes its versioned native RPC contract and signed Wallet consent.
Do not invent an independent Transfer deployment API or execute arbitrary CLI
commands from a connection profile.

Before implementation, reconcile the endpoint candidate's v1–v8 runtime parser
with the actual owner-v9 and installed local-RPC sources, exact source revisions,
native companion pins and owner fixtures. Factory tests must use the real matched
composition. An exported review or substituted v8 test runtime is not sufficient.
Never copy a handful of candidate modules over the installed runtime.

Existing local RPC v1 supports inspect/challenge/execute for its current admitted
access-administration purpose. Endpoint configuration needs a separately versioned
capability and narrow Wallet consent. It must not reinterpret the existing four
access-admin permissions as deployment/configuration authority. Preserve the
original signed owner registration and bind the configuration capability through
the protected installation-owner channel with explicit owner consent.

Wire operation names, route paths and schema version identifiers are not allocated
by this document. Agree them against the reconciled DevGraph/Wallet/secS source
set before implementing decoders, fixtures or any executable adapter.

## Required semantic operations

| Phase | Transfer / programmatic client | Service contract |
| --- | --- | --- |
| Inspect | Select exact graph and service; enumerate bound endpoints and capabilities | Read authenticated current owner, configuration revisions, endpoint registry and readiness; report unsupported capabilities explicitly |
| Prepare | Supply explicit desired endpoint change and expected revisions | Validate authority/channel, origin/TLS/route/ceiling bindings and occupied listeners; return an immutable bounded plan with durable action ID, digest, blockers and before/after values |
| Review | Display plan and complete signed configuration disclosure | Bind exact owner proof/policy and plan digest in a new service-change challenge; no implicit member grant |
| Commit | Atomically reserve and durably retain the exact action before dispatch; obtain explicit Wallet approval | Recheck expected revisions and authority, apply only the owned change, record stable result and readiness; duplicate original action returns original result |
| Status | Recover by the original action identity and binding | Return original dispatch/result/progress evidence without creating another action or listener |

Local RPC discovery must match the selected graph/service and verified executable
manifest exactly. Remote service-control transport is supported only if the
server explicitly advertises and enforces that same new contract; local support
does not imply remote administration is enabled. The public member API must not
expose native host control or operator administration.

## Plan and consent bindings

The canonical plan must bind at least:

- Graph resource UUID, service identity, stable endpoint ID and binding generation.
- Active parent-owner proof digest, applicable owner/policy revision and the new
  service-configuration capability.
- Canonical provider/service identity and issuer/key/audience, plus the separate
  HTTPS origin, access-point binding, route policy digest and pinned
  unchanged-or-narrower permission ceiling.
- Explicit exposure: direct LAN, private Tailnet or public internet. Preserve
  origin identity separately from reachability and route configuration.
- Exact upstream target, TLS termination and hostname/certificate verification,
  expected Host handling and allowed member routes. No forwarded-header wildcard.
- Catalogue/hierarchy visibility, independent from permissions and Work data.
- Expected service configuration and endpoint-registry revisions, observed network
  revision/digest, durable action ID, plan digest and exact before/after values.

An origin change creates a new access-point binding for the same canonical
service; it does not create a new credential authority or rewrite signed legacy
requests, credentials or registrations. Route restrictions cannot expand the
canonical service's credential or policy ceiling.
Changing owner/revocation/configuration before dispatch invalidates the old plan.

## Transfer UI and storage

Endpoint list rows show name, exact origin, exposure, binding generation,
configuration revision and observed readiness. Use distinct states: unsupported,
not configured, prepared, awaiting approval, dispatching, result unknown, applying,
ready, failed/partial and disabled. A reachable port is not an authenticated
endpoint or a ready graph service.

Keep **Review change** separate from **Approve and apply**. Show TLS/route/policy
changes and whether any names become public. Never preselect public exposure or
rewrite occupied Tailscale listeners. Account records and host-network observations
cannot authorize configuration. Wallet unlock is distinct from action consent.

Use a new service-configuration action journal, not an altered access-admin journal.
Its composite key includes graph, service, endpoint binding/generation, action ID
and plan digest. Atomically claim across windows/processes before consent/dispatch,
persist dispatch state before network I/O, and refuse replacing an uncertain action.
Store no private keys, tokens or signed proof envelopes in that public journal.
After timeout offer **Check original result**, never automatic resubmission with
a new ID. Dispatched work retains its original bindings through later changes.

Discovery is published only after the service confirms exact route readback and
readiness. Partial application remains partial. Rollback may restore owned routing
or code but must not restore old grant/replay databases over newer decisions.

## Canonical service credential inbox

Each canonical service has one logical request/enrollment/grant/revocation/replay
authority. Its admitted access points reach that same authority. Transfer may show
the arrival route as provenance, but does not require a second request or grant
for another route. Show route failures without presenting another permission domain.

New inbox selection/journals bind canonical provider/service identity, request ID,
request digest and original action identity. Route provenance and channel binding
remain separate. All admitted routes coordinate replay and original-result
recovery. Legacy pending actions keep their original receiver-bound contract;
neither an endpoint change nor UI grouping silently migrates them.

## Integration ownership and paths

| Surface | Owner |
| --- | --- |
| Runtime/source reconciliation; canonical control schemas, host adapter, endpoint registry/CAS and status; bounded member routes | DevGraph host/runtime lane, coordinated with secS and Wallet maintainers |
| New service-change consent transcript and exact native proof validation | Wallet/secS maintainers with DevGraph contract owner |
| Native contract consumer, action journal, endpoint list/editor/review/status and endpoint-aware inbox projection | This `zenith-transfer` repository |
| Generic browser URL → Wallet request/enrollment/access UI | DevGraph browser lane |
| iOS connection/discovery/client rollout | Separate iOS lane; no iOS changes implied here |

Transfer integration points are `Sources/ZenithKit/ServicePublication.swift`,
`LocalAdminRPC.swift`, `LocalServiceDiscovery.swift` and new service-control/journal
types; `Sources/ZenithTransfer/TransferPublicationView.swift`, `TransferConsole.swift`
and native operator client selection/recovery. Reuse existing endpoint/pin validation
where compatible, but do not broaden existing RPC v1 or access-admin wire operations.

DevGraph and Transfer jointly review shared schema/fixture changes. The DevGraph
lane owns the canonical schema allocation; Transfer owns no parallel server state.
Neither lane edits the other's repository without a coordinated handoff.

## Acceptance gates

1. Matched immutable source/artifact set, real owner runtime and companion pins;
   original owner proof and local endpoint unchanged.
2. Repair or prove unreachable the relevant operator capacity/challenge/audit,
   RPC process-tree deadline and cross-window journal race findings on final paths.
3. Shared prepare/review/commit/status fixtures consumed by both a programmatic
   client and Transfer; exact consent and stale revision/owner/plan rejection.
4. Native UI and journal tests: concurrent windows/processes, lock/cancel, restart,
   lost response, partial application, original-status recovery and no second action.
5. Multi-access-point request/approve/enroll/accept/read/write/revoke qualification
   against one canonical service: one grant across routes; wrong services, invalid
   access-point bindings, cross-route replay, excluded paths and revoked credentials
   denied; concurrent retries execute only once. Legacy local credentials keep
   their original semantics until explicitly migrated.
6. TLS/Host/Origin/proxy-spoofing tests; endpoint disabling closes challenge,
   request/enrollment/presentation routes while preserving audit/replay state.
7. Human-reviewed exact live cutover and independent public browser acceptance
   from outside the Tailnet, after readiness/readback. Preserve unrelated routes.

No new Funnel, public listener, certificate trust, origin substitution, production
policy change or member grant is authorized by spec preparation or passing source
tests. A review-only export is not completion of service activation.
