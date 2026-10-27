# Shared service access

The native apps authenticate an access point before using canonical provider
authority. Issuer/key/service identify the provider service; HTTPS, LAN, Tailnet
and protected local RPC are routes to it. The signed public binding does not
grant access or bypass certificate/site/Wallet checks.

New read and access-request calls use the signed canonical receiver and fixed
service route. Equal-scope or narrower holder credentials retain their existing
format, and onward delegation remains disabled. Request IDs, installation and
Wallet identity checks remain exact. Transfer resolves locally registered routes
through secS inspect and executes through secS RPC without an HTTP hop.

An existing uncertain legacy operator action or member request stays on its
original route for recovery. Canonical-provider journals retain their namespace
so verified aliases see the same current request. No signed action is relabeled
or resubmitted under a different identity; no existing server or Wallet is
removed. An unsupported old service retains its old protocol. Invalid or expired
bindings and changed registration fail closed.

Saved connection settings retain the chosen transport and certificate. The new
public binding is optional and old settings decode unchanged. Source builds and
synthetic tests do not establish installed-provider authority or real-device
qualification; production opt-in and a real Wallet are still required.

After confirmed legacy recovery, the editor renegotiates the current service
before a new action. A stored route binding cannot relabel an original journal.

## Transfer service inbox (build 50)

The resource chooser groups registered interfaces by the local registry's graph
ID. Private API, local Wallet API and Tailnet/public access points appear under
one DevGraph service. Matching saved profiles are associated with that entry;
unrelated saved profiles are not merged by name, hostname or port. Conflicting
issuer pins block management rather than silently picking a server.

**Manage credentials** opens one Requests / Grants / Servers view. Transfer
loads every registered local management store with Wallet-authenticated secS RPC;
there is no HTTP or Tailscale fallback on this path. A missing local binding is
reported as incomplete coverage. This update does not deploy a service, enable
network publication, register an owner or issue a recipient grant.

Canonical aliases of one authority share one inbox fetch. Older origin-bound
stores remain included so pending requests and existing grants do not disappear.
Their signed request IDs, receiver restrictions and original journals are not
rewritten. A retained action takes priority over canonical route negotiation;
status recovery retains its original identity and action ID. The combined view
qualifies legacy row IDs with their authority, so a collision cannot route a
decision to a different store.

Selecting a request opens its normal custom editor: permissions, presets,
hierarchy, validity and **Servers & origin restrictions**. Existing restrictions
are displayed and enforced, not broadened by regrouping servers. The UI does
not invent an editable origin-attenuation contract; changing those signed
restrictions remains a separate protocol change. Onward delegation stays off.
The Servers view contains exact access points and existing network controls.

Pagination appends to the combined list; changed request snapshots or policy
digests require refresh. Missing stores, retained actions and further pages keep
the coverage indicator incomplete. Reading the inbox never implicitly runs an
owner-policy migration. Grant activation/revocation keeps its separate exact
Wallet review. Loaded data is application-memory state, not Wallet backup data.

Verification includes grouping/identity, legacy ID collisions, pagination,
canonical alias deduplication, original journal selection, synthetic Wallet proof
execution over injected local RPC, refusal of unregistered remote management,
and an opt-in read-only inspection of installed local service metadata. Real
Wallet inbox review and member grants still require the user's Wallet consent.
