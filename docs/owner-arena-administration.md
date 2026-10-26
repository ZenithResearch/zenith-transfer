# Owner Arena administration

In Credentials & requests for a locally administered DevGraph, review the inbox
with the registered owner Wallet. **Enable Arena sharing** offers a separate
owner review for every current/future Arena and creation of Arenas. This changes
the owner ceiling only, preserves existing Work rules and member grants, and
restarts only the graph's already-installed Wallet services. Transfer never
hosts an HTTPS listener itself.

The original owner registration is retained. The signed review binds the exact
graph, canonical provider, old/new policies, access points and proposal digest.
Local secS RPC verifies the Wallet proof; the receiver rechecks the current
registered owner. A retained journal and server transaction preserve the
original action through lock, relaunch and uncertain results. Recover the
original result instead of starting a second action.

Once enabled, **Create Arena** asks for a stable ID, name and description and
presents an exact Wallet review. It executes through DevGraph's normal mutation,
audit, receipt and idempotency machinery. It creates no member grant.

For a member, select its request, optional preset, Work hierarchy and/or explicit
Arena records, permissions and validity. The all-Arena owner rule is never copied
into a member credential. Future Arenas appear in the owner's refreshed catalog,
but existing recipient credentials do not automatically gain them. Onward
delegation remains disabled.
