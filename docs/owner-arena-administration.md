# Owner Arena administration

Arena is an ordinary resource scope in the existing credential system. In
Credentials & requests, authenticate with the registered owner Wallet, select a
recipient, and choose Arena records and Work coverage in the standard editor.
There is no Arena-sharing feature switch, app-specific grant or separate kind of
recipient credential. secS and DevGraph enforce the same scope over every
admitted access point; iOS reads the same credential contract.

An older signed owner policy may require a one-time compatibility migration.
The inbox flow obtains an explicit Wallet approval for that exact data update,
then reloads the standard editor. It does not reinterpret a read-only inbox proof
as permission to change policy. A cancelled or uncertain update preserves its
original journal for recovery. This preserves existing Work rules and member
grants and restarts only the graph's already-installed Wallet services. Transfer
never hosts an HTTPS listener itself.

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
