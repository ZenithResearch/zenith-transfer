# Persistent iOS Tailnet connection

Enroll once using a one-time, non-ephemeral Tailscale auth key. The SDK keeps
its existing node identity in `Application Support/PrivateNetwork/tailscaled.state`.
That installation-local directory remains protected by complete file protection
and excluded from device/Wallet backups. Auth keys are transient enrollment
input, never saved or replayed by reconnect logic.

The app now remembers two non-secret network preferences: automatic reconnect
(default on), and whether the connection was explicitly disconnected. Startup
probes only the existing SDK state file's metadata; the SDK and control plane
still decide whether it is valid and admitted. An earlier installation with
saved state is restored noninteractively. A fresh installation or restored app
preferences without the device state never creates a new node automatically.

**Reconnect to Tailscale** reuses the saved identity without a new key or browser
login. **Disconnect Tailscale** preserves that identity but remains disconnected
across launches until the user reconnects. The automatic reconnect setting can
also be disabled. Failed, expired or revoked identities require explicit user
attention; reconnect never automatically opens browser authentication, changes
the control plane, reenrolls, or falls back to a direct connection.

This is an app-scoped userspace node, not an always-on iOS VPN. Backgrounding or
locking the device closes the node and invalidates old HTTP sessions. Returning
to Zenith restores it when automatic reconnect is enabled. Locking the Wallet
alone does not disconnect the network; signing still requires Wallet approval.

The enrollment identity remains application network data, outside Wallet
recovery exports and grant backups. No DevGraph scopes, grants, endpoints,
Serve/Funnel mappings or server exposure change. macOS Transfer already uses
the installed Tailscale host node; the shared library/test update does not
replace or reenroll that node.

Verification covers cold-launch restoration, legacy state discovery, no auth-key
replay, explicit disconnect across launch, disabled auto reconnect, missing state,
late completion after cancellation, expired login without automatic browser UI,
transport invalidation and no direct fallback. Physical-device qualification
still requires enrolling or reusing the user's existing node, then backgrounding
and relaunching the signed app.

Sources: [tsnet state directory](https://tailscale.com/docs/reference/tsnet-server-api)
and [auth-key and node-key expiry](https://tailscale.com/docs/features/access-control/auth-keys).
