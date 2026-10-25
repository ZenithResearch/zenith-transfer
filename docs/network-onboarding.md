# Set up network connections without an assistant

Open **Settings → Network** in Transfer. The Network screen works before a Wallet
is created or unlocked. It finds public DevGraph listings on this Mac and offers
saved files from **ConnectionFiles** in Transfer's Application Support folder.
Use **Open connection files folder** to find that folder. **Choose connection
file** also works with files saved elsewhere. Refresh after copying a file.
Nothing is connected or replaced merely by finding or choosing a file.

## Tailscale

1. Install the official Tailscale app using **Install Tailscale**, then open it.
   Auth-key enrollment is the preferred new-device path; browser sign-in
   remains available in Tailscale. An existing host connection is reused; Transfer does not
   change a Mac already associated with a network to a different network.
2. A Tailscale connection file is plain UTF-8 text containing only a `tskey-auth-`
   enrollment key, optionally followed by a newline. Transfer discovers `.txt`,
   `.key` and `.tailscale-key` files in its ConnectionFiles folder. It accepts the
   same key format as the existing iOS enrollment-file importer.
3. If you manage the network, expand **How to get a Tailscale auth-key file**
   and open **Tailscale Keys**. Generate a one-time, non-ephemeral key with
   **Reusable** and **Ephemeral** off. Choose **Create auth-key file** in
   Transfer, paste the key into the protected field, and save a new file. No
   Terminal command, JSON editing, URL entry or LLM is needed for this step.
   Use a different one-time key for each Mac, iPad or iPhone installation.
   Leave Tags unset for a personal device and retain device approval when enabled.
   Otherwise, ask your network administrator for that file.
4. Choose or review the file, then explicitly select **Connect this Mac**.
   Device approval may still be required. Refresh after the administrator approves
   it. Expired or used one-time keys need replacing by the administrator.

Keep enrollment files private. Transfer creates its own files with owner-only
permissions and excludes the managed directory from backups. It does not delete
original files. The enrollment key is never put in process arguments, environment
variables, application logs, public DevGraph connection files or Wallet exports.
The official CLI receives a private temporary file snapshot; Transfer removes it
when the attempt ends. Closing cancels the local attempt; a device already added
at Tailscale must still be managed in Tailscale.

See [Tailscale auth keys](https://tailscale.com/docs/features/access-control/auth-keys)
and [the official file-input option](https://tailscale.com/docs/reference/tailscale-cli/up).
No control-plane override, route, exit node, OAuth/API token, shell command or
executable can be supplied by an enrollment file.

## DevGraph on this Mac

1. Install and configure DevGraph following its [setup guide](https://github.com/ZenithResearch/devgraph/blob/main/docs/user/beta.md).
   If the existing local instance is not listed, run `devgraph local resource register`
   once in Terminal; `devgraph local start` starts that configured instance.
   This uses its existing local configuration, without entering a server URL.
2. Refresh in Transfer. Select a discovered **Wallet API** and **Review connection**.
   Check the displayed service, network and verification settings, then save.
   A Private API without a Wallet connection needs Wallet access setup in
   **Resources & requests** before it can provide a public connection file.
3. Open **Resources & requests** to use the saved service. Wallet access and server
   permissions are requested and approved separately.

To configure another Mac or iPhone, the server owner selects a Tailnet, LAN or HTTPS
Wallet connection and **Save connection file**. Transfer writes the existing
public DevGraph JSON contract; there is no new issuer/credential format. Send that
file with Files, AirDrop or another trusted transfer. The receiving user chooses
**DevGraph connection file**, reviews it, then saves it. A **This Mac only**
connection points at loopback and cannot be used by another device.

Private Tailnet connections need the network first. Public Funnel endpoints can
be used without joining Tailscale. A connection file supplies public endpoint and
verification settings; it does not grant service access, install Wallet trust or
include a Tailscale auth key. Existing saved settings are preserved with a revision
check; changed files must be selected and reviewed again.

## Validation boundaries

Synthetic tests cover safe file reads, duplicate/oversize/link rejection, stale
review detection, no overwriting, private temporary key handling and cleanup,
connected-host protection, cookie-free host transport and failure before requests
when Tailscale is disconnected. Native UI rendering covers an empty installation
with no configured Wallet. Tests never enroll a real device or change a live
Tailscale/Serve/Funnel configuration. macOS uses its installed Tailscale node and
OS routing; the existing iOS embedded route and its no-direct-fallback guard are
unchanged. Wallet/Core remains pinned to public Core0.4.0 / `0c889e7`; this UI change does not change that dependency.
