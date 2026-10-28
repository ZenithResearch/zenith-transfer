# Native session review and local MCP bridge

This candidate adds a native Transfer review window, private local broker and
stdio MCP adapter. The actual Wallet Core → session custody → secS → DevGraph
receiver chain is qualified with new disposable test data. The installed app's
provider remains unavailable until an actual DevGraph adapter is separately
qualified and registered. There is no production authority change in this slice.

## Flow and trust boundaries

1. A local MCP process gets a random client identifier. The model cannot choose
   that identifier, a transport URL, provider executable or profile file.
2. `request_session_credential` asks the configured provider to prepare a finite
   scope for a fresh session key held by its persistent native custody helper.
   Transfer journals the public immutable review. This issues no credential.
3. Transfer opens a native window showing the canonical service, session public
   key, operations, resources, conditions and expiry. The session label is
   explicitly untrusted local-application text, not an attested Codex identity.
4. The person may edit expiry. A new provider revision, challenge and digest
   must be verified before approval. The exact requested permissions stay fixed.
5. The existing native Wallet Core operator-consent verifier checks the issuer,
   receiver and entire `details.session_review` binding. Its existing 120-second
   challenge lifetime is unchanged. The effective approval deadline is the
   earlier of that challenge expiry and the retained review deadline.
6. Only the native UI can approve. Transfer durably records the dispatch fence
   before asking Core to sign and submitting the proof over private provider
   IPC. No approve, arbitrary-sign, seed-export or grant-export MCP tool exists.
7. The provider verifies the owner proof, activates the ordinary access decision
   and installs the exact finite grant in the session custody helper. MCP gets
   an opaque, client-bound credential handle, never the root grant or key.
8. Scoped calls use that helper's proof of possession and the existing receiver's
   verification. A resource URI is a semantic authorization target; it cannot
   select a network endpoint. Business results alone return to MCP.

The owner Wallet may lock after approval while the separate session credential
remains usable until its own expiry/revocation. This does not change Wallet
inactivity settings. Onward delegation and silent renewal remain disabled.

## Local transport and persistence

Settings → Session requests enables the channel; it is off by default. The
socket lives in an owner-only directory under the system temporary directory,
with same-UID peer checking, a random private pairing token, exclusive broker
lease, bounded frames, duplicate-key rejection and closed method dispatch.
Descriptors are close-on-exec. This opens no TCP listener. Same-UID processes
are not a hardened security boundary against a compromised local user account;
this channel does not replace the separately designed code-authorized XPC signer.

App recovery records live alongside application configuration, separate from
the Wallet and its backup. They retain public review snapshots, status and opaque
handles; no password, owner proof, private session key or root grant is recorded.
Writes compare the previous revision, replace atomically and fsync the file and
directory before dispatch. Corrupt records block new requests without deletion.
After uncertain dispatch, only the original result may be reconciled. Closing a
window does not mean provider cancellation or revocation.

The provider process is pinned to explicit interpreter, script, profile and
source inventory hashes. Its environment excludes unrelated tokens, Python
path overrides and dynamic-library injection variables. Python's venv invocation
path is preserved. A failed custody/provider process is not silently restarted
under an old handle: its memory-only session key cannot be recovered. The app
journal is not a session-key backup or a promise of restart survival.
These pins bind the reviewed application source. They do not make Python's
third-party site-packages or the complete operating-system environment immutable;
that requires a separate packaging and deployment boundary.

After every awaited owner/provider step, Transfer rechecks the channel lifecycle,
client liveness and exact active review version before retaining consent or
dispatching. EOF during preparation cannot save a dead-custody review. EOF during
native signing blocks subsequent submission; if dispatch was already fenced or
in flight, the original record stays outcome-unknown without another approval.

Normal stdio EOF asks the provider to close only that client's helper and release
its capacity slot. This private cleanup method is not an MCP tool. Cleanup failure
or abrupt process termination cannot be described as confirmed key destruction
or server revocation; the finite receiver-enforced expiry still applies.

The MCP-process identity identifies the local adapter instance, not a verified
conversation ID or the human owner's identity. Restarting that adapter cannot
claim another instance's credential. Session helper teardown is not server-side
revocation; the receiver still enforces expiry and revocation independently.

## Codex configuration

The Settings button copies a Codex TOML snippet referencing the script inside
the packaged app resources. It does not edit user configuration or start a
provider. The existing app must remain open with local requests enabled.
The format follows [OpenAI's MCP configuration documentation](https://learn.chatgpt.com/docs/extend/mcp?surface=cli).

```toml
[mcp_servers.zenith_transfer_wallet]
command = "/usr/bin/python3"
args = ["-I", "/path/to/Zenith Transfer.app/Contents/Resources/ZenithKit_ZenithTransfer.bundle/Resources/MCP/transfer_mcp.py"]
```

Tools: `list_wallet_services`, `request_session_credential`,
`get_session_credential_status`, `call_service_with_session_credential`.
The user reviews the complete native request before signing. A model-facing
tool result cannot be used to programmatically approve it.

## Qualification and compatibility

The producer is `ZenithResearch/devgraph` at
`1b3c5f03a1b7e5ba6ea51d594d7803ac35ce63b9`; custody is
`ZenithResearch/castalia-wallet` at
`a325fcf90ef6ffa7535235e9cd38f6801d87a8b0`.
The initial unsigned manifest fixture and pin remain documented in
[session-access-review.md](session-access-review.md). Existing signed grant,
credential, operator-consent and Wallet backup formats are unchanged.

`scripts/test-transfer-mcp.py` runs dependency-free wire/privacy checks.
`SessionReviewBridgeTests` covers real stdio/socket interaction, idempotency,
cross-client denial, durable recovery fences, unsafe filesystem cases, packaged
configuration and optional offscreen native rendering.
`NativeSessionEndToEndTests` is opt-in: it requires six explicit fixture paths
(`TRANSFER_SESSION_TEST_PYTHON`, `..._GENERATOR`, `..._PROVIDER`, `..._BINARY`,
`..._HOLDER`, `..._READ`). It creates a new disposable native Wallet and graph,
verifies an edited expiry through real Core consent/issuance, locks the owner
Wallet, reads the permitted task, denies another task and another MCP client,
and confirms the owner's identity and empty grant store afterward. Automated
approval in this test is confined to those new disposable fixtures.

This qualification supports the fixture's explicit Work get/list mapping.
Modern Arena/path/standing profiles and writes are refused rather than flattened
into a different scope. Actual DevGraph profile mapping, reviewed registration,
production activation and installed-app replacement remain separate gates.

## Provider registration

`SessionReviews/provider.json` is application configuration, excluded from the
recovery-record scan and Wallet backup. The typed example is
`Tests/ZenithTransferTests/Fixtures/session-provider-registration-v1.json`.
The loader accepts only an owner-private regular file, pinned provider and HTTPS
receiver origin, canonical profile digest, explicit interpreter/script/profile
file hashes and a unique source inventory. The registration's own bytes are
included in the runtime hash fence. Declared disposable/production mode must
match the provider's advertisement before requests are allowed. This is checked
even when a requester skips service discovery. Absence stays unavailable;
invalid configuration blocks the channel and preserves all files.

The example has placeholder hashes and cannot launch. A production registration
must be generated from reviewed actual source/profile bytes and installed only
after its concrete review. No discovery result, MCP call or model-selected file
can install it. It does not convert a route into a separate credential authority.
