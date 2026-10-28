# Configure existing grants

Both active-grant lists expose **Configure** beside the separate revocation action.
It loads the same permission/scope/validity editor used for pending requests, using
the authenticated server's exact current assignment snapshot. Historical request
preferences do not lock changes to an already approved grant.

Opening, editing, returning to the inbox or discarding a draft sends no action and
does not change permissions. Current permissions are shown in a separate disclosure.
**Review exact selection in Wallet** obtains a server review; **Approve changes in
Wallet** is the final update. The original request is reused; no new request is
submitted. Current access remains active until approval commits.

The server must advertise `devgraph.grant-configuration.v1` and supply a configuration
snapshot. Older servers remain readable/revocable and explain that an update/reload
is needed when Configure is chosen. A failed or uncertain action keeps the existing
original-action recovery flow; no replacement action is silently created.

Hydration checks recipient/issuer/receiver/installation bindings, assignment digests
and validity, then recompiles the initial rules against the operator ceiling. It
compares every action/resource/path/filter row with the original, ignoring only array
ordering. Independent read/write scopes remain independent; restricted filters are
never silently broadened. Unsupported filters, missing inventory, mixed exact/path
conditions or excessive rules fail closed with an explanation. Credential lifetime
caps are retained, because this editor does not expose that field.

Version 1 edits permissions within the existing read/write components. At least one
permission in each existing component must remain; adding/removing a whole component
requires a separately reviewed lifecycle extension. Full removal uses revocation.
Pending-request omission semantics are unchanged. Exact previous assignment digests
and current policy prevent a stale draft from overwriting another decision.

Synthetic coverage: `ExistingGrantConfigurationTests` verifies round-trip loading,
independent scopes, lifetime retention, invalid snapshot/filter refusal, and that
opening/editing/cancelling/reopening never signs, submits a request or changes the
loaded grant. Server lifecycle tests cover review versus approval, expired original
submission, stale assignment/review, rollback and mixed-grant revocation.
