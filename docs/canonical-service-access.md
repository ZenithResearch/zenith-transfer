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
