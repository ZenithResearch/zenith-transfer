# Identity and account boundaries

Transfer owns the native UI. Castalia owns Wallet custody and exact-consent signing.
An account record associates a public provider identity with one Castalia public
key locally; this association is not proof of ownership or a server credential.

```mermaid
flowchart TD
  Transfer[Zenith Transfer] --> Wallet[Castalia Wallet custody]
  Transfer --> Accounts[Public identities and accounts]
  Accounts --> Matrix[Matrix ID and homeserver]
  Accounts --> Nostr[Nostr public key and relay]
  Accounts --> Tail[Tailscale account and Tailnet]
  Transfer --> Inspector[Read-only host Tailscale inspector]
  Inspector --> Node[Persistent Tailscale host service]
  Wallet --> Admin[Wallet-signed DevGraph administration]
  Admin --> Grant[Resource permissions and Arena/path scopes]
  Accounts -. future provider adapters .-> Secrets[Protected authentication references]
  Transfer -. future owner-authorized adapter .-> Publish[Serve or Funnel configuration]
  Publish --> Node
```

Private keys/sessions are not stored in account metadata. Tailscale node state
remains with its persistent service; quitting Transfer does not stop it. Graph
authorization is independent of Matrix, Nostr and Tailscale account authentication.
Local secS RPC and remote HTTPS retain their separately bound service selection.
