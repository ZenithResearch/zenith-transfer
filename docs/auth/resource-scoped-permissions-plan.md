# Resource-scoped permission rules in Transfer

Transfer 53 adds independent permission rules to the native credential editor.
Choose a rule's preset or custom actions, Scope, Read permissions and Write
permissions. Add another rule for a different hierarchy or action set. One
Validity applies to the complete reviewed assignment.

For example, rule 1 can read Work below Arena A while rule 2 edits Work below
Project B. The compiler preserves these pairs; it never unions all actions with
all hierarchies. No matching rule means deny. Selecting a parent includes its
current and future descendants; unchecking a child is not an exclusion.

Scope supports verified hierarchy branches, exact resource IDs, or explicitly
all resources permitted by the provider's existing rules. Arena records follow
verified Arena anchors for fixed-ID grants. With a compatible server and an
all-Arena ceiling, Scope can instead select “Arena records: all current and
future Arenas.” This stores a live collection selector, including future records,
without widening existing fixed-ID grants. Reading an Arena does not
grant sibling Work access. Creation, proposals, decisions and review evidence
cannot silently inherit a Work hierarchy wildcard. Every resource touched by a
move, relationship, decision or review still needs the matching operation.

All 20 named Work/Arena mutations are recognized when offered by the provider's
current policy. New actions do not expand the built-in presets, old saved recipes,
owner authority or existing member grants. The advanced custom rule editor and
server presets can select the additional operations. The local saved-recipe
format remains the existing Work/Arena-read recipe format; richer saved rule
recipes need a separately versioned format. Arena list/get are still bundled.

The compiler emits the existing provider grant arrays, with each original row's
conditions intact. secS and Wallet Core already verify opaque action IDs with
independent scopes and reject cross-rule substitution. Tests cover same-holder
equal/narrower derivation and encrypted grant backup/restore. The native Core pin,
shared iOS Wallet files and signed protocols are unchanged; onward delegation
remains disabled. Management uses the canonical service's local secS RPC.

The canonical [DevGraph implementation plan](https://github.com/ZenithResearch/devgraph/blob/codex/owner-arena-completion/docs/auth/resource-scoped-permissions-plan.md)
records receiver semantics, Canadian security-control references and remaining
work. Graph/material/query/export families are separately classified; supporting
20 named mutations is not a claim of every private API operation or certification.

```sh
python3 scripts/audit-devgraph-operation-coverage.py --devgraph /path/to/canonical/devgraph --report /path/to/report.json
```

The audit now requires all 20 named mutation IDs to match the editor adapter.
It reads source and ontology only and never changes running authority.
