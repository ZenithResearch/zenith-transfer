# Scope and permission editing in Transfer

The canonical completion plan and Canadian security-control mapping are in
[DevGraph's resource-scoped permissions plan](https://github.com/ZenithResearch/devgraph/blob/codex/owner-arena-completion/docs/auth/resource-scoped-permissions-plan.md).

The immediate editor order is preset, Scope, Read permissions, Write permissions
and Validity. Scope contains hierarchy selection, object-type limits and a
read-only preview of its Arena-record coverage. A single Arena read action
uses that verified coverage. It never grants Work solely because an Arena
record is readable. Standalone Work paths do not infer an Arena, and the
selection compiler rejects Arena IDs outside the current hierarchy.

This is a local editor constraint using the existing signed grant formats.
It does not migrate old grants, broaden owner policy, add onward delegation,
or change the current running Transfer app. Arena list/get are still bundled;
member Arena IDs stay explicit snapshots. Separate hierarchy scopes per action
are the next planned editor stage, not a feature claimed by this change.

The audit script reads the canonical DevGraph operation constants and ontology:

```sh
python3 scripts/audit-devgraph-operation-coverage.py --devgraph /path/to/canonical/devgraph --report /path/to/report.json
```

It currently reports 12 of 20 named mutations configurable by this editor.
The eight gaps are Arena create/patch/archive/member.set and Work
accept/convert/proposal.reject/workflow.review. Owner-only Create Arena is not
recipient-grant coverage. Additional graph/material/query/export read families
also need explicit receiver mappings. No claim of full operation coverage or
Canadian certification is made.
