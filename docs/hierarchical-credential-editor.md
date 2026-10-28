# Hierarchical credential selection in Transfer

The credential editor starts with the server-verified Arena → Initiative → Project tree. Expand a branch, then choose Read, Write, or both on its row. A selected container covers its permitted current and future Work descendants. A moved-out item no longer belongs to that branch. Sibling branches are independent.

Read selects the server-admitted Work read operations. Selecting an Arena directly also selects its admitted Arena metadata read; choosing only a Project does not silently add the containing Arena record. Write in the simple editor means Edit Work details (`devgraph.work.patch.v2`); it does not imply Read, creation, deletion, progress, membership or grant administration.

Inherited checks name the parent relationship and cannot be unchecked to create an exclusion. Remove the parent selection and choose narrower branches instead. Each column supports up to sixteen independent branches. The existing signed compiler checks each column separately against the original ceiling: Read on Arena A and Write on Project B never become Write on Arena A.

Choose **Advanced rules and other write actions** for creation, progress, workflow, moves, Arena operations, exact resource IDs, all-permitted/future-Arena coverage, presets and custom paired rules. This transition preserves the exact selected paths, actions and validity. It sends no request and opens no Wallet approval. All twenty existing named mutation controls remain available there under their original admission rules.

Validity applies to both columns. Review the selection, then approve the exact credential through the existing Wallet ceremonies. Editing a checkbox is never approval. There is no new delegation field or changed signed format. Failed or uncertain operations retain the existing journal and retry identity; do not replace an uncertain request with a new request.

Known connection, catalog and Wallet approval errors now show distinct closed diagnostics. For an expired service binding, reopen the server to obtain a fresh verified connection. For a stale request, refresh context and review again. For an uncertain result, recover the original action first. Arbitrary server or core text is not exposed. These diagnostics do not establish that the live grant failure has been resolved; that needs the actual failing step and receiver result.

Qualification: the existing permission compiler and full Transfer suite, targeted parent/child/sibling scope isolation, branch budgets, advanced handoff preserving compiled bytes, and a rendered synthetic hierarchy fixture. Real Wallet authority and consent remain user-controlled.
