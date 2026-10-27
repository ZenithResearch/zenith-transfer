#if os(macOS)
/// DevGraph's adapter over opaque secS action IDs. Recipes remain separate and
/// never acquire additional authority when this supported-action list grows.
enum DevGraphPermissionCatalog {
  struct Action: Identifiable {
    let id: String
    let title: String
    let explanation: String
    let kinds: [String]
    let hierarchy: Bool
    init(_ id: String, _ title: String, _ explanation: String, _ kinds: [String], hierarchy: Bool = true) {
      self.id = id; self.title = title; self.explanation = explanation; self.kinds = kinds; self.hierarchy = hierarchy
    }
  }
  static let workKinds = ["Todo", "Proposal", "Initiative", "Project", "Issue", "Task"]
  static let writes: [Action] = [
    Action("devgraph.work.create.v2", "Create Work", "Creation requires an explicit new resource ID or all permitted resources; a hierarchy alone cannot authorize unattached creation.", workKinds, hierarchy: false),
    Action("devgraph.work.patch.v2", "Edit Work", "Change permitted fields of matching Work items.", workKinds),
    Action("devgraph.work.progress.set.v2", "Set progress", "Completion may also require a separately authorized ReviewPacket and evidence links.", workKinds + ["ReviewPacket", "ExternalLink"]),
    Action("devgraph.work.dependency.add.v2", "Add dependency", "Both ends of the relationship must be authorized for this action.", workKinds),
    Action("devgraph.work.dependency.remove.v2", "Remove dependency", "Both ends of the relationship must be authorized for this action.", workKinds),
    Action("devgraph.work.blocker.add.v2", "Add blocker", "Both Task endpoints must be authorized for this action.", ["Task"]),
    Action("devgraph.work.blocker.remove.v2", "Remove blocker", "Both Task endpoints must be authorized for this action.", ["Task"]),
    Action("devgraph.work.parent.set.v2", "Move Work", "Current and destination containers must be authorized; the receiver checks before and after the move.", workKinds + ["Arena"]),
    Action("devgraph.work.workflow.assign.v2", "Assign workflow", "Assign a workflow to matching Work items.", workKinds),
    Action("devgraph.work.workflow.transition.v2", "Transition workflow", "Workflow gates still apply to matching Work items.", workKinds),
    Action("devgraph.work.archive.v2", "Archive Work", "Archive matching Work items.", workKinds),
    Action("devgraph.work.restore.v2", "Restore Work", "Restore matching archived Work items.", workKinds),
    Action("devgraph.work.accept.v2", "Accept proposal", "Authorize the Proposal and the new Decision separately, using exact IDs or all permitted resources.", ["Proposal", "Decision"], hierarchy: false),
    Action("devgraph.work.convert.v2", "Convert proposal", "Authorize the Proposal, Issue and new Decision. Proposal and Decision records cannot inherit a Work hierarchy wildcard.", ["Proposal", "Issue", "Decision"], hierarchy: false),
    Action("devgraph.work.proposal.reject.v2", "Reject proposal", "Authorize the Proposal and new Decision separately.", ["Proposal", "Decision"], hierarchy: false),
    Action("devgraph.work.workflow.review.v2", "Review workflow", "Authorize the Work item and each ReviewPacket, Handoff or evidence link touched by the review.", workKinds + ["ReviewPacket", "Handoff", "ExternalLink"]),
    Action("devgraph.arena.create.v1", "Create Arena", "Authorize the new Arena ID or all permitted Arena resources. This does not grant credential administration.", ["Arena"], hierarchy: false),
    Action("devgraph.arena.patch.v1", "Edit Arena", "Change the selected Arena records; no sibling Work access is implied.", ["Arena"]),
    Action("devgraph.arena.archive.v1", "Archive Arena", "Archive the selected Arena records subject to the receiver's lifecycle checks.", ["Arena"]),
    Action("devgraph.arena.member.set.v1", "Move Work between Arenas", "Authorize the Work item and both prior and destination Arena records. Scope is checked before and after the move.", ["Initiative", "Task", "Arena"])
  ]
}
#endif
