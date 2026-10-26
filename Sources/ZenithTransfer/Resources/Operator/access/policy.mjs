import {validityView} from './core.mjs';
/** Present the authenticated server ceiling without merging correlated rules. */
export function policyView(model){
 const ceiling=model.ceiling,groups=[],validity=validityView(ceiling);
 const arenaReadIds=[...new Set((ceiling.read_grants??[]).filter(g=>g.scope==='devgraph.arena.read').flatMap(g=>g.arena_ids))].sort();
 for(const grant of ceiling.read_grants??[]){if(grant.scope==='devgraph.arena.read'){groups.push({mode:'Read',operations:['Read Arena metadata'],kinds:['Arena'],objects:grant.arena_ids.map(id=>'Arena/'+id),arenas:[...grant.arena_ids],archived:true,relationships:[]});continue;}groups.push({mode:'Read',operations:[...grant.operations],kinds:[...grant.work_kinds],objects:grant.work_ids?[...grant.work_ids]:null,arenas:grant.arena_ids?[...grant.arena_ids]:null,archived:grant.include_archived,relationships:[...(grant.relationship_types??[])]});}
 for(const grant of ceiling.write_grants??[])groups.push({mode:'Write',operations:[grant.operation],resources:structuredClone(grant.resources),arenas:grant.arena_ids?[...grant.arena_ids]:null});
 return{arenaReadIds,revision:model.policy_revision??null,digest:model.policy_digest_sha256??null,issuer:ceiling.issuer,receiver:ceiling.receiver,notBefore:validity.not_before,notAfter:validity.not_after??null,untilRevoked:validity.mode==='until_revoked',validity,lifetime:ceiling.lifetime_seconds,groups,kinds:[...new Set(groups.flatMap(g=>g.kinds??g.resources.map(r=>r.kind)))].sort(),readOperations:[...new Set((ceiling.read_grants??[]).filter(g=>g.scope==='devgraph.work.read').flatMap(g=>g.operations))].sort(),writeAvailable:model.activation?.write!==false&&Boolean(ceiling.write_grants?.length),mixedAvailable:model.activation?.mixed!==false&&model.activation?.write!==false&&Boolean(ceiling.read_grants?.length)&&Boolean(ceiling.write_grants?.length)};
}
export const operationName=operation=>({'get':'Read details','list':'List work','relationships':'Read relationships','children':'Read children','blockers':'Read blockers'}[operation]??operation.replace('devgraph.work.','').replace('.v2','').replaceAll('.',' '));
export function renderPolicy(container,model){
 const view=policyView(model),doc=container.ownerDocument,element=(tag,text)=>{const n=doc.createElement(tag);n.textContent=text;return n;};
 container.replaceChildren();
 const counts=view.groups.reduce((n,g)=>({...n,[g.mode]:(n[g.mode]??0)+1}),{});
 container.append(element('p',(counts.Read??0)+' read rules · '+(counts.Write??0)+' write rules · '+(view.untilRevoked?'Until-revoked grants permitted':'Grant expiry no later than '+new Date(view.notAfter*1000).toLocaleString())),element('p',view.writeAvailable?'Read and write choices are available within this policy.':'Write activation is unavailable under this server policy.'));
 const details=doc.createElement('details');details.className='policy-rules';details.append(element('summary','View policy rules and verification details'));container.append(details);
 const content=doc.createElement('div');details.append(content);content.append(element('p','Issuer: '+view.issuer),element('p','Server: '+view.receiver),element('p','Policy revision: '+(view.revision??'not supplied')),element('p',view.untilRevoked?'Grants may remain valid until revoked. Individual credentials still expire.':'Grant expiry must be no later than '+new Date(view.notAfter*1000).toLocaleString()),element('p','Issued read credentials last up to '+view.lifetime+' seconds within the grant.'));
 for(const [index,group]of view.groups.entries()){
  const rule=doc.createElement('details');rule.className='policy-rule';rule.append(element('summary',group.mode+' rule '+(index+1)+' · '+group.operations.map(operationName).join(', ')));
  if(group.mode==='Read'){rule.append(element('p','Kinds: '+group.kinds.join(', ')),element('p',group.objects?'Objects: '+group.objects.join(', '):'All matching current and future objects within these kinds'),element('p',group.archived?'Archived objects included':'Archived objects excluded'),element('p','Relationship types: '+(group.relationships.join(', ')||'none')));}
  else for(const resource of group.resources)rule.append(element('p',resource.ids?resource.ids.map(id=>resource.kind+'/'+id).join(', '):'All '+resource.kind+' objects permitted by this policy, including future objects'));
  rule.append(element('p',group.arenas?'Arenas: '+group.arenas.join(', '):'No additional Arena restriction in this rule'));content.append(rule);
 }
 content.append(element('p',view.writeAvailable?'Write choices are limited to the operations and resources shown above.':'Write activation is unavailable under this server policy.'));
 if(model.activation?.mixed===false)content.append(element('p','This server requires read and write grants to be approved separately.'));
 if(view.digest){const details=doc.createElement('details');details.append(element('summary','Policy digest'),element('code',view.digest));content.append(details);}
 return view;
}
