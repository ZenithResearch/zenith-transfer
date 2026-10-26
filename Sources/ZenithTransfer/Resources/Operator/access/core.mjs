const kinds=new Set(['Todo','Proposal','Initiative','Project','Issue','Task','Arena','Decision','ReviewPacket','Handoff','ExternalLink']);
export function resourceIds(text){
 const ids=typeof text==='string'?text.split(/[\s,]+/).filter(Boolean):text;
 if(!Array.isArray(ids)||ids.length>256||ids.some(id=>typeof id!=='string'||!kinds.has(id.split('/')[0])||!new RegExp('^[A-Za-z]+/[a-z0-9][a-z0-9-]{0,255}$').test(id)))throw Error('invalid_resource_selection');
 return [...new Set(ids)].sort();
}
const intersect=(a,b)=>b.filter(x=>!a||a.includes(x));
export function narrowPaths(parent,selected){
 if(!parent?.length)return structuredClone(selected??[]);if(!selected?.length)return structuredClone(parent);
 const ranks=['Arena','Initiative','Project'],result=[];
 for(const a of parent)for(const b of selected){const map=new Map(a.path.map(x=>x.split('/')));if(b.path.some(x=>{const[k,id]=x.split('/');return map.has(k)&&map.get(k)!==id;}))continue;for(const x of b.path){const[k,id]=x.split('/');map.set(k,id);}const path=ranks.filter(k=>map.has(k)).map(k=>k+'/'+map.get(k));const p={schema:'devgraph.resource-path.v1',path};if(!result.some(r=>JSON.stringify(r)===JSON.stringify(p)))result.push(p);}
 return result.sort((a,b)=>JSON.stringify(a.path).localeCompare(JSON.stringify(b.path)));
}
/** Grant validity is chosen explicitly and never inherits the credential timer. */
export function grantExpiry({choice,policyExpiresAt,customExpiresAt,now}){
 const expiresAt=choice==='policy'?policyExpiresAt:choice==='custom'?customExpiresAt:null;
 if(!Number.isSafeInteger(now)||!Number.isSafeInteger(policyExpiresAt)||!Number.isSafeInteger(expiresAt)||expiresAt<=now||expiresAt>policyExpiresAt)throw Error('invalid_expiry');
 return expiresAt;
}
export function validityView(ceiling){
 const v=['devgraph.access-draft.v5','devgraph.access-draft.v6'].includes(ceiling.schema)?ceiling.validity:{schema:'castalia.grant-validity.v1',mode:'dated',not_before:ceiling.not_before,not_after:ceiling.not_after};
 const fields=v?.mode==='dated'?['schema','mode','not_before','not_after']:['schema','mode','not_before'];
 if(!v||v.schema!=='castalia.grant-validity.v1'||!['dated','until_revoked'].includes(v.mode)||Object.keys(v).length!==fields.length||fields.some(k=>!Object.hasOwn(v,k))||!Number.isSafeInteger(v.not_before)||v.not_before<0||v.mode==='dated'&&(!Number.isSafeInteger(v.not_after)||v.not_after<=v.not_before))throw Error('invalid_expiry');
 return structuredClone(v);
}
export function chooseGrantValidity({choice,ceiling,customExpiresAt,now}){
 const parent=validityView(ceiling);
 if(!Number.isSafeInteger(now)||now<0||now<parent.not_before||parent.mode==='dated'&&now>=parent.not_after)throw Error('invalid_expiry');
 let validity;
 if(choice==='until_revoked'&&['devgraph.access-draft.v5','devgraph.access-draft.v6'].includes(ceiling.schema)&&parent.mode==='until_revoked')validity={schema:parent.schema,mode:'until_revoked',not_before:now};
 else{const end=choice==='policy'&&parent.mode==='dated'?parent.not_after:choice==='custom'?customExpiresAt:null;if(!Number.isSafeInteger(end)||end<=now||parent.mode==='dated'&&end>parent.not_after)throw Error('invalid_expiry');validity={schema:parent.schema,mode:'dated',not_before:now,not_after:end};}
 return validity;
}
export const validityLabel=value=>value?.mode==='until_revoked'?'Until revoked':'Expires '+new Date(value.not_after*1000).toLocaleString();
export function makeSelection({ceiling,ceilingDigest,recipient,mode='read',operations=[],workIds=[],arenaIds=[],arenaMetadataIds=[],workKinds=null,readOperations=null,resourcePaths=[],preset=null,expiresAt,validity=null,now}){
 const standing=['devgraph.access-draft.v5','devgraph.access-draft.v6'].includes(ceiling.schema);
 if(validity&&!standing)throw Error('validity_upgrade_required');
 if(!['read','write','both'].includes(mode))throw Error('invalid_expiry');
 if(standing){
  const parent=validityView(ceiling),child=validityView({schema:ceiling.schema,validity:validity??{schema:parent.schema,mode:'dated',not_before:now,not_after:expiresAt}});
  if(!Number.isSafeInteger(now)||now<0||child.not_before<parent.not_before||child.not_before>now||child.mode==='dated'&&child.not_after<=now||parent.mode==='dated'&&(child.mode!=='dated'||child.not_after>parent.not_after))throw Error('invalid_expiry');
  validity=child;
 }else if(!Number.isSafeInteger(expiresAt)||expiresAt<=now||expiresAt>ceiling.not_after)throw Error('invalid_expiry');
 workIds=resourceIds(workIds);
 if(workKinds!==null&&(!Array.isArray(workKinds)||workKinds.some(k=>!kinds.has(k))))throw Error('invalid_kind_selection');
 const readNames=new Set(['list','get','relationships','children','blockers']);
 if(readOperations!==null&&(!Array.isArray(readOperations)||readOperations.some(op=>!readNames.has(op))))throw Error('invalid_read_operation_selection');
 if(arenaIds.some(id=>typeof id!=='string'||!/^[a-z0-9][a-z0-9-]{0,255}$/.test(id)))throw Error('invalid_arena_selection');
 arenaIds=[...new Set(arenaIds)].sort();
 if(!Array.isArray(arenaMetadataIds)||arenaMetadataIds.length>256||arenaMetadataIds.some(id=>typeof id!=='string'||!/^[a-z0-9][a-z0-9-]{0,255}$/.test(id)))throw Error('invalid_arena_selection');
 const permittedArenaIds=new Set((ceiling.read_grants??[]).filter(g=>g.scope==='devgraph.arena.read').flatMap(g=>g.arena_ids));
 if(arenaMetadataIds.some(id=>!permittedArenaIds.has(id)))throw Error('arena_metadata_scope_unavailable');
 if(arenaIds.length&&mode!=='read'&&!['devgraph.access-draft.v3','devgraph.access-draft.v4','devgraph.access-draft.v5','devgraph.access-draft.v6'].includes(ceiling.schema))throw Error('arena_scoped_writes_unsupported');
 if(ceiling.subject_public_key&&ceiling.subject_public_key!==recipient.subject_public_key)throw Error('recipient_outside_policy');
 const base={...structuredClone(ceiling),subject_public_key:recipient.subject_public_key,previous_digest:ceilingDigest,...(standing?{validity}:{not_before:Math.max(now,ceiling.not_before),not_after:expiresAt})};
 if(resourcePaths.length&&!['devgraph.access-draft.v4','devgraph.access-draft.v5','devgraph.access-draft.v6'].includes(ceiling.schema))throw Error('path_scope_upgrade_required');
 const selected={};
 const constrain=g=>{const paths=narrowPaths(g.resource_paths,resourcePaths);if((g.resource_paths?.length||resourcePaths.length)&&!paths.length)return null;if(paths.length){g.resource_paths=paths;g.schema=Array.isArray(g.operations)?'devgraph.path-read-grant.v1':'devgraph.path-write-grant.v1';}return g;};
 if(arenaMetadataIds.length)preset=null;
 if(preset)base.preset=structuredClone(preset);else delete base.preset;
 if(mode!=='write'){
  const read={...base,schema:['devgraph.access-draft.v4','devgraph.access-draft.v5','devgraph.access-draft.v6'].includes(ceiling.schema)?ceiling.schema:'devgraph.access-draft.v2',installation_id:recipient.installation_id};delete read.write_grants;
  read.read_grants=(ceiling.read_grants??[]).map(raw=>{
   const g=structuredClone(raw);
   if(g.scope==='devgraph.arena.read'){g.arena_ids=g.arena_ids.filter(id=>arenaMetadataIds.includes(id));return g.arena_ids.length?g:null;}
   if(workKinds!==null){g.work_kinds=g.work_kinds.filter(kind=>workKinds.includes(kind));if(!g.work_kinds.length)return null;if(g.work_ids){g.work_ids=g.work_ids.filter(id=>g.work_kinds.includes(id.split('/')[0]));if(!g.work_ids.length)return null;}}
   if(readOperations!==null){g.operations=g.operations.filter(operation=>readOperations.includes(operation));if(!g.operations.length)return null;}
   if(workIds.length){g.work_ids=intersect(g.work_ids,workIds).filter(id=>g.work_kinds.includes(id.split('/')[0]));if(!g.work_ids.length)return null;}
   if(arenaIds.length){g.arena_ids=intersect(g.arena_ids,arenaIds);if(!g.arena_ids.length)return null;}
   return constrain(g);
  }).filter(Boolean);
  if(!read.read_grants.length)throw Error('read_scope_unavailable');selected.read=read;
 }
 if(mode!=='read'){
  if(ceiling.installation_id)throw Error('installation_scoped_writes_unsupported');
  const write={...base};delete write.read_grants;delete write.installation_id;
  write.write_grants=(ceiling.write_grants??[]).filter(g=>operations.includes(g.operation)).map(raw=>{
   const g=structuredClone(raw);
   if(workKinds!==null)g.resources=g.resources.filter(r=>workKinds.includes(r.kind));
   if(arenaIds.length){g.arena_ids=intersect(g.arena_ids,arenaIds);if(!g.arena_ids.length)return null;}
   if(workIds.length)g.resources=g.resources.map(r=>({...r,ids:intersect(r.ids,workIds.filter(id=>id.startsWith(r.kind+'/')).map(id=>id.slice(r.kind.length+1)))})).filter(r=>r.ids.length);
   if(resourcePaths.length||g.resource_paths?.length){
    // Missing unattached objects and provenance do not acquire a path by name.
    // Never advertise create authority that the receiver cannot enforce in-path.
    if(g.operation==='devgraph.work.create.v2')return null;
    g.resources=g.resources.filter(r=>['Initiative','Project','Issue','Task'].includes(r.kind));
   }
   return g.resources.length?constrain(g):null;
  }).filter(Boolean);
  if(!write.write_grants.length)throw Error('write_scope_unavailable');selected.write=write;
 }
 return selected;
}
export function selectionSummary(selection){
 const parts=[];
 if(selection.read){const grants=selection.read.read_grants;parts.push({title:'Read',expires_at:selection.read.not_after,validity:validityView(selection.read),binding:'This member and Wallet installation',operations:[...new Set(grants.flatMap(g=>g.scope==='devgraph.arena.read'?['Arena metadata']:g.operations))],resources:grants.map(g=>({operations:g.scope==='devgraph.arena.read'?['Read Arena metadata']:g.operations,types:g.scope==='devgraph.arena.read'?['Arena']:g.work_kinds,objects:g.scope==='devgraph.arena.read'?g.arena_ids.map(id=>'Arena/'+id):g.work_ids??'All matching current and future objects',arenas:g.arena_ids??'All permitted Arenas',archived:g.include_archived,paths:g.resource_paths??[]}))});}
 if(selection.write)parts.push({title:'Write',expires_at:selection.write.not_after,validity:validityView(selection.write),grants:selection.write.write_grants.map(g=>({operation:g.operation,resources:g.resources,arenas:g.arena_ids??'All permitted Arenas',paths:g.resource_paths??[]})),binding:'This member; not restricted to one installation',operations:selection.write.write_grants.map(g=>g.operation),resources:selection.write.write_grants.flatMap(g=>g.resources.map(r=>r.kind+'/'+(r.ids?.join(', ')??'all matching current and future objects')))});
 return parts;
}
