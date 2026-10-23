const plain=v=>!!v&&Object.getPrototypeOf(v)===Object.prototype;
const id=()=>[...crypto.getRandomValues(new Uint8Array(16))].map(v=>v.toString(16).padStart(2,'0')).join('');
const sha=value=>ZenithOperator.call('hash',{text:stable(value)});
const stable=v=>v===null||typeof v!=='object'?JSON.stringify(v):Array.isArray(v)?'['+v.map(stable).join(',')+']':'{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+stable(v[k])).join(',')+'}';
export class AccessOperatorClient{
 constructor({wallet,fetchImpl=fetch,storage=globalThis.sessionStorage,origin=location.origin,now=()=>Math.floor(Date.now()/1000)}={}){
  Object.assign(this,{wallet,fetchImpl,storage,origin,now,pending:null,state:'idle'});
  this.key='devgraph.operator-pending.v1:'+origin;
  const saved=storage?.getItem(this.key);
  if(saved){try{const p=JSON.parse(saved);if(!plain(p)||p.schema!=='devgraph.operator-pending.v1'||p.origin!==origin||!plain(p.action)||!/^[a-f0-9]{32}$/.test(p.action.action_id))throw Error();this.pending=p;this.state=p.dispatched===false?'idle':'unknown';}catch{throw Error('invalid_recovery_record');}}
 }
 async post(path,body){
  const fetchImpl=this.fetchImpl;const response=await fetchImpl(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body),credentials:'omit',redirect:'error',cache:'no-store',referrerPolicy:'no-referrer'});
  const result=await response.json();if(!response.ok)throw Object.assign(Error(result.error??'access_request_failed'),{status:response.status});return result;
 }
 persist(){if(!this.storage)throw Error('recovery_storage_required');this.storage.setItem(this.key,JSON.stringify(this.recovering?this.original:this.pending));}
 get approvalExpired(){return Number.isSafeInteger(this.challenge?.expires_at)&&this.now()>=this.challenge.expires_at;}
 async refreshPrepared(){
  // Renew only an unsigned challenge, never the action, selection or recovery target.
  if(this.state!=='prepared'||!this.pending||this.pending.dispatched)throw Error('prepare_operator_action_first');
  const identity=this.wallet.requestIdentity;
  if(!identity||stable(identity)!==stable(this.pending.identity))throw Error('wallet_connection_required');
  const action=this.pending.action;
  const challenge=await this.post('/devgraph/access-operator/v1/challenges',{...identity,action});
  if(!plain(challenge)||challenge.schema!=='castalia.access-request-challenge.v1'||challenge.receiver!==this.origin||challenge.subject_public_key!==identity.subject_public_key||challenge.installation_id!==identity.installation_id||stable(challenge.details?.action)!==stable(action)||!Number.isSafeInteger(challenge.expires_at)||challenge.expires_at<=this.now())throw Error('invalid_operator_challenge');
  this.challenge=challenge;return challenge;
 }
 cancelPrepared(){
  if(this.state!=='prepared'||this.recovering||!this.pending||this.pending.dispatched)throw Error('recover_original_action_first');
  this.storage.removeItem(this.key);this.pending=null;this.challenge=null;this.state='idle';
 }
 async prepare(action){
  if(this.state==='unknown')throw Error('recover_original_action_first');
  const identity=this.wallet.requestIdentity;if(!identity)throw Error('wallet_connection_required');
  const request={schema:'devgraph.access-operator-action.v1',action_id:id(),...structuredClone(action)};
  const challenge=await this.post('/devgraph/access-operator/v1/challenges',{...identity,action:request});
  if(!plain(challenge)||challenge.schema!=='castalia.access-request-challenge.v1'||challenge.receiver!==this.origin||challenge.subject_public_key!==identity.subject_public_key||challenge.installation_id!==identity.installation_id||stable(challenge.details?.action)!==stable(request))throw Error('invalid_operator_challenge');
  this.pending={schema:'devgraph.operator-pending.v1',origin:this.origin,identity,action:request,assignment_digest:request.selection?.read&&request.selection?.write&&['devgraph.access-operator-action.v5','devgraph.access-operator-action.v7'].includes(request.schema)?await sha(request.selection):['devgraph.access-operator-action.v3','devgraph.access-operator-action.v5','devgraph.access-operator-action.v7'].includes(request.schema)&&request.selection?.write?await sha(request.selection.write):['devgraph.access-operator-action.v2','devgraph.access-operator-action.v4','devgraph.access-operator-action.v6'].includes(request.schema)&&request.selection?.read?await sha(request.selection.read):null,dispatched:false};this.challenge=challenge;this.persist();this.state='prepared';return challenge;
 }
 approve(){
  if(this.state!=='prepared')throw Error('prepare_operator_action_first');
  if(this.approvalExpired)throw Error('operator_approval_expired');
  const challenge=this.challenge;
  // Start Wallet within the click gesture, before awaiting any network call.
  const consent=this.wallet.approveAccess(challenge);
  return consent.then(async approval=>{
   this.state='unknown';this.pending.dispatched=true;this.persist();
   let result;try{result=await this.post('/devgraph/access-operator/v1/actions',{challenge:approval.challenge,signature:approval.signature});}catch(error){if(!this.recovering&&[400,401,409].includes(error.status)&&['invalid_operator_selection','operator_access_denied','operator_request_changed','operator_assignment_changed','write_activation_unavailable','write_activation_upgrade_required','native_admission_required','mixed_activation_unavailable','activation_unavailable','activation_upgrade_required'].includes(error.message)){this.storage.removeItem(this.key);this.pending=null;this.challenge=null;this.state='idle';throw error;}throw Object.assign(Error('operator_outcome_unknown'),{cause:error});}
   return this.accept(result);
  });
 }
 accept(result){
  if(!plain(result)||!['devgraph.access-operator-result.v1','devgraph.access-operator-result.v2'].includes(result.schema)||result.action_id!==this.pending.action.action_id||result.authority_issued!==false)throw Error('operator_outcome_unknown');
  if(this.recovering){
   if(result.original_action_id!==this.original.action.action_id||result.status!=='reconciled'||!plain(result.result)||result.result.action_id!==this.original.action.action_id){this.pending=this.original;this.recovering=false;this.state='unknown';this.persist();throw Error('operator_outcome_unknown');}
   result=result.result;
  }
  const action=this.recovering?this.original.action:this.pending.action;
  const expectedAssignment=(this.recovering?this.original:this.pending).assignment_digest;
  const valid=action.action==='inbox'?plain(result.inbox)&&Array.isArray(result.inbox.items)&&Number.isSafeInteger(result.inbox.total)&&result.inbox.total>=result.inbox.items.length&&['devgraph.access-draft.v2','devgraph.access-draft.v3','devgraph.access-draft.v4','devgraph.access-draft.v5'].includes(result.ceiling?.schema)&&/^[a-f0-9]{64}$/.test(result.ceiling_digest_sha256):action.action==='review'?result.request_id===action.request_id&&result.review_id===action.action_id&&result.expected_version===action.expected_version&&result.request_digest_sha256===action.request_digest_sha256&&/^[a-f0-9]{64}$/.test(result.selection_digest_sha256)&&plain(result.selection)&&stable(result.selection)===stable(action.selection)&&plain(result.plans)&&(!['devgraph.access-operator-action.v2','devgraph.access-operator-action.v3','devgraph.access-operator-action.v4','devgraph.access-operator-action.v5','devgraph.access-operator-action.v6','devgraph.access-operator-action.v7'].includes(action.schema)||result.plans.activation?.assignment_digest===expectedAssignment):action.action==='revoke'?result.request_id===action.request_id&&result.version===3&&result.status==='revoked'&&result.activation?.active===false&&result.activation.assignment_digest===action.previous_assignment_digest&&(!Object.hasOwn(action,'previous_write_assignment_digest')||result.activation.write_assignment_digest===action.previous_write_assignment_digest)&&result.request_digest_sha256===action.request_digest_sha256:action.action==='approve'&&['devgraph.access-operator-action.v2','devgraph.access-operator-action.v3','devgraph.access-operator-action.v4','devgraph.access-operator-action.v5','devgraph.access-operator-action.v6','devgraph.access-operator-action.v7'].includes(action.schema)?result.request_id===action.request_id&&result.version===2&&result.status==='active'&&result.activation?.active===true&&result.activation.credential_issued===false&&result.activation.assignment_digest===expectedAssignment&&result.request_digest_sha256===action.request_digest_sha256:['approve','deny'].includes(action.action)?result.request_id===action.request_id&&result.version===2&&result.status===(action.action==='approve'?'approved_pending_activation':'denied'):false;
  if(!valid||result.authority_issued!==false)throw Error('operator_outcome_unknown');
  this.storage.removeItem(this.key);this.pending=null;this.challenge=null;this.recovering=false;this.state='idle';return result;
 }
 async prepareRecovery(){
  if(this.state!=='unknown'||!this.pending)throw Error('no_unknown_action');
  const original=structuredClone(this.recovering?this.original:this.pending);this.state='idle';this.original=original;this.recovering=true;
  try{await this.prepare({action:'status',original_action_id:original.action.action_id});}
  catch(error){this.pending=original;this.state='unknown';this.recovering=false;this.persist();throw error;}
 }
}
