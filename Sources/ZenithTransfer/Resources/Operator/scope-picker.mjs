const plain=value=>!!value&&Object.getPrototypeOf(value)===Object.prototype;
const ranks=['Arena','Initiative','Project'];
export function validPath(value){
 if(!plain(value)||value.schema!=='devgraph.resource-path.v1'||Object.keys(value).sort().join(',')!=='path,schema'||!Array.isArray(value.path)||!value.path.length||value.path.length>3)return false;
 let prior=-1;for(const anchor of value.path){if(typeof anchor!=='string'||!/^(Arena|Initiative|Project)\/[a-z0-9](?:[a-z0-9-]{0,254}[a-z0-9])?$/.test(anchor))return false;const rank=ranks.indexOf(anchor.split('/')[0]);if(rank<=prior)return false;prior=rank;}return true;
}
export function validateCatalog(value,origin){
 if(!plain(value)||value.schema!=='devgraph.access-catalog.v1'||value.receiver!==origin||typeof value.issuer!=='string'||!Number.isSafeInteger(value.revision)||value.revision<1||!/^[a-f0-9]{64}$/.test(value.catalog_digest_sha256)||!Array.isArray(value.presets)||value.presets.length>16||!Array.isArray(value.scopes??[])||(value.scopes??[]).length>2000)throw Error('invalid_access_catalog');
 const seen=new Set();for(const p of value.presets){if(!plain(p)||Object.keys(p).sort().join(',')!=='id,name,read_operations,version,write_operations'||typeof p.id!=='string'||!/^[a-z][a-z0-9-]{0,63}$/.test(p.id)||seen.has(p.id)||typeof p.name!=='string'||!p.name.length||p.name.length>80||!Number.isSafeInteger(p.version)||p.version<1||!Array.isArray(p.read_operations)||!Array.isArray(p.write_operations)||p.read_operations.length>5||p.write_operations.length>64||new Set(p.read_operations).size!==p.read_operations.length||new Set(p.write_operations).size!==p.write_operations.length||p.read_operations.some(op=>!['list','get','relationships','children','blockers'].includes(op))||p.write_operations.some(op=>typeof op!=='string'||!/^devgraph\.(?:work\.[a-z.]+\.v2|arena\.[a-z.]+\.v1)$/.test(op)||op.length>128))throw Error('invalid_access_catalog');seen.add(p.id);}
 if(new Set((value.scopes??[]).map(r=>r.resource)).size!==(value.scopes??[]).length)throw Error('invalid_access_catalog');
 for(const row of value.scopes??[])if(!plain(row)||Object.keys(row).sort().join(',')!=='parent,resource,resource_path,title'||!validPath(row.resource_path)||row.resource!==row.resource_path.path.at(-1)||typeof row.title!=='string'||row.title.length>4096)throw Error('invalid_access_catalog');
 return structuredClone(value);
}
export function preferenceFor(catalog,presetID,resourcePaths=[]){
 if(resourcePaths.length>16||new Set(resourcePaths.map(p=>JSON.stringify(p))).size!==resourcePaths.length||resourcePaths.some(p=>!validPath(p)||!(catalog.scopes??[]).some(r=>JSON.stringify(r.resource_path)===JSON.stringify(p))))throw Error('invalid_resource_path');
 const preset=catalog.presets.find(p=>p.id===presetID);
 if(presetID&&!preset)throw Error('preset_unavailable');
 return {catalog_digest_sha256:catalog.catalog_digest_sha256,id:preset?.id??null,version:preset?.version??null,...(resourcePaths.length?{resource_paths:structuredClone(resourcePaths)}:{})};
}
const make=(tag,text)=>{const node=document.createElement(tag);if(text!==undefined)node.textContent=text;return node;};
const same=(a,b)=>JSON.stringify(a.path)===JSON.stringify(b.path);
export const pathCovers=(parent,child)=>parent.path.every(anchor=>child.path.includes(anchor));
/** A union of subtree roots. Never discard a condition to manufacture a parent. */
export function normalizePaths(paths){
 if(paths.some(p=>!validPath(p)))throw Error('invalid_resource_path');
 const unique=paths.filter((p,i)=>!paths.slice(0,i).some(q=>same(p,q)));
 const result=unique.filter(p=>!unique.some(q=>!same(p,q)&&pathCovers(q,p)));
 if(result.length>16)throw Error('too_many_resource_paths');return structuredClone(result);
}
export function scopeTree(scopes){
 const nodes=scopes.map(row=>({...row,children:[]})),roots=[];
 for(const node of nodes){const parents=nodes.filter(p=>p!==node&&p.resource_path.path.length<node.resource_path.path.length&&p.resource_path.path.every((a,i)=>node.resource_path.path[i]===a));const parent=parents.sort((a,b)=>b.resource_path.path.length-a.resource_path.path.length)[0];(parent?parent.children:roots).push(node);}
 const sort=rows=>{rows.sort((a,b)=>a.title.localeCompare(b.title)||a.resource.localeCompare(b.resource));for(const row of rows)sort(row.children);};sort(roots);return roots;
}
export function pathLabel(path,scopes){return path.path.map(anchor=>{const row=scopes.find(r=>r.resource===anchor);return row?`${anchor.split('/')[0]}: ${row.title}`:anchor;}).join(' → ');}
const operationLabel=op=>({list:'List work',get:'Read details',relationships:'Read relationships',children:'Read children',blockers:'Read blockers',create:'Create work',patch:'Edit details','progress.set':'Change progress','parent.set':'Move work','dependency.add':'Add dependencies','dependency.remove':'Remove dependencies','blocker.add':'Add blockers','blocker.remove':'Remove blockers','workflow.assign':'Assign workflow','workflow.transition':'Transition workflow',archive:'Archive work',restore:'Restore work'})[op.replace(/^devgraph\.work\./,'').replace(/\.v2$/,'')]??op;
/** Shared requester/operator presentation; the existing signed path union is unchanged. */
export function mountScopePicker(element,{catalog,scopes=catalog.scopes??[],operator=false,presetID='',paths=[],onChange=()=>{}}){
 catalog=validateCatalog({...catalog,scopes},catalog.receiver);
 let selected=normalizePaths(paths),mode=paths.length?'path':'all',disposed=false,query='',lastValue=null;
 if(selected.some(p=>!scopes.some(r=>same(r.resource_path,p))))throw Error('invalid_resource_path');
 const wrapper=make('div');wrapper.className='scope-picker';
 const permissions=make('fieldset');permissions.append(make('legend','1. Permissions · What can they do?'));
 const roleLabel=make('label','Permission preset'),role=make('select');role.setAttribute('aria-label','Access preset');role.append(new Option(operator?'Custom permissions':'No preset · Operator chooses',''),...catalog.presets.map(p=>new Option(p.name,p.id)));role.value=presetID;roleLabel.append(role);permissions.append(roleLabel);
 permissions.append(make('p','Presets select operations. They do not select an Arena, Initiative or Project.'));
 const permissionSummary=make('p');permissionSummary.className='scope-permissions';permissions.append(permissionSummary);wrapper.append(permissions);
 const resources=make('fieldset');resources.append(make('legend','2. Resources · Where can they do it?'));
 const group='scope-'+crypto.randomUUID();
 const modes=make('div');modes.className='scope-mode';const radios={};
 for(const [id,label]of [['all',operator?'Global · All resources permitted by policy':'Global request · No path restriction'],['path','Selected areas · Choose one or more subtrees']]){
  const line=make('label'),input=make('input');input.type='radio';input.name=group;input.value=id;input.checked=mode===id;line.append(input,make('span',label));modes.append(line);radios[id]=input;input.onchange=()=>{mode=id;refresh();};
 }resources.append(modes);
 const globalHelp=make('p',operator?'Global adds no path filter. The owner’s policy, selected operations, object filters, validity and revocation still apply. A restricted policy remains restricted.':'This requests no path restriction. The operator still chooses and approves the exact scope; requesting global access grants nothing.');resources.append(globalHelp);
 const chooser=make('div');chooser.className='scope-chooser';
 const searchLabel=make('label','Find resources'),search=make('input');search.type='search';search.setAttribute('aria-label','Find resources');search.placeholder='Search titles, kinds or IDs';searchLabel.append(search);chooser.append(searchLabel);
 const help=make('p','Select any combination of Arenas, Initiatives and Projects. A checked container includes everything beneath it at each access, including future descendants. Moved-out resources lose access. To narrow an inherited branch, clear its selected ancestor first.');chooser.append(help);
 const tree=make('ul');tree.className='scope-tree';tree.setAttribute('aria-label','Resource hierarchy');chooser.append(tree);
 const error=make('p');error.className='scope-selection-error';error.setAttribute('role','status');chooser.append(error);
 const selectedHeading=make('h4','Selected roots'),chips=make('ul');chips.className='scope-selected';chooser.append(selectedHeading,chips);resources.append(chooser);wrapper.append(resources);
 const summary=make('p');summary.className='scope-picker-summary';summary.setAttribute('aria-live','polite');wrapper.append(summary);element.replaceChildren(wrapper);
 const roots=scopeTree(scopes),expanded=new Set();
 for(const row of scopes)if(row.resource.startsWith('Arena/')||selected.some(p=>pathCovers(row.resource_path,p)))expanded.add(row.resource);
 function value(){return {presetID:role.value,paths:mode==='path'?structuredClone(selected):[],all:mode==='all'};}
 function emit(){if(disposed)return;const v=value(),preset=catalog.presets.find(p=>p.id===v.presetID);
  permissionSummary.textContent=preset?[...preset.read_operations,...preset.write_operations].map(operationLabel).join(' · '):operator?'Choose the exact operations below.':'The operator will choose the operations.';
  summary.textContent=(preset?.name??(operator?'Custom permissions':'Operator chooses permissions'))+' · '+(v.all?(operator?'Global within operator policy':'Global requested · operator approves exact scope'):v.paths.length?v.paths.map(p=>pathLabel(p,scopes)).join('; '):'No areas selected');const signature=JSON.stringify(v);if(signature!==lastValue){lastValue=signature;onChange(v);}
 }
 function refresh(){
  radios.all.checked=mode==='all';radios.path.checked=mode==='path';chooser.hidden=mode!=='path';globalHelp.hidden=mode!=='all';tree.replaceChildren();chips.replaceChildren();
  const matches=row=>!query||`${row.title} ${row.resource}`.toLocaleLowerCase().includes(query);
  const visible=row=>matches(row)||row.children.some(visible);
  function draw(rows,parent){for(const row of rows){if(!visible(row))continue;
   const item=make('li'),line=make('div');line.className='scope-node';item.dataset.resource=row.resource;
   const children=make('ul'),isOpen=!!query||expanded.has(row.resource);children.hidden=!isOpen;
   if(row.children.length){const toggle=make('button',isOpen?'▾':'▸');toggle.type='button';toggle.className='scope-disclosure secondary';toggle.setAttribute('aria-label',(isOpen?'Collapse ':'Expand ')+row.resource.split('/')[0]+': '+row.title);toggle.setAttribute('aria-expanded',String(isOpen));toggle.onclick=()=>{expanded.has(row.resource)?expanded.delete(row.resource):expanded.add(row.resource);refresh();};line.append(toggle);}else{const spacer=make('span');spacer.className='scope-disclosure-space';line.append(spacer);}
   const label=make('label'),check=make('input');check.type='checkbox';check.setAttribute('aria-label',row.resource.split('/')[0]+': '+row.title);const own=selected.some(p=>same(p,row.resource_path)),ancestor=selected.find(p=>!same(p,row.resource_path)&&pathCovers(p,row.resource_path));check.checked=own||!!ancestor;check.disabled=!!ancestor;check.dataset.scopeInherited=String(!!ancestor);
   const caption=make('span');caption.className='scope-caption';caption.append(make('strong',row.title),make('small',row.resource));if(ancestor)caption.append(make('small','Inherited from '+pathLabel(ancestor,scopes)));else caption.append(make('small','Includes this '+row.resource.split('/')[0]+' and its descendants'));label.append(check,caption);line.append(label);item.append(line);
   check.onchange=()=>{if(ancestor){refresh();return;}try{selected=normalizePaths(check.checked?[...selected,row.resource_path]:selected.filter(p=>!same(p,row.resource_path)));error.textContent='';refresh();}catch{check.checked=false;error.textContent='Select up to 16 separate areas. Choose a common parent to include more.';}};
   draw(row.children,children);if(row.children.length)item.append(children);parent.append(item);
  }}draw(roots,tree);
  if(!tree.children.length)tree.append(make('li',scopes.length?'No matching resources.':'No resources are published for selection. The operator can still review a general request.'));
  for(const p of selected){const row=make('li'),text=make('span',pathLabel(p,scopes)),remove=make('button','Remove');remove.type='button';remove.className='secondary';remove.setAttribute('aria-label','Remove '+pathLabel(p,scopes));remove.onclick=()=>{selected=selected.filter(q=>!same(q,p));error.textContent='';refresh();};row.append(text,remove);chips.append(row);}
  selectedHeading.textContent=`Selected roots (${selected.length}/16)`;emit();
 }
 role.onchange=emit;search.oninput=()=>{query=search.value.trim().toLocaleLowerCase();refresh();};refresh();
 return {value,dispose(){disposed=true;element.replaceChildren();}};
}
