// Producer-parity vectors for the Swift credential editor. Run with --check in CI.
import {makeSelection} from '../Sources/ZenithTransfer/Resources/Operator/access/core.mjs';
import {readFileSync,writeFileSync} from 'node:fs';
const path=new URL('../Tests/ZenithTransferTests/Fixtures/native-grants.json',import.meta.url);
const subject='a'.repeat(64),installation='b'.repeat(32),now=1800000000,digest='c'.repeat(64);
const recipient={request_id:'d'.repeat(32),subject_public_key:subject,installation_id:installation,request_digest_sha256:'e'.repeat(64),version:1};
const read=(kinds,ids)=>({scope:'devgraph.work.read',operations:['list','get','relationships'],relationship_types:['parent','children'],work_kinds:kinds,...(ids?{work_ids:ids}:{}),include_archived:false});
const write=(operation,kinds)=>({operation:'devgraph.work.'+operation+'.v2',resources:kinds.map(kind=>({kind}))});
const base={schema:'devgraph.access-draft.v5',issuer:'fixture',receiver:'https://fixture.example',write_audience:'devgraph://receiver-local',lifetime_seconds:300,validity:{schema:'castalia.grant-validity.v1',mode:'until_revoked',not_before:1},read_grants:[read(['Project','Task'])],write_grants:[write('create',['Project','Task']),write('patch',['Project','Task']),write('progress.set',['Task'])]};
const branch=(...path)=>({schema:'devgraph.resource-path.v1',path});
const cases=[];
function add(name,ceiling,{paths=[],reads=['list','get'],writes=[],kinds=['Project','Task'],arenas=[],end=null}={}) {
 const validity={schema:'castalia.grant-validity.v1',mode:end?'dated':'until_revoked',not_before:now,...(end?{not_after:end}:{})};
 const expected=makeSelection({ceiling,ceilingDigest:digest,recipient,mode:reads.length||arenas.length?(writes.length?'both':'read'):'write',operations:writes,readOperations:reads,workKinds:kinds,resourcePaths:paths,arenaMetadataIds:arenas,validity,now});
 cases.push({name,ceiling,digest,recipient,now,paths,reads,writes,kinds,arenas,end,expected});
}
add('explicit global mixed standing',base,{writes:['devgraph.work.patch.v2','devgraph.work.create.v2']});
add('multiple branches exclude path creation',base,{paths:[branch('Arena/a','Project/p'),branch('Arena/b','Initiative/i')],writes:['devgraph.work.create.v2','devgraph.work.patch.v2','devgraph.work.progress.set.v2']});
const correlated={...base,read_grants:[read(['Project'],['Project/p']),read(['Task'],['Task/t'])]};
correlated.read_grants[0].operations=['get'];correlated.read_grants[0].arena_ids=['a'];correlated.read_grants[1].operations=['list'];correlated.read_grants[1].arena_ids=['b'];
add('correlated rules retain IDs arenas and operations',correlated);
const constrained={...base,validity:{schema:'castalia.grant-validity.v1',mode:'dated',not_before:1,not_after:now+1000},read_grants:[{...read(['Task']),schema:'devgraph.path-read-grant.v1',resource_paths:[branch('Arena/a')]}]};
add('parent intersection and finite validity',constrained,{paths:[branch('Arena/a','Initiative/i','Project/p')],kinds:['Task'],end:now+500});
const arena={...base,schema:'devgraph.access-draft.v6',read_grants:[...base.read_grants,{scope:'devgraph.arena.read',arena_ids:['a','b']}]};
add('explicit Arena metadata with independent Work branch',arena,{paths:[branch('Arena/a')],arenas:['a']});
add('Arena metadata alone grants no Work',arena,{reads:[],kinds:[],arenas:['b']});
const content=JSON.stringify(cases,null,2)+'\n';
if(process.argv.includes('--check')) { if(readFileSync(path,'utf8')!==content)throw Error('Producer fixture drift'); }
else writeFileSync(path,content);
console.log(cases.length+' native grant parity vectors verified');
