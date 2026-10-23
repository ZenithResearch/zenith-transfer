from pathlib import Path
import hashlib,json,subprocess,sys
source=Path(sys.argv[1]).resolve()
static=source/'src/devgraph/frontend/static';out=Path(__file__).resolve().parents[1]/'Sources/ZenithTransfer/Resources/Operator';(out/'access').mkdir(parents=True,exist_ok=True)
files={'access/app.mjs':'access/app.mjs','access/client.mjs':'access/client.mjs','access/core.mjs':'access/core.mjs','access/policy.mjs':'access/policy.mjs','access/style.css':'access/style.css','credential-v2/scope-picker.mjs':'scope-picker.mjs','topology/theme.js':'theme.js','topology/zenith-tokens.css':'zenith-tokens.css'}
manifest={'source_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=source,text=True).strip(),'source_files':{},'adaptations':['native bridge identity, proof and HTTP transport','native pending-action storage and SHA-256','bundle-relative imports and strict offline CSP']}
for original,target in files.items():
 data=(static/original).read_text();manifest['source_files'][original]=hashlib.sha256(data.encode()).hexdigest()
 if original=='access/app.mjs':
  old='new AccessOperatorClient({wallet})';assert old in data;data=data.replace(old,'new AccessOperatorClient({wallet,fetchImpl:ZenithOperator.fetch,storage:ZenithOperator.storage,origin:ZenithOperator.origin})')
  data=data.replace("'/assets/credential-v2/scope-picker.mjs'","'../scope-picker.mjs'")
 if original=='access/client.mjs':
  data=data.replace("const id=()=>crypto.randomUUID().replaceAll('-','');","const id=()=>[...crypto.getRandomValues(new Uint8Array(16))].map(v=>v.toString(16).padStart(2,'0')).join('');")
  old="const sha=async value=>[...new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(stable(value))))].map(v=>v.toString(16).padStart(2,'0')).join('');"
  assert old in data;data=data.replace(old,"const sha=value=>ZenithOperator.call('hash',{text:stable(value)});")
 (out/target).write_text(data)
s=(static/'access/index.html').read_text();manifest['source_files']['access/index.html']=hashlib.sha256(s.encode()).hexdigest()
s=s.replace('<script src="/monitor/topology-assets/wallet-access.js"></script>','')
s=s.replace('<link rel="stylesheet" href="/monitor/topology-assets/wallet-access.css">','')
s=s.replace('/monitor/topology-assets/','/').replace('/monitor/access-assets/','/access/')
s=s.replace('<head>','<head><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; script-src \'self\'; style-src \'self\' \'unsafe-inline\'; img-src \'self\' data:; connect-src \'none\'; frame-src \'none\'; base-uri \'none\'; form-action \'none\'">')
s=s.replace('<a href="/monitor">← Work monitor</a>','<span>Native Castalia Wallet · DevGraph operator</span>')
s=s.replace('__WALLET_CONNECTION__','<div id="wallet-read-connection">Uses the unlocked Castalia Wallet in Transfer. The server verifies your operator authority.</div>')
(out/'index.html').write_text(s);(out/'provenance.json').write_text(json.dumps(manifest,indent=2)+'\n')
