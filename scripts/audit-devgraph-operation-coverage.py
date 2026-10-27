"""Compare canonical DevGraph mutations with Transfer's current grant editor.

Read source and published ontology JSON only. Never import DevGraph, connect to a
service, inspect policy/Wallet data, or infer permission from an HTTP address.
The report distinguishes known gaps from operations actually selectable today.
"""
import argparse
import ast
import json
from pathlib import Path
import re
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument('--devgraph', type=Path, required=True)
parser.add_argument('--report', type=Path, required=True)
args = parser.parse_args()
source = args.devgraph.resolve()
origin = subprocess.check_output(['git', '-C', str(source), 'remote', 'get-url', 'origin'], text=True).strip()
if origin.removesuffix('.git') not in {'git@github.com:ZenithResearch/devgraph', 'https://github.com/ZenithResearch/devgraph'}:
    raise SystemExit('Select the canonical ZenithResearch/devgraph checkout.')


def literal_assignment(file, name):
    tree = ast.parse((source / file).read_text())
    return next(ast.literal_eval(n.value) for n in tree.body
                if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in n.targets))


legacy = literal_assignment('src/devgraph/work_requests.py', 'WORK_OPERATIONS')
# The producer explicitly replaces legacy status and appends its v2 operations.
tree = ast.parse((source / 'src/devgraph/work_requests.py').read_text())
v2 = next(n.value for n in tree.body if isinstance(n, ast.Assign)
          and any(isinstance(t, ast.Name) and t.id == 'WORK_OPERATIONS_V2' for t in n.targets))
if not (isinstance(v2, ast.BinOp) and isinstance(v2.op, ast.Add)
        and ast.unparse(v2.left) == "tuple((op for op in WORK_OPERATIONS if op != 'status'))"):
    raise SystemExit('The producer operation construction changed; review the audit adapter.')
work = sorted(set(legacy) - {'status'} | set(ast.literal_eval(v2.right)))
arena = literal_assignment('src/devgraph/arena_requests.py', 'ARENA_OPERATIONS')
transfer = Path(__file__).resolve().parents[1]
text = (transfer / 'Sources/ZenithTransfer/DevGraphPermissionCatalog.swift').read_text()
selected = re.findall(r'Action\("(devgraph\.[^"]+)"', text)
if len(set(selected)) != len(selected):
    raise SystemExit('Duplicate editor action mapping.')
editor = set(selected)
mutations = ['devgraph.work.' + op + '.v2' for op in work] + ['devgraph.arena.' + op + '.v1' for op in arena]
releases = source / 'src/devgraph/resources/ontology-releases'
latest = max((p for p in releases.iterdir() if (p / 'operations.json').is_file()), key=lambda p: tuple(map(int, p.name.removeprefix('v').split('.'))))
ontology = json.loads((latest / 'operations.json').read_text())
names = {op['name'] for op in ontology['operations']}
if not set(mutations) <= names:
    raise SystemExit('Runtime operations are missing from the latest ontology; reconcile before publication.')
report = {
    'schema': 'devgraph.native-grant-operation-audit.v1',
    'devgraph_revision': subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip(),
    'ontology_version': ontology['ontology_version'],
    'complete': set(mutations) <= editor,
    'work_write_operations': len(work), 'arena_write_operations': len(arena),
    'native_editor_write_operations': len(editor),
    'missing_native_editor_mutations': sorted(set(mutations) - editor),
    'mutations': [{'operation': op, 'selectable_when_admitted': op in editor} for op in mutations],
    'ontology_operations': ontology['operations'],
    'interpretation': 'Editor support does not establish owner admission, receiver support, or an active member grant. Ontology declarations do not establish deployment readiness.'
}
args.report.parent.mkdir(parents=True, exist_ok=True)
args.report.write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps({k: report[k] for k in ['complete', 'work_write_operations', 'arena_write_operations', 'native_editor_write_operations', 'missing_native_editor_mutations']}))
if set(mutations) != editor:
    raise SystemExit('Named mutation mapping drifted; review the provider adapter before publication.')
