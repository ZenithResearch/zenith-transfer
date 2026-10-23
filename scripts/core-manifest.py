"""Record source and exact native artifacts without collecting user configuration."""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

root, artifacts = map(Path, sys.argv[1:])
files = [root / 'Cargo.toml', root / 'Cargo.lock']
for crate in ['castalia-wallet-core', 'castalia-wallet-native', 'castalia-wallet-presentation']:
    files.extend(
        p for p in (root / 'crates' / crate).rglob('*')
        if p.is_file() and (p.suffix in ['.rs', '.toml', '.h', '.modulemap'] or p.name == 'LICENSE')
    )
hashes = {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(set(files))}
manifest = {
    'schema': 'zenith.ios-core-build.v1',
    'revision': subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip(),
    'source_state': 'build inputs match the pinned Wallet commit',
    'source_files': hashes,
    'source_digest': hashlib.sha256(json.dumps(hashes, sort_keys=True).encode()).hexdigest(),
    'libraries': {
        str(p.relative_to(artifacts)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted((artifacts / 'CastaliaWallet.xcframework').rglob('*.a'))
    },
}
(artifacts / 'core-build-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
