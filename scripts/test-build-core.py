"""Exercise public build behavior with isolated source and tool stubs."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


class PublicCoreBuildTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.app = self.root / "transfer"
        self.wallet = self.root / "wallet"
        self.bin = self.root / "bin"
        for folder in [self.app / "scripts", self.wallet, self.bin]:
            folder.mkdir(parents=True)
        scripts = Path(__file__).resolve().parent
        for name in ["build-core.sh", "core-manifest.py"]:
            shutil.copy2(scripts / name, self.app / "scripts" / name)
        (self.wallet / "Cargo.toml").write_text("[workspace]\n")
        (self.wallet / "Cargo.lock").write_text("version = 4\n")
        subprocess.run(["git", "init", "-q", str(self.wallet)], check=True)
        self.git("add", ".")
        self.git("-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "fixture")
        revision = self.git("rev-parse", "HEAD").stdout.strip()
        (self.app / "Dependencies.json").write_text(json.dumps({"wallet": {"revision": revision}}))
        self.log = self.root / "cargo-calls.jsonl"
        self.env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ["PATH"],
                        BUILD_TEST_ROOT=str(self.root), BUILD_TEST_LOG=str(self.log))
        self.env.pop("ZENITH_CARGO_OFFLINE", None)
        self.tool("cargo", '''import json, os, pathlib, sys
root = pathlib.Path(os.environ["BUILD_TEST_ROOT"])
with open(os.environ["BUILD_TEST_LOG"], "a") as log: log.write(json.dumps(sys.argv[1:]) + "\\n")
if "metadata" in sys.argv: print(json.dumps({"target_directory": str(root / "target")}))
elif "--offline" in sys.argv and not os.environ.get("BUILD_TEST_CACHE_WARM"): sys.exit("dependency missing from cold cache")
else:
    library = root / "target/aarch64-apple-darwin/release/libcastalia_wallet_native.a"
    library.parent.mkdir(parents=True, exist_ok=True)
    library.write_bytes(b"fixture archive")
''')
        self.tool("xcodebuild", '''import pathlib, sys
pathlib.Path(sys.argv[sys.argv.index("-output") + 1]).mkdir()
''')

    def git(self, *args):
        return subprocess.run(["git", "-C", str(self.wallet), *args], check=True, text=True, capture_output=True)

    def tool(self, name, code):
        path = self.bin / name
        path.write_text("#!/usr/bin/env python3\n" + code)
        path.chmod(0o755)

    def build(self):
        return subprocess.run(["bash", str(self.app / "scripts/build-core.sh"), str(self.wallet)],
                              env=self.env, text=True, capture_output=True)

    def test_fresh_build_can_fetch_locked_dependencies(self):
        result = self.build()
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = [json.loads(line) for line in self.log.read_text().splitlines()]
        self.assertTrue(all("--locked" in call for call in calls))
        self.assertTrue(all("--offline" not in call for call in calls))

    def test_offline_mode_is_explicit_and_preserves_locked_resolution(self):
        self.env.update(ZENITH_CARGO_OFFLINE="1", BUILD_TEST_CACHE_WARM="1")
        result = self.build()
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = [json.loads(line) for line in self.log.read_text().splitlines()]
        self.assertTrue(all("--offline" in call and "--locked" in call for call in calls))

    def test_wrong_revision_stops_before_cargo_or_artifact_replacement(self):
        (self.app / "Dependencies.json").write_text(json.dumps({"wallet": {"revision": "0" * 40}}))
        self.assertNotEqual(self.build().returncode, 0)
        self.assertFalse(self.log.exists())
        self.assertFalse((self.app / "Artifacts").exists())

    def test_modified_input_stops_before_cargo(self):
        (self.wallet / "Cargo.toml").write_text("changed input\n")
        self.assertNotEqual(self.build().returncode, 0)
        self.assertFalse(self.log.exists())


if __name__ == "__main__":
    unittest.main()
