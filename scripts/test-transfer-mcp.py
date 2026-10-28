"""Dependency-free tests. No live provider, Wallet, enrollment or signing."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "Sources/ZenithTransfer/Resources/MCP/transfer_mcp.py"
spec = importlib.util.spec_from_file_location("transfer_mcp", SCRIPT)
mcp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mcp)
FIXTURES = json.loads((ROOT / "Tests/ZenithKitTests/Fixtures/session-access-review-v1.json").read_bytes())


class MCPBridgeTests(unittest.TestCase):
    def test_raw_json_rejects_duplicate_escaped_key_floats_and_large_numbers(self):
        for raw in [b'{"x":1,"\\u0078":2}', b'{"x":1.0}', b'{"x":1e0}', b'{"x":NaN}', b'{"x":9007199254740992}']:
            with self.subTest(raw=raw), self.assertRaises(Exception):
                mcp.loads(raw)
        self.assertEqual(mcp.loads(b'{"constraint":-1}'), {"constraint": -1})

    def test_nesting_and_byte_limits(self):
        for raw in [b"[" * 26 + b"0" + b"]" * 26, b" " * (mcp.MAX + 1), b"[" + b"0," * 256 + b"0]"]:
            with self.assertRaises(Exception):
                mcp.loads(raw)

    def test_no_approve_sign_seed_or_export_tool(self):
        names = {value["name"] for value in mcp.TOOLS}
        self.assertEqual(names, {"list_wallet_services", "request_session_credential", "get_session_credential_status", "call_service_with_session_credential"})
        for tool in mcp.TOOLS:
            self.assertFalse(tool["inputSchema"]["additionalProperties"])

    def test_public_output_whitelist_rejects_extra_crypto_and_nonissued_handles(self):
        for result in FIXTURES["results"]:
            self.assertEqual(mcp.public_result(result), result)
        for result in FIXTURES["invalid_results"]:
            # Identity substitutions are checked by the native retained review,
            # not this transport-only whitelist. Extra credentials are rejected.
            value = result["result"]
            if value["state"] != "issued" and value["credential_handle"] is not None:
                with self.assertRaises(Exception):
                    mcp.public_result(value)
        issued = next(copy.deepcopy(r) for r in FIXTURES["results"] if r["state"] == "issued")
        for field in ["proof", "signature", "grant", "private_key", "seed", "token"]:
            value = dict(issued, **{field: "must-not-leave-broker"})
            with self.assertRaises(Exception):
                mcp.public_result(value)

    def test_client_identity_and_transport_target_not_model_arguments(self):
        for extra in ["client_id", "token", "endpoint", "profile_file", "executable", "approve"]:
            with self.assertRaises(Exception):
                mcp.call_tool(Path("unused"), {"name": "get_session_credential_status", "arguments": {"request_handle": "example", extra: "untrusted"}})

    def test_request_idempotency_is_stable_for_this_process(self):
        seen = []
        original = mcp.exchange
        try:
            mcp.exchange = lambda directory, method, args: seen.append((method, args))
            args = {"service": "urn:example:service", "permissions": [{"operation": "read"}], "purpose": "Read one object", "session_label": "Example"}
            for _ in range(2):
                mcp.call_tool(Path("unused"), {"name": "request_session_credential", "arguments": args})
            self.assertEqual(seen[0][1]["request_id"], seen[1][1]["request_id"])
            self.assertNotIn("client_id", seen[0][1])
        finally:
            mcp.exchange = original

    def test_control_and_bidi_text_is_rejected(self):
        for text in ["Bad\nlabel", "Bad\u202elabel", "Bad\u2066label", "Bad\x7flabel"]:
            with self.assertRaises(Exception):
                mcp.text(text)
        self.assertEqual(mcp.text("작업 👩🏽‍💻"), "작업 👩🏽‍💻")

    def test_private_token_rejects_symlink_hardlink_and_broad_permissions(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            target = root / "token"
            target.write_text("ab" * 32)
            target.chmod(0o600)
            self.assertEqual(mcp.private_file(target), ("ab" * 32).encode())
            link = root / "symlink"
            link.symlink_to(target)
            with self.assertRaises(Exception):
                mcp.private_file(link)
            hard = root / "hardlink"
            hard.hardlink_to(target)
            with self.assertRaises(Exception):
                mcp.private_file(target)
            hard.unlink()
            target.chmod(0o644)
            with self.assertRaises(Exception):
                mcp.private_file(target)

    def test_actual_stdio_protocol_and_unavailable_broker_keep_secrets_out(self):
        with tempfile.TemporaryDirectory() as root:
            messages = [
                {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26"}},
                {"jsonrpc": "2.0", "method": "notifications/initialized"},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
                {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "list_wallet_services", "arguments": {}, "_meta": {"progressToken": 1}}},
                {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "sign", "arguments": {"password": "DO-NOT-ECHO"}}},
            ]
            output = subprocess.run([sys.executable, "-I", str(SCRIPT), "--broker-directory", root], input=b"".join(mcp.encoded(m) + b"\n" for m in messages), capture_output=True, timeout=5, check=True)
            rows = [json.loads(line) for line in output.stdout.splitlines()]
            self.assertEqual(len(rows), 4)
            self.assertEqual(rows[0]["result"]["protocolVersion"], "2025-03-26")
            self.assertTrue(rows[2]["result"]["isError"])
            self.assertTrue(rows[3]["result"]["isError"])
            self.assertNotIn(b"DO-NOT-ECHO", output.stdout + output.stderr)
            self.assertEqual(output.stderr, b"")


if __name__ == "__main__":
    unittest.main()
