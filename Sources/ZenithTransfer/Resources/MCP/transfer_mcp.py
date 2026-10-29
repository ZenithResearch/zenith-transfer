#!/usr/bin/env python3
"""Local review/scoped-call bridge. Never stores Wallet keys or approves."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
import sys
import uuid

MAX = 65536
SAFE = 9007199254740991
VERSIONS = {"2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"}
CLIENT = uuid.uuid4().hex  # This MCP process, never a model-provided identity.
STATES = {"prepared", "awaiting_human", "submitting", "issued", "denied", "cancelled", "expired", "revoked", "outcome_unknown"}
RESULT_KEYS = {"schema", "request_handle", "request_id", "review_digest_sha256", "provider_service", "holder_public_key", "state", "credential_handle", "expires_at", "reconcile_required"}


class ClosedError(ValueError):
    pass


def require(value):
    if not value:
        raise ClosedError("wallet_review_unavailable")


def pairs(items):
    value = {}
    for key, item in items:
        require(key not in value and len(value) < 256)
        value[key] = item
    return value


def integer(value):
    number = int(value)
    require(abs(number) <= SAFE)
    return number


def reject(_):
    raise ClosedError("invalid_json")


def check_shape(value, depth=0):
    require(depth <= 24)
    if isinstance(value, dict):
        require(len(value) <= 256)
        for item in value.values():
            check_shape(item, depth + 1)
    elif isinstance(value, list):
        require(len(value) <= 256)
        for item in value:
            check_shape(item, depth + 1)


def loads(raw):
    require(len(raw) <= MAX)
    value = json.loads(raw, object_pairs_hook=pairs, parse_int=integer, parse_float=reject, parse_constant=reject)
    check_shape(value)
    return value


def encoded(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def text(value, length=512):
    require(isinstance(value, str) and 0 < len(value) <= length)
    require(not any(ord(c) < 32 or 127 <= ord(c) <= 159 or ord(c) in {0x61C, 0x200E, 0x200F, *range(0x202A, 0x202F), *range(0x2066, 0x206A)} for c in value))
    return value


def private_file(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_mode & 0o077 == 0 and info.st_nlink == 1)
        raw = os.read(fd, 129)
        require(len(raw) <= 128)
        return raw
    finally:
        os.close(fd)


def receive(connection, size):
    data = bytearray()
    while len(data) < size:
        chunk = connection.recv(size - len(data))
        require(bool(chunk))
        data.extend(chunk)
    return bytes(data)


def public_result(value):
    require(isinstance(value, dict))
    if value.get("schema") == "zenith.session-call-result.v1":
        require(set(value) == {"schema", "request_id", "provider_service", "operation", "result"})
        require(isinstance(value["request_id"], str) and re.fullmatch("[0-9a-f]{32}", value["request_id"]))
        text(value["provider_service"]); text(value["operation"])
        return value
    if value.get("schema") == "zenith.session-review-services.v1":
        require(set(value) == {"schema", "services"} and isinstance(value["services"], list) and len(value["services"]) <= 64)
        for service in value["services"]:
            require(set(service) == {"service", "name", "read_available", "write_available"})
            text(service["service"]); text(service["name"])
            require(type(service["read_available"]) is bool and type(service["write_available"]) is bool)
        return value
    require(set(value) == RESULT_KEYS and value["schema"] in {"zenith.session-access-result.v1", "zenith.session-access-result.v2"})
    require(value["state"] in STATES and type(value["reconcile_required"]) is bool)
    require(value["reconcile_required"] == (value["state"] == "outcome_unknown"))
    for field in ["request_handle", "provider_service"]:
        text(value[field])
    for field, count in [("request_id", 32), ("review_digest_sha256", 64), ("holder_public_key", 64)]:
        pending = value["schema"] == "zenith.session-access-result.v2" and value["state"] in {"awaiting_human", "cancelled"} and field != "request_id"
        require(pending and value[field] is None or isinstance(value[field], str) and re.fullmatch("[0-9a-f]{%d}" % count, value[field]))
    if value["state"] == "issued":
        require(isinstance(value["credential_handle"], str) and re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", value["credential_handle"]))
        require(type(value["expires_at"]) is int and 0 < value["expires_at"] <= SAFE)
    else:
        require(value["credential_handle"] is None and value["expires_at"] is None)
    return value


def exchange(directory, method, params):
    info = directory.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and info.st_mode & 0o077 == 0)
    key = private_file(directory / "pairing-token").decode("ascii")
    require(re.fullmatch("[0-9a-f]{64}", key))
    endpoint = directory / "review.sock"
    info = endpoint.lstat()
    require(stat.S_ISSOCK(info.st_mode) and info.st_uid == os.getuid() and info.st_mode & 0o077 == 0)
    call = uuid.uuid4().hex
    raw = encoded({"schema": "zenith.session-review-ipc.v1", "call_id": call, "client_id": CLIENT, "token": key, "method": method, "params": params})
    require(len(raw) <= MAX)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(12)
        connection.connect(str(endpoint))
        connection.sendall(struct.pack("!I", len(raw)) + raw)
        length = struct.unpack("!I", receive(connection, 4))[0]
        require(0 < length <= MAX)
        value = loads(receive(connection, length))
    require(value.get("schema") == "zenith.session-review-ipc-result.v1" and value.get("call_id") == call)
    require(set(value) == {"schema", "call_id", "result"})
    if method == "close_client":
        require(value["result"] == {"schema": "zenith.session-client-closed.v1", "closed": True, "server_revocation_confirmed": False})
        return value["result"]
    return public_result(value["result"])


TOOLS = [
    {"name": "list_wallet_services", "description": "List locally configured canonical services available for a human-reviewed session credential. Network routes are not separate authorities.", "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False}, "annotations": {"readOnlyHint": True, "openWorldHint": False}},
    {"name": "request_session_credential", "description": "Ask Transfer to open a native Wallet review for this session. Creates no access without the person's approval. Use get_session_credential_status for the original result; never ask for a password in chat.", "inputSchema": {"type": "object", "properties": {"service": {"type": "string", "maxLength": 512}, "permissions": {"type": "array", "minItems": 1, "maxItems": 64, "items": {"type": "object"}}, "session_label": {"type": "string", "maxLength": 512}, "purpose": {"type": "string", "maxLength": 512}, "lifetime_seconds": {"type": "integer", "minimum": 1}, "request_id": {"type": "string", "pattern": "^[0-9a-f]{32}$"}}, "required": ["service", "permissions", "session_label", "purpose"], "additionalProperties": False}, "annotations": {"readOnlyHint": False, "destructiveHint": False, "openWorldHint": False}},
    {"name": "get_session_credential_status", "description": "Read or reconcile the original request owned by this MCP process. Returns opaque handles and status, never a key, bearer credential or signing presentation.", "inputSchema": {"type": "object", "properties": {"request_handle": {"type": "string", "pattern": "^[A-Za-z0-9._:-]{1,128}$"}}, "required": ["request_handle"], "additionalProperties": False}, "annotations": {"readOnlyHint": True, "openWorldHint": False}},
    {"name": "call_service_with_session_credential", "description": "Use this session's approved credential for a scoped call to its configured service. Current qualified provider supports reads only. Receiver enforces scope/expiry/revocation. No target URL, owner key or raw-signing input is accepted; denial does not renew access.", "inputSchema": {"type": "object", "properties": {"credential_handle": {"type": "string", "pattern": "^[A-Za-z0-9._:-]{1,128}$"}, "request_id": {"type": "string", "pattern": "^[0-9a-f]{32}$"}, "operation": {"type": "string", "maxLength": 512}, "resource": {"type": "string", "maxLength": 2048}, "parameters": {"type": "object"}}, "required": ["credential_handle", "operation", "resource", "parameters"], "additionalProperties": False}, "annotations": {"readOnlyHint": False, "destructiveHint": False, "openWorldHint": False}},
]


def call_tool(directory, params):
    require(isinstance(params, dict) and set(params) <= {"name", "arguments", "_meta"})
    name, args = params.get("name"), params.get("arguments", {})
    require(isinstance(args, dict))
    if name == "list_wallet_services":
        require(not args)
        return exchange(directory, "list_services", {})
    if name == "get_session_credential_status":
        require(set(args) == {"request_handle"} and re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", text(args["request_handle"], 128)))
        return exchange(directory, "get_result", args)
    if name == "call_service_with_session_credential":
        required = {"credential_handle", "operation", "resource", "parameters"}
        require(required <= set(args) <= required | {"request_id"})
        require(re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", text(args["credential_handle"], 128)))
        text(args["operation"]); text(args["resource"], 2048)
        require(isinstance(args["parameters"], dict))
        args = dict(args)
        args.setdefault("request_id", uuid.uuid4().hex)
        require(isinstance(args["request_id"], str) and re.fullmatch("[0-9a-f]{32}", args["request_id"]))
        return exchange(directory, "execute", args)
    require(name == "request_session_credential")
    required = {"service", "permissions", "session_label", "purpose"}
    require(required <= set(args) <= required | {"lifetime_seconds", "request_id"})
    for field in ["service", "session_label", "purpose"]:
        text(args[field])
    require(isinstance(args["permissions"], list) and 1 <= len(args["permissions"]) <= 64 and all(isinstance(p, dict) for p in args["permissions"]))
    if "lifetime_seconds" in args:
        require(type(args["lifetime_seconds"]) is int and 0 < args["lifetime_seconds"] <= SAFE)
    if "request_id" in args:
        require(isinstance(args["request_id"], str) and re.fullmatch("[0-9a-f]{32}", args["request_id"]))
    else:
        args = dict(args, request_id=hashlib.sha256(CLIENT.encode() + encoded(args)).hexdigest()[:32])
    return exchange(directory, "request_review", args)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--broker-directory", type=Path, default=Path("/tmp") / ("zenith-transfer-%d" % os.getuid()))
    directory = parser.parse_args().broker_directory
    try:
        serve(directory)
    finally:
        # EOF ends this adapter's custody only. No server revocation is claimed.
        try:
            exchange(directory, "close_client", {})
        except Exception:
            pass  # Process/receiver expiry remains the independent hard limit.


def serve(directory):
    initialized = False
    while True:
        line = sys.stdin.buffer.readline(MAX + 2)
        if not line:
            return
        request_id = None
        try:
            require(len(line) <= MAX and line.endswith(b"\n"))
            value = loads(line)
            require(isinstance(value, dict) and value.get("jsonrpc") == "2.0" and set(value) <= {"jsonrpc", "id", "method", "params"})
            if "id" not in value:  # Notifications have no response or side effect.
                require(str(value.get("method", "")).startswith("notifications/"))
                continue
            request_id = value["id"]
            require(type(request_id) in (int, str))
            method = value.get("method")
            if method == "initialize":
                require(not initialized)
                version = value.get("params", {}).get("protocolVersion")
                initialized = True
                result = {"protocolVersion": version if version in VERSIONS else "2025-03-26", "capabilities": {"tools": {}}, "serverInfo": {"name": "zenith-transfer-wallet", "version": "0.1.0"}, "instructions": "Human approval happens only in native Transfer. Never request Wallet passwords or private keys. A session credential is distinct from the owner's Wallet and is finite, scoped and revocable."}
            else:
                require(initialized)
                if method == "ping":
                    result = {}
                elif method == "tools/list":
                    result = {"tools": TOOLS}
                elif method == "tools/call":
                    try:
                        content = call_tool(directory, value.get("params"))
                        result = {"content": [{"type": "text", "text": encoded(content).decode()}], "structuredContent": content, "isError": False}
                    except Exception:
                        result = {"content": [{"type": "text", "text": "Wallet review is unavailable. Open Transfer, enable local session requests, and check the original request before retrying. No approval was sent by this tool."}], "isError": True}
                else:
                    raise ClosedError("unsupported_method")
            response = {"jsonrpc": "2.0", "id": request_id, "result": result}
        except Exception:
            response = {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32600, "message": "Invalid or unsupported request"}}
        sys.stdout.buffer.write(encoded(response) + b"\n")
        sys.stdout.buffer.flush()


if __name__ == "__main__":
    main()
