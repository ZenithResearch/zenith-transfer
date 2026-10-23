"""Check a committed Git tree, without inspecting untracked user files.

Run alongside Gitleaks. This catches common machine-path and artwork metadata
leaks, not every possible personal identifier. Optional --deny-list is a private
JSON array of strings; its contents and matched values are never printed.
"""
import argparse
import json
import re
import struct
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument("--ref", default="HEAD")
parser.add_argument("--deny-list")
args = parser.parse_args()


def git(*arguments):
    return subprocess.check_output(["git", *arguments])


private_markers = []
if args.deny_list:
    with open(args.deny_list) as source:
        private_markers = json.load(source)
    assert isinstance(private_markers, list) and all(isinstance(v, str) and v for v in private_markers)

patterns = [
    re.compile(r"/(?:Users|home)/[^/\s\"']+"),
    re.compile(r"/(?:private/)?var/" + r"folders/[^/]+/[^/]+/"),
    re.compile(r"pytest-" + r"of-[a-zA-Z0-9_-]+"),
]
issues = []
names = git("ls-tree", "-rz", "--name-only", args.ref).decode().strip("\0").split("\0")
for name in filter(None, names):
    content = git("show", args.ref + ":" + name)
    try:
        text = content.decode()
    except UnicodeDecodeError:
        text = ""
    if any(p.search(text) for p in patterns):
        issues.append((name, "machine-specific path"))
    if any(marker.casefold() in text.casefold() for marker in private_markers):
        issues.append((name, "private deny-list marker"))
    if name.endswith(".png"):
        offset = 8
        while offset < len(content):
            length = struct.unpack(">I", content[offset:offset + 4])[0]
            chunk = content[offset + 4:offset + 8]
            if chunk in {b"eXIf", b"iTXt", b"tEXt", b"zTXt", b"tIME"}:
                issues.append((name, "ancillary image metadata"))
            offset += length + 12

# This repository uses neutral project attribution for public release commits.
authors = git("log", args.ref, "--format=%an%x09%ae%x09%cn%x09%ce").decode().splitlines()
for index, author in enumerate(authors):
    fields = author.split("\t")
    if fields != ["Zenith Research contributors", "noreply@users.noreply.github.com"] * 2:
        issues.append(("commit " + str(index + 1), "non-neutral author or committer metadata"))

for path, reason in issues:
    print(path + ": " + reason)
if issues:
    raise SystemExit(1)
print("Privacy checks passed for " + str(len(names)) + " committed files and their reachable commit metadata.")
