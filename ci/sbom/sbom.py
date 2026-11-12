"""CycloneDX SBOM generation and checks for ci/sbom/{generate,check}.sh.

  sbom.py generate <Cargo.lock> <cargo tree output> <workspace Cargo.toml>
  sbom.py audit <binary>...       print "name version" lines from the embedded data
  sbom.py check <Cargo.lock> <cargo tree output> <sbom> <binary>...
"""
import json
import re
import subprocess
import sys
import tempfile
import tomllib
import zlib
import os

TREE_LINE = re.compile(r"^(\S+) v(\S+)")


def lock_packages(path):
    with open(path, "rb") as f:
        return {(p["name"], p["version"]): p for p in tomllib.load(f)["package"]}


def tree_set(path):
    found = set()
    with open(path) as f:
        for line in f:
            m = TREE_LINE.match(line)
            if m:
                found.add((m.group(1), m.group(2)))
    return found


def audit_set(binary):
    with tempfile.TemporaryDirectory() as d:
        section = os.path.join(d, "dep-v0")
        r = subprocess.run(
            ["objcopy", "--dump-section", f".dep-v0={section}", binary, os.devnull],
            capture_output=True,
        )
        if r.returncode != 0 or not os.path.exists(section) or os.path.getsize(section) == 0:
            sys.exit(f"FAIL: {binary} has no embedded audit data (.dep-v0)")
        with open(section, "rb") as f:
            data = json.loads(zlib.decompress(f.read()))
    pkgs = {(p["name"], p["version"]) for p in data.get("packages", [])}
    if not pkgs:
        sys.exit(f"FAIL: the audit data in {binary} lists no packages")
    raw = json.dumps(data)
    if "/home/" in raw or "/build" in raw:
        sys.exit(f"FAIL: the audit data in {binary} contains a path")
    return pkgs


def workspace_version(path):
    with open(path, "rb") as f:
        return tomllib.load(f)["workspace"]["package"]["version"]


def generate(lock, tree, cargo_toml):
    packages = lock_packages(lock)
    components = []
    for name, version in sorted(tree_set(tree)):
        pkg = packages.get((name, version))
        if pkg is None:
            sys.exit(f"FAIL: {name} {version} is in the tree but not in Cargo.lock")
        comp = {
            "type": "library",
            "bom-ref": f"pkg:cargo/{name}@{version}",
            "name": name,
            "version": version,
            "purl": f"pkg:cargo/{name}@{version}",
        }
        if "checksum" in pkg:
            comp["hashes"] = [{"alg": "SHA-256", "content": pkg["checksum"]}]
        components.append(comp)
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "bom-ref": "xudo",
                "name": "xudo",
                "version": workspace_version(cargo_toml),
            }
        },
        "components": components,
    }
    print(json.dumps(bom, indent=2, sort_keys=True))


def check(lock, tree, sbom, binaries):
    packages = lock_packages(lock)
    with open(sbom) as f:
        bom = json.load(f)
    listed = {}
    for c in bom["components"]:
        listed[(c["name"], c["version"])] = c
    expected = tree_set(tree)
    for b in binaries:
        expected |= audit_set(b)
    bad = []
    for key in sorted(expected):
        pkg = packages.get(key)
        comp = listed.get(key)
        if pkg is None:
            bad.append(f"{key[0]} {key[1]} is not in Cargo.lock at that version")
        elif comp is None:
            bad.append(f"{key[0]} {key[1]} is missing from the SBOM")
        elif "checksum" in pkg and comp.get("hashes") != [
            {"alg": "SHA-256", "content": pkg["checksum"]}
        ]:
            bad.append(f"{key[0]} {key[1]} has the wrong checksum in the SBOM")
    if bad:
        sys.exit("FAIL:\n  " + "\n  ".join(bad))
    print(f"OK: the SBOM lists all {len(expected)} crates of the audit data and the tree "
          f"({len(listed)} components)")


def main(argv):
    if argv[0] == "generate":
        generate(*argv[1:4])
    elif argv[0] == "audit":
        for b in argv[1:]:
            for name, version in sorted(audit_set(b)):
                print(name, version)
    elif argv[0] == "check":
        check(argv[1], argv[2], argv[3], argv[4:])
    else:
        sys.exit(__doc__)


main(sys.argv[1:])
