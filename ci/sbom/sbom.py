"""CycloneDX SBOM generation and checks for ci/sbom/{generate,check}.sh.

  sbom.py generate <Cargo.lock> <all tree> <linked tree> <workspace Cargo.toml>
  sbom.py audit <binary>...       print "name version" lines from the embedded data
  sbom.py check <Cargo.lock> <sbom> <both-arch tree> <allowed audit-only names,> \
                [<tree> <binary>]...
  sbom.py drop <sbom> <name>      the SBOM without that component (for the self-test)

<all tree> is `cargo tree --prefix none -e normal,build`, <linked tree> is
`cargo tree --prefix depth --no-dedupe -e normal`, each for both musl targets.
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


DEPTH_LINE = re.compile(r"^(\d+)(\S+) v(\S+)(.*)")


def linked_set(path):
    """Crates reachable by normal edges, never through a proc macro's subtree."""
    found = set()
    skip_below = None
    with open(path) as f:
        for line in f:
            m = DEPTH_LINE.match(line)
            if not m:
                continue
            depth = int(m.group(1))
            if skip_below is not None and depth > skip_below:
                continue
            skip_below = None
            if "(proc-macro)" in m.group(4):
                skip_below = depth
                continue
            found.add((m.group(2), m.group(3)))
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


def generate(lock, all_tree, linked_tree, cargo_toml):
    packages = lock_packages(lock)
    linked = linked_set(linked_tree)
    components = []
    for name, version in sorted(tree_set(all_tree)):
        pkg = packages.get((name, version))
        if pkg is None:
            sys.exit(f"FAIL: {name} {version} is in the tree but not in Cargo.lock")
        comp = {
            "type": "library",
            "bom-ref": f"{name}@{version}",
            "name": name,
            "version": version,
        }
        # A purl names a registry crate; a workspace crate has no source in
        # Cargo.lock and must not be mistaken for the crates.io one of that name.
        if pkg.get("source", "").startswith("registry+"):
            comp["purl"] = f"pkg:cargo/{name}@{version}"
            comp["bom-ref"] = comp["purl"]
        if "checksum" in pkg:
            comp["hashes"] = [{"alg": "SHA-256", "content": pkg["checksum"]}]
        if (name, version) not in linked:
            comp["scope"] = "excluded"  # build script or proc macro chain, not linked
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


def check(lock, sbom, both_tree, allow_audit_only, pairs):
    packages = lock_packages(lock)
    with open(sbom) as f:
        bom = json.load(f)
    listed = {(c["name"], c["version"]): c for c in bom["components"]}
    allow = {n for n in allow_audit_only.split(",") if n}
    bad = []
    audit_union = set()
    host_union = set()
    for tree, binary in zip(pairs[0::2], pairs[1::2]):
        want = tree_set(tree)
        have = audit_set(binary)
        audit_union |= have
        host_union |= want
        for key in sorted(want - have):
            bad.append(f"{binary}: {key[0]} {key[1]} is in cargo tree but not in its audit data")
        for key in sorted(have - want):
            if key[0] not in allow:
                bad.append(f"{binary}: {key[0]} {key[1]} is in its audit data but not in cargo tree")
    # SBOM against what ships. Crates only the other architecture links are fine.
    other_only = tree_set(both_tree) - host_union
    for key in sorted(set(listed) - audit_union - other_only):
        bad.append(f"{key[0]} {key[1]} is in the SBOM but in no shipped binary")
    for key in sorted(audit_union | host_union):
        if key[0] in allow and key not in host_union:
            continue  # named audit-only crate: deliberately not in the SBOM
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
    for c in bom["components"]:
        if "purl" in c and "source" not in packages.get((c["name"], c["version"]), {}):
            bad.append(f"{c['name']} {c['version']} has a purl but no registry source")
    if bad:
        sys.exit("FAIL:\n  " + "\n  ".join(bad))
    audit_only = sorted(audit_union - host_union)
    sbom_only = sorted(set(listed) - audit_union)  # other architecture, or excluded
    print(f"OK: {len(listed)} SBOM components; audit data {len(audit_union)} crates")
    print(f"    audit-only (allowed): {[k for k in audit_only if k[0] in allow]}")
    print(f"    SBOM-only (other architecture): {sbom_only}")


def main(argv):
    if argv[0] == "generate":
        generate(*argv[1:5])
    elif argv[0] == "audit":
        for b in argv[1:]:
            for name, version in sorted(audit_set(b)):
                print(name, version)
    elif argv[0] == "check":
        check(argv[1], argv[2], argv[3], argv[4], argv[5:])
    elif argv[0] == "drop":
        with open(argv[1]) as f:
            bom = json.load(f)
        bom["components"] = [c for c in bom["components"] if c["name"] != argv[2]]
        print(json.dumps(bom, indent=2, sort_keys=True))
    else:
        sys.exit(__doc__)


main(sys.argv[1:])
