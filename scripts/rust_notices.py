#!/usr/bin/env python3
"""License notices of the Rust crates linked into OrangeSpace.exe.

    python -I scripts/rust_notices.py <output.txt>

Walks the locked dependency graph of orangespace-https for the Windows target
(normal dependencies only: build scripts and procedural macros run at build
time and are not part of the binary) and writes, for every crate, its name,
version, declared license and repository, followed by the license and notice
files the published crate carries. Needs cargo and the crates already fetched
(run after a build).
"""
import json
from pathlib import Path
import subprocess
import sys

ROOT_PACKAGE = "orangespace-https"
TARGET = "x86_64-pc-windows-msvc"
LICENSE_PREFIXES = ("license", "licence", "copying", "notice", "copyright")


def metadata(repository):
    out = subprocess.run(["cargo", "metadata", "--format-version", "1", "--locked", "--filter-platform", TARGET],
                         cwd=repository, check=True, capture_output=True, text=True).stdout
    return json.loads(out)


def shipped(meta):
    packages = {p["id"]: p for p in meta["packages"]}
    nodes = {n["id"]: n for n in meta["resolve"]["nodes"]}
    root = next(p["id"] for p in meta["packages"] if p["name"] == ROOT_PACKAGE and p["source"] is None)
    seen, stack = set(), [root]
    while stack:
        current = stack.pop()
        if current in seen:
            continue
        seen.add(current)
        for dep in nodes[current]["deps"]:
            if not any(kind["kind"] is None for kind in dep["dep_kinds"]):
                continue
            package = packages[dep["pkg"]]
            if all("proc-macro" in target["kind"] for target in package["targets"]):
                continue
            stack.append(dep["pkg"])
    return sorted((packages[i] for i in seen if packages[i]["source"] is not None),
                  key=lambda p: (p["name"], p["version"]))


def license_files(package):
    directory = Path(package["manifest_path"]).parent
    files = {p for p in directory.iterdir() if p.is_file() and p.name.lower().startswith(LICENSE_PREFIXES)}
    if package.get("license_file"):
        files.add(directory / package["license_file"])
    return sorted(files)


def main(argv):
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    repository = Path(__file__).resolve().parent.parent
    output = Path(argv[1])
    crates = shipped(metadata(repository))
    with output.open("w", encoding="utf-8", newline="\n") as out:
        out.write("Rust crates linked into OrangeSpace.exe (via orangespace-https), with their licenses.\n")
        out.write("The rights in these crates remain with their authors.\n\n")
        for package in crates:
            out.write("=" * 78 + "\n")
            out.write(f"{package['name']} {package['version']}\n")
            out.write(f"License: {package.get('license') or 'see files below'}\n")
            if package.get("repository"):
                out.write(f"Source: {package['repository']}\n")
            files = license_files(package)
            if not files:
                out.write("(The published crate carries no license file; the declared license applies.)\n")
            for path in files:
                out.write(f"\n--- {path.name} ---\n")
                out.write(path.read_text(encoding="utf-8", errors="replace").rstrip() + "\n")
            out.write("\n")
    print(f"{len(crates)} crates -> {output}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
