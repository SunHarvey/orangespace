"""Fixed NONSECRET premise-probe builder. Does not provision or run Windows.

Input values are external assertions, not an authentication mechanism. The
external administrator/bootstrap must independently authenticate the output
seal/plan and both images before any approved Windows execution.
"""
import json
import pathlib
import re

FIELDS = {"purpose", "nonce", "program_files", "sid", "observer_session", "observer_luid",
          "probe_session", "probe_luid", "root_volume", "root_file_id",
          "evidence_volume", "evidence_file_id"}

def validate(v):
    if not isinstance(v, dict) or set(v) != FIELDS:
        raise ValueError("exact input fields required; no arbitrary commands/modes/paths")
    if v["purpose"] not in {"compilation-fixture", "external-os-input"}:
        raise ValueError("purpose")
    if not isinstance(v["nonce"], str) or not re.fullmatch(r"[0-9a-f]{32}", v["nonce"]):
        raise ValueError("nonce")
    if not isinstance(v["sid"], str) or not re.fullmatch(r"S-1-5-21-[1-9][0-9]*-[1-9][0-9]*-[1-9][0-9]*-[1-9][0-9]*", v["sid"]):
        raise ValueError("existing domain/local UserA SID required")
    if any(int(x) > 0xffffffff for x in v["sid"].split("-")[4:]):
        raise ValueError("SID subauthority overflow")
    # This first candidate deliberately supports only this conservative canonical
    # Program Files spelling; a different actual OS location is a STOP, not repair.
    if not isinstance(v["program_files"], str) or not re.fullmatch(r"[A-Z]:\\Program Files", v["program_files"]):
        raise ValueError("unsupported actual Program Files path; do not normalize")
    for k in FIELDS - {"purpose", "nonce", "program_files", "sid"}:
        if type(v[k]) is not int or v[k] < (0 if k == "observer_session" else 1):
            raise ValueError(k)
        if v[k] > (0xffffffff if k.endswith("session") or k.endswith("volume") else 0xffffffffffffffff):
            raise ValueError(k)
    if v["probe_session"] > 0x7fffffff:
        raise ValueError("probe session must fit RunEx signed LONG")
    # Compare each role against its independently OS-derived external input;
    # equality/difference of LUIDs is not an authentication mechanism.
    if (v["root_volume"], v["root_file_id"]) == (v["evidence_volume"], v["evidence_file_id"]):
        raise ValueError("distinct roots required")
    p = dict(v)
    p["compilation_fixture"] = v["purpose"] == "compilation-fixture"
    p["task_name"] = "OrangeSpacePhase1TaskIdentity-" + v["nonce"]
    p["root"] = v["program_files"] + "\\" + p["task_name"]
    p["evidence_root"] = v["program_files"] + "\\OrangeSpacePhase1TaskIdentityEvidence-" + v["nonce"]
    return p


def sha(data):
    import hashlib
    return hashlib.sha256(data).hexdigest()


def configuration(p, probe_digest):
    if not re.fullmatch(r"[0-9a-f]{64}", probe_digest):
        raise ValueError("probe digest")
    plan = dict(p, probe_sha256=probe_digest,
                observer_image="phase1_task_identity_observer.exe",
                probe_image="phase1_task_identity_probe.exe",
                plan_basename="plan.bin", report_basename="report.bin",
                recovery_basename="recovery.bin", schema=1,
                action="fixed-nonsecret-probe", logon="InteractiveToken", runlevel="LUA",
                task_action_binding="UNPROVED", further_admission=False)
    data = (json.dumps(plan, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    header = "#pragma once\nnamespace phase1_task_identity_config {\n"
    for k in ["program_files", "sid", "root", "evidence_root", "task_name"]:
        header += f"inline constexpr wchar_t {k}[] = L{json.dumps(p[k])};\n"
    header += f'inline constexpr char nonce[] = {json.dumps(p["nonce"])};\n'
    header += f'inline constexpr char probe_sha256[] = "{probe_digest}";\n'
    header += f'inline constexpr char plan_sha256[] = "{sha(data)}";\n'
    header += f'inline constexpr bool compilation_fixture = {str(p["compilation_fixture"]).lower()};\n'
    for k in ["observer_session", "observer_luid", "probe_session", "probe_luid",
              "root_volume", "root_file_id", "evidence_volume", "evidence_file_id"]:
        header += f"inline constexpr unsigned long long {k} = {p[k]}ULL;\n"
    return data, header + "}\n"


def snapshot(paths):
    return {str(pathlib.Path(p).resolve()): sha(pathlib.Path(p).read_bytes()) for p in sorted(set(paths))}


def build(value, out):
    """Fresh local GNU static compatibility build. NEVER executes a Windows PE."""
    import shutil
    import subprocess
    import shlex
    import os
    p = validate(value)
    out = pathlib.Path(out).resolve()
    out.mkdir(exist_ok=False, parents=False)
    here = pathlib.Path(__file__).resolve().parent
    compiler = shutil.which("x86_64-w64-mingw32-g++")
    if not compiler: raise RuntimeError("existing MinGW compiler required; no dependency installation")
    include = out / "include"; include.mkdir()
    (include / "phase1_task_identity_probe_config.hpp").write_text(
        "#pragma once\nnamespace phase1_task_identity_probe_config { inline constexpr bool compilation_fixture = " +
        str(p["compilation_fixture"]).lower() + "; }\n")
    common = [compiler, "-std=c++20", "-Wall", "-Wextra", "-Werror", "-O2", "-municode",
              "-static", "-static-libgcc", "-static-libstdc++", "-Wl,--no-insert-timestamp",
              "-I", str(include)]
    commands = []
    def run(args, name):
        commands.append(args)
        env = dict(os.environ, TMPDIR=str(out))
        r = subprocess.run(args, text=True, capture_output=True, env=env)
        (out / name).write_text(r.stdout + r.stderr)
        if r.returncode: raise RuntimeError(f"local build failed; see {out / name}")
        return r.stdout + r.stderr
    probe = here / "phase1_task_identity_probe.cpp"
    observer = here / "phase1_task_identity_observer.cpp"
    probe_args = common + [str(probe)]
    observer_args = common + [str(observer), "-ladvapi32", "-lole32", "-loleaut32", "-ltaskschd", "-luuid", "-lshell32", "-lbcrypt"]
    probe_exe = out / "phase1_task_identity_probe.exe"
    observer_exe = out / "phase1_task_identity_observer.exe"
    # First pass discovers linker inputs. It is not the deliverable/attestation.
    trace1 = run(probe_args + ["-Wl,-t", "-o", str(probe_exe)], "probe-firstpass.log")
    plan, header = configuration(p, sha(probe_exe.read_bytes()))
    (include / "phase1_task_identity_config.hpp").write_text(header)
    (out / "plan.bin").write_bytes(plan)
    trace2 = run(observer_args + ["-Wl,-t", "-o", str(observer_exe)], "observer-firstpass.log")
    deps = {str(pathlib.Path(__file__).resolve()), str(out / "plan.bin")}
    deps.update(str(f) for f in here.glob("phase1_task_identity_*") if f.is_file())
    for source in [probe, observer]:
        deptext = run(common + ["-M", "-MT", "identity", str(source)], source.stem + "-dependencies.log")
        deps.update(shlex.split(deptext.replace("\\\n", " ").split(":", 1)[1]))
    for line in (trace1 + trace2).splitlines():
        name = line.strip()
        if pathlib.Path(name).is_file() and name.endswith((".a", ".o")):
            deps.add(name)
    # Trace includes transient compiler-owned .o files which no longer exist;
    # their generated content is bound by source/tool hashes, not fabricated.
    for name in [compiler] + [subprocess.check_output([compiler, "-print-prog-name=" + n], text=True).strip()
                              for n in ["cc1plus", "collect2", "as", "ld"]]:
        resolved = shutil.which(name) or name
        if not pathlib.Path(resolved).is_file(): raise RuntimeError("compiler tool not found: " + name)
        deps.add(resolved)
    before = snapshot(deps)
    (out / "dependencies-before.json").write_text(json.dumps(before, indent=2, sort_keys=True) + "\n")
    run(probe_args + ["-o", str(probe_exe)], "probe-final.log")
    if sha(probe_exe.read_bytes()) != json.loads(plan)["probe_sha256"]:
        raise RuntimeError("probe bytes changed across fresh build; discard artifacts")
    run(observer_args + ["-o", str(observer_exe)], "observer-final.log")
    # Inspect actual PE imports, not a claim based on -static alone.
    for exe in [probe_exe, observer_exe]:
        imports = run(["x86_64-w64-mingw32-objdump", "-p", str(exe)], exe.stem + "-pe.txt")
        for dll in re.findall(r"DLL Name:\s*(\S+)", imports):
            if re.search(r"(?i)(libgcc|libstdc\+\+|libwinpthread|vcruntime|msvcp)", dll):
                raise RuntimeError("dynamic compiler runtime import: " + dll)
    after = snapshot(deps)
    (out / "dependencies-after.json").write_text(json.dumps(after, indent=2, sort_keys=True) + "\n")
    if before != after: raise RuntimeError("dependency drift; discard artifacts")
    seal = {"kind": "UNAPPROVED-NONSECRET-TASK-IDENTITY-COMPATIBILITY-CANDIDATE",
            "compilation_fixture": p["compilation_fixture"], "native_executed": False,
            "action_binding": "UNPROVED", "further_admission": False,
            "external_bootstrap_authentication": "REQUIRED; self-checking this seal is not authentication",
            "files": {f.name: sha(f.read_bytes()) for f in [probe_exe, observer_exe, out / "plan.bin"]},
            "dependency_manifest_sha256": sha((out / "dependencies-before.json").read_bytes())}
    (out / "seal.json").write_text(json.dumps(seal, indent=2, sort_keys=True) + "\n")
    (out / "commands.json").write_text(json.dumps(commands, indent=2) + "\n")
    return seal


def unique_json(pairs):
    out = {}
    for key, value in pairs:
        if key in out: raise ValueError("duplicate JSON key")
        out[key] = value
    return out


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=pathlib.Path, required=True)
    parser.add_argument("--out", type=pathlib.Path, required=True, help="new local scratch directory; must not exist")
    args = parser.parse_args()
    value = json.loads(args.input.read_text(), object_pairs_hook=unique_json)
    print(json.dumps(build(value, args.out), indent=2, sort_keys=True))
