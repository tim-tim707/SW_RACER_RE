"""Run the clang static analyzer (scan-build's analyze-build) over the project and gate on new findings.

    python scripts/static_analysis.py --cdb build/clang-release/compile_commands.json --out sa-report
    python scripts/static_analysis.py ... --update-baseline     # accept the current findings

Vendored third-party code is skipped. Findings are matched against
scripts/static_analysis_baseline.json by (checker, file, message) -- no line numbers, so
unrelated edits don't churn it -- and the script exits non-zero only on findings not in the
baseline. Fixing a baselined finding just leaves a stale entry; --update-baseline prunes it.
"""

import argparse
import collections
import glob
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import urllib.parse

REPO = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
BASELINE = os.path.join(REPO, "scripts", "static_analysis_baseline.json")

VENDORED = ("dinput_hook/imgui-", "dinput_hook/glfw-master/", "dinput_hook/detours-master/",
            "dinput_hook/fastgltf-", "dinput_hook/glad/", "dinput_hook/nv_dds/", "dinput_hook/harfbuzz-",
            "dinput_hook/openal-soft/", "dinput_hook/stb_image.h", "modules/")

# On top of analyze-build's defaults (core, cplusplus, deadcode, nullability, security, unix).
# Not optin.core.FixedAddressDereference: every game global is a fixed-address dereference. Not the
# alpha.cplusplus iterator checkers: they crash the analyzer on the delta layer's C++.
EXTRA_CHECKERS = (
    "optin.cplusplus.UninitializedObject",
    "optin.cplusplus.VirtualCall",
    "optin.portability.UnixAPI",
    "security.insecureAPI.strcpy",
    "alpha.core.StackAddressAsyncEscape",
    "alpha.cplusplus.DeleteWithNonVirtualDtor",
    "alpha.security.ReturnPtrRange",
    "alpha.unix.cstring.BufferOverlap",
    "alpha.unix.cstring.OutOfBounds",
)


def rel(path, directory="."):
    path = os.path.normpath(os.path.join(directory, path))
    try:
        return os.path.relpath(path, REPO).replace("\\", "/")
    except ValueError:  # different drive
        return path.replace("\\", "/")


def expand_response_files(args, directory):
    out = []
    for a in args:
        if a.startswith("@"):
            with open(os.path.join(directory, a[1:]), encoding="utf-8") as f:
                out.extend(shlex.split(f.read().replace("\\", "/")))
        else:
            out.append(a)
    return out


def normalize(cdb_path, out_path):
    """analyze-build splits commands POSIX-style (eating Windows backslashes), only recognizes
    compilers named exactly `clang`/`clang++` (no .exe), and can't see into @response files."""
    with open(cdb_path, encoding="utf-8") as f:
        entries = json.load(f)
    kept = []
    for e in entries:
        source = rel(e["file"], e["directory"])
        if source.startswith(VENDORED) or "/generated/" in source:
            continue
        args = e.get("arguments") or shlex.split(e["command"].replace("\\", "/"))
        args = expand_response_files(args, e["directory"])
        args[0] = "clang++" if re.search(r"clang\+\+(\.exe)?$", args[0]) or source.endswith(".cpp") else "clang"
        kept.append({"directory": e["directory"].replace("\\", "/"), "file": e["file"].replace("\\", "/"),
                     "command": shlex.join(args)})
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(kept, f, indent=1)
    return len(kept)


def run_analyzer(cdb, out_dir, clang, analyze_build):
    cmd = [sys.executable, analyze_build, "--cdb", cdb, "--use-analyzer", clang, "--sarif-html", "-o", out_dir,
           "--html-title", "SW_RACER_RE static analysis", "--keep-empty"]
    for c in EXTRA_CHECKERS:
        cmd += ["--enable-checker", c]
    subprocess.run(cmd, check=True)
    runs = sorted(glob.glob(os.path.join(out_dir, "scan-build-*")), key=os.path.getmtime)
    return runs[-1]


def load_findings(report_dir):
    merged = os.path.join(report_dir, "results-merged.sarif")
    if not os.path.exists(merged):
        return []
    with open(merged, encoding="utf-8") as f:
        sarif = json.load(f)
    findings = []
    for run in sarif.get("runs", []):
        for r in run.get("results", []):
            loc = r["locations"][0]["physicalLocation"]
            uri = loc["artifactLocation"]["uri"]
            # file:///C:/%2F/Users/... or file:///%2F/Users/... (drive dropped) -> C:/Users/...
            path = urllib.parse.unquote(re.sub(r"^file:/*", "", uri))
            path = re.sub(r"^([A-Za-z]:)?/+", lambda m: (m[1] or os.path.splitdrive(REPO)[0]) + "/", path)
            path = rel(path)
            if path.startswith(VENDORED):
                continue
            findings.append({
                "checker": r.get("ruleId", "?"),
                "file": path,
                "message": r["message"]["text"],
                "line": loc.get("region", {}).get("startLine", 0),
            })
    return findings


def key(f):
    return f["checker"], f["file"], f["message"]


def analyzer_failures(report_dir):
    """Translation units the analyzer crashed on or could not parse -- silently lost coverage."""
    failed = []
    for info in glob.glob(os.path.join(report_dir, "failures", "*.info.txt")):
        with open(info, encoding="utf-8", errors="replace") as f:
            failed.append(rel(f.readline().strip()))
    return sorted(set(failed))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--cdb", required=True, help="compile_commands.json of a clang build")
    parser.add_argument("--out", default="static-analysis", help="report directory")
    parser.add_argument("--clang", default=shutil.which("clang"))
    parser.add_argument("--analyze-build", help="path to analyze-build (default: next to clang)")
    parser.add_argument("--update-baseline", action="store_true")
    parser.add_argument("--summary", help="append a Markdown summary here (e.g. $GITHUB_STEP_SUMMARY)")
    args = parser.parse_args()

    if not args.clang:
        sys.exit("clang not found; pass --clang")
    analyze_build = args.analyze_build or os.path.join(os.path.dirname(args.clang), "analyze-build")
    os.makedirs(args.out, exist_ok=True)

    cdb = os.path.join(args.out, "compile_commands.json")
    print(f"analyzing {normalize(args.cdb, cdb)} translation units")
    report_dir = run_analyzer(cdb, args.out, args.clang, analyze_build)
    findings = load_findings(report_dir)
    failed = analyzer_failures(report_dir)

    if args.update_baseline:
        entries = sorted(key(f) for f in findings)
        with open(BASELINE, "w", encoding="utf-8", newline="\n") as f:
            json.dump([dict(zip(("checker", "file", "message"), e)) for e in entries], f, indent=1)
            f.write("\n")
        print(f"baseline updated: {len(entries)} findings")
        return 0

    # A multiset: the same message can legitimately repeat within one file.
    baseline = collections.Counter()
    if os.path.exists(BASELINE):
        with open(BASELINE, encoding="utf-8") as f:
            baseline.update(key(e) for e in json.load(f))
    new = []
    for f in findings:
        if baseline[key(f)] > 0:
            baseline[key(f)] -= 1
        else:
            new.append(f)

    by_checker = collections.Counter(f["checker"] for f in findings)
    lines = [f"### Static analysis: {len(findings)} findings, {len(new)} new", ""]
    lines += [f"- `{c}`: {n}" for c, n in by_checker.most_common()]
    if failed:
        lines += ["", "#### Not analyzed (analyzer error)", ""] + [f"- `{p}`" for p in failed]
    if new:
        lines += ["", "#### New findings", ""]
        lines += [f"- `{f['file']}:{f['line']}` **{f['checker']}**: {f['message']}" for f in new]
    text = "\n".join(lines)
    print(text)
    print(f"\nHTML report: {report_dir}")
    if args.summary:
        with open(args.summary, "a", encoding="utf-8") as f:
            f.write(text + "\n")
    for f in new:
        # GitHub annotation on the PR diff
        print(f"::error file={f['file']},line={f['line']},title={f['checker']}::{f['message']}")
    return 1 if new or failed else 0


if __name__ == "__main__":
    sys.exit(main())
