"""Run the libFuzzer harnesses (fuzz/) built by the clang-fuzz preset.

    cmake --preset clang-fuzz && cmake --build --preset clang-fuzz
    python scripts/run_fuzzers.py --build-dir build/clang-fuzz --seconds 60
    python scripts/run_fuzzers.py --build-dir build/clang-fuzz --seconds 600 \
        --seed-dir "<game dir>/assets/custom_tracks"            # real tracks as extra seeds

Each fuzzer starts from the committed corpus in fuzz/corpus/<name> (plus any --seed-dir, read
only) and grows a working corpus under the build dir. Crashing inputs land in
test-results/fuzz/<name>/ with the ASan report. Exit code 0 only if nothing crashed.
"""

import argparse
import glob
import os
import shutil
import subprocess
import sys

REPO = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
FUZZERS = {
    # name: file names a --seed-dir is searched for
    "custom_track_blocks": ("out_splineblock.bin", "out_modelblock.bin"),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--build-dir", required=True)
    parser.add_argument("--seconds", type=int, default=60, help="per fuzzer")
    parser.add_argument("--seed-dir", action="append", default=[], help="extra seeds (searched recursively)")
    parser.add_argument("--max-len", type=int, default=65536)
    parser.add_argument("--out", default=os.path.join(REPO, "test-results", "fuzz"))
    args = parser.parse_args()
    args.build_dir = os.path.abspath(args.build_dir)
    args.out = os.path.abspath(args.out)

    failed = False
    for name, seed_files in FUZZERS.items():
        exe = os.path.join(args.build_dir, "fuzz", f"fuzz_{name}.exe")
        if not os.path.exists(exe):
            sys.exit(f"{exe} not built (cmake --build --preset clang-fuzz)")
        work = os.path.join(args.build_dir, "fuzz", "corpus", name)
        os.makedirs(work, exist_ok=True)
        artifacts = os.path.join(args.out, name)
        os.makedirs(artifacts, exist_ok=True)

        seeds = [os.path.join(REPO, "fuzz", "corpus", name)]
        for d in args.seed_dir:
            for f in seed_files:
                seeds += [p for p in glob.glob(os.path.join(d, "**", f), recursive=True)]
        seed_dirs = []
        extra = os.path.join(args.build_dir, "fuzz", "seeds", name)
        shutil.rmtree(extra, ignore_errors=True)
        os.makedirs(extra)
        for i, s in enumerate(seeds):
            if os.path.isdir(s):
                seed_dirs.append(s)
            else:
                shutil.copy(s, os.path.join(extra, f"seed{i}"))
        seed_dirs.append(extra)

        log = os.path.join(artifacts, "fuzz.log")
        cmd = [exe, work, *seed_dirs, f"-max_total_time={args.seconds}", f"-max_len={args.max_len}",
               "-rss_limit_mb=1536", f"-artifact_prefix={artifacts}{os.sep}", "-print_final_stats=1"]
        with open(log, "w", encoding="utf-8", errors="replace") as f:
            rc = subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT, cwd=os.path.dirname(exe)).returncode
        with open(log, encoding="utf-8", errors="replace") as f:
            text = f.read()
        crashes = [p for p in glob.glob(os.path.join(artifacts, "*")) if
                   os.path.basename(p).split("-")[0] in ("crash", "oom", "timeout", "leak")]
        runs = [line for line in text.splitlines() if line.startswith("stat::number_of_executed_units")]
        print(f"{name}: {'FAIL' if rc or crashes else 'ok'}  "
              f"{runs[0].split(':')[-1].strip() if runs else '?'} inputs in {args.seconds}s")
        if rc or crashes:
            failed = True
            summary = [line for line in text.splitlines() if "ERROR: " in line or line.startswith("SUMMARY")]
            print("  " + "\n  ".join(summary[:4]))
            for c in crashes:
                print(f"  input: {c}")
    print("FAILED" if failed else "PASSED")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
