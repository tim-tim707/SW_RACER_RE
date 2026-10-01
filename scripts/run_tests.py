"""Run an unattended test plan in the game and collect the results.

Deploy an instrumented build first (clang-asan, clang-ubsan or clang-coverage with GAME_DIR set),
then:

    python scripts/run_tests.py --game-dir "<game dir>"   # all stock tracks: 4 raced to the line, the rest sampled
    python scripts/run_tests.py --game-dir "<game dir>" --tracks 0,7 --laps 2
    python scripts/run_tests.py --game-dir "<game dir>" --coverage
    python scripts/run_tests.py --game-dir "<game dir>" --hd --coverage --accumulate   # suite total

Writes swr_test_plan.ini, launches the game through Steam, and waits for dinput.dll's test runner
(dinput_hook/test_runner.cpp) to finish and exit. Reports every race, any new crashes/ files (ASan
reports symbolized), and with --coverage an llvm-cov summary plus HTML report of our own code.
Exit code 0 only if every race finished and nothing crashed.
"""

import argparse
import glob
import json
import os
import shutil
import subprocess
import sys
import time

REPO = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
STEAM_URL = "steam://rungameid/808910"
GAME_EXE = "SWEP1RCR.EXE"


def game_running():
    out = subprocess.run(["tasklist", "/FI", f"IMAGENAME eq {GAME_EXE}", "/NH"],
                         capture_output=True, text=True).stdout
    return GAME_EXE.lower() in out.lower()


def kill_game():
    subprocess.run(["taskkill", "/IM", GAME_EXE, "/F"], capture_output=True)


def read_results(path):
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8", errors="replace") as f:
        return [json.loads(line) for line in f if line.strip().startswith("{")]


def wait_for_run(game_dir, launch_timeout, run_timeout):
    os.startfile(STEAM_URL)
    deadline = time.time() + launch_timeout
    while not game_running():
        if time.time() > deadline:
            return "game never started"
        time.sleep(1)
    deadline = time.time() + run_timeout
    while game_running():
        if time.time() > deadline:
            kill_game()
            return f"run exceeded {run_timeout}s; game killed"
        time.sleep(2)
    return None


def llvm_tool(name, explicit_root):
    root = explicit_root or os.environ.get("LLVM_MINGW_ROOT")
    if root and os.path.exists(os.path.join(root, "bin", name + ".exe")):
        return os.path.join(root, "bin", name + ".exe")
    return shutil.which(name)


def build_id(dll):
    st = os.stat(dll)
    return f"{st.st_size}-{int(st.st_mtime)}"


def coverage_report(game_dir, out_dir, llvm_root, accumulate):
    fresh = glob.glob(os.path.join(game_dir, "coverage", "*.profraw"))
    if not fresh:
        print("coverage: no .profraw written (was a clang-coverage build deployed?)")
        return
    dll = os.path.join(game_dir, "dinput.dll")
    # Counters only line up with the binary that wrote them, so the archive is per build.
    archive = os.path.join(out_dir, "coverage-runs", build_id(dll))
    os.makedirs(archive, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    for i, p in enumerate(fresh):
        shutil.move(p, os.path.join(archive, f"{stamp}-{i}.profraw"))
    profraws = glob.glob(os.path.join(archive, "*.profraw")) if accumulate else \
        [os.path.join(archive, f"{stamp}-{i}.profraw") for i in range(len(fresh))]
    runs = len({os.path.basename(p).rsplit("-", 1)[0] for p in profraws})
    profdata = os.path.join(out_dir, "dinput.profdata")
    subprocess.run([llvm_tool("llvm-profdata", llvm_root), "merge", "-sparse", *profraws, "-o", profdata],
                   check=True)
    sources = [os.path.join(REPO, "dinput_hook"), os.path.join(REPO, "src")]
    ignore = r"(imgui-|glfw-master|detours-master|fastgltf-|glad|nv_dds|stb_image|generated)"
    cov = llvm_tool("llvm-cov", llvm_root)
    common = [f"--instr-profile={profdata}", dll, f"--ignore-filename-regex={ignore}"]
    report = subprocess.run([cov, "report", *common, *sources], capture_output=True, text=True).stdout
    with open(os.path.join(out_dir, "coverage.txt"), "w", encoding="utf-8") as f:
        f.write(report)
    subprocess.run([cov, "show", *common, "--format=html", f"--output-dir={os.path.join(out_dir, 'html')}",
                    *sources], check=False)
    total = [line for line in report.splitlines() if line.startswith("TOTAL")]
    print(f"coverage ({runs} run{'s' if runs != 1 else ''} of this build):",
          total[0] if total else "(no TOTAL line)")
    print(f"coverage report: {os.path.join(out_dir, 'html', 'index.html')}")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--game-dir", required=True)
    parser.add_argument("--tracks", default="all", help="'all' or comma-separated stock track indices")
    parser.add_argument("--laps", type=int, default=1)
    parser.add_argument("--racers", type=int, default=6)
    parser.add_argument("--race-timeout", type=int, default=300, help="seconds before a race is abandoned")
    parser.add_argument("--finish-tracks", default="0,9,16,23",
                        help="tracks raced to the finish line ('all' / 'none'); the rest are sampled")
    parser.add_argument("--sample-s", type=int, default=45, help="seconds of driving on a sampled track")
    parser.add_argument("--pace", type=float, default=1.6,
                        help="autopilot speed-multiplier floor (1.6 = the game's AI ceiling, 0 = game's own)")
    parser.add_argument("--no-autopilot", action="store_true", help="leave the local pod idle")
    parser.add_argument("--stock-pod", action="store_true", help="don't max out the test pod's upgrades")
    parser.add_argument("--custom-tracks-dir",
                        help="load custom tracks from this folder (game-relative) for the run; race them "
                             "with --tracks custom")
    parser.add_argument("--hd", action="store_true",
                        help="force HD model replacement on (assets/gltf), restored afterwards")
    parser.add_argument("--tools", action="store_true",
                        help="exercise the debug tools (ImGui panels, collision overlays, cameras, "
                             "free camera) during the first race")
    parser.add_argument("--menus", action="store_true",
                        help="tour the front-end menus with synthetic input, ending in a race, first")
    parser.add_argument("--run-timeout", type=int, default=0, help="whole-run limit in seconds (default: scaled)")
    parser.add_argument("--coverage", action="store_true", help="merge coverage into an llvm-cov report")
    parser.add_argument("--accumulate", action="store_true",
                        help="with --coverage: report every archived run of this build, not just this one")
    parser.add_argument("--reset-coverage", action="store_true", help="clear the coverage archive first")
    parser.add_argument("--out", default=os.path.join(REPO, "test-results"))
    parser.add_argument("--llvm-root", help="toolchain root (default: $LLVM_MINGW_ROOT, then PATH)")
    args = parser.parse_args()

    game_dir = args.game_dir
    if game_running():
        sys.exit("the game is already running; close it first")
    os.makedirs(args.out, exist_ok=True)
    if args.reset_coverage:
        shutil.rmtree(os.path.join(args.out, "coverage-runs"), ignore_errors=True)

    results_path = os.path.join(game_dir, "swr_test_results.jsonl")
    if os.path.exists(results_path):
        os.remove(results_path)
    crashes_before = set(glob.glob(os.path.join(game_dir, "crashes", "*")))
    with open(os.path.join(game_dir, "swr_test_plan.ini"), "w", encoding="utf-8") as f:
        f.write(f"tracks={args.tracks}\nlaps={args.laps}\nracers={args.racers}\n"
                f"race_timeout_s={args.race_timeout}\nautopilot={0 if args.no_autopilot else 1}\n"
                f"max_upgrades={0 if args.stock_pod else 1}\nfinish_tracks={args.finish_tracks}\n"
                f"sample_s={args.sample_s}\npace={args.pace}\nmenus={1 if args.menus else 0}\n"
                f"hd={1 if args.hd else -1}\ntools={1 if args.tools else 0}\n")
        if args.custom_tracks_dir:
            f.write(f"custom_tracks_dir={args.custom_tracks_dir}\n")

    races = sum(25 if t == "all" else 70 if t == "custom" else 1 for t in args.tracks.split(","))
    races = min(races, 100) + (1 if args.menus else 0)
    run_timeout = args.run_timeout or 180 + races * (args.race_timeout + 30)
    error = wait_for_run(game_dir, 120, run_timeout)
    for leftover in ("swr_test_plan.ini", "swr_test_plan.running"):
        path = os.path.join(game_dir, leftover)
        if os.path.exists(path):
            os.remove(path)

    results = read_results(results_path)
    if os.path.exists(results_path):
        shutil.copy(results_path, args.out)
    failed = error is not None
    for r in results:
        if "race" in r and "outcome" in r:
            ok = r["outcome"] in ("finished", "sampled")
            failed |= not ok
            print(f"{'ok  ' if ok else 'FAIL'} race {r['race']:>2}  track {r['track']:>2} {r['name']:<28} "
                  f"{r['outcome']:<9} {r['seconds']:>4}s (load {r.get('load_s', '?'):>3}s, "
                  f"race {r.get('race_s', '?'):>3}s, {r.get('laps_done', 0):.2f} laps)")
        elif r.get("event") == "error":
            failed = True
            print(f"ERROR at race {r['race']}: {r['message']}")
    if not any(r.get("event") == "done" for r in results):
        failed = True
        print("run did not complete (crash, hang, or the runner never armed)")
    if error:
        print("ERROR:", error)

    new_crashes = sorted(set(glob.glob(os.path.join(game_dir, "crashes", "*"))) - crashes_before)
    for c in new_crashes:
        failed = True
        dest = os.path.join(args.out, os.path.basename(c))
        shutil.copy(c, dest)
        print(f"CRASH: {dest}")
        if os.path.basename(c).startswith("asan"):
            symbolized = dest + ".txt"
            with open(symbolized, "w", encoding="utf-8") as f:
                subprocess.run([sys.executable, os.path.join(REPO, "scripts", "asan_symbolize.py"), dest,
                                "--symbolizer", llvm_tool("llvm-symbolizer", args.llvm_root) or "llvm-symbolizer"],
                               stdout=f, check=False)
            with open(symbolized, encoding="utf-8") as f:
                print("".join(f.readlines()[:12]))

    if args.coverage:
        coverage_report(game_dir, args.out, args.llvm_root, args.accumulate)

    print("FAILED" if failed else "PASSED")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
