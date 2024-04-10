import sys
import os
import subprocess
import platform
import glob
import concurrent.futures
import argparse

class colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

THISDIR = os.getcwd()
THISPYTHON = "python" + sys.version[0:4]

INCLUDES = ["-I.", "-Isrc",  "-Isrc/Dss", "-Isrc/Engine", "-Isrc/General", "-Isrc/generated", "-Isrc/Gui", "-Isrc/Main", "-Isrc/Platform", "-Isrc/Platform/D3D", "-Isrc/Primitives" ,"-Isrc/Raster", "-Isrc/Swr", "-Isrc/Unknown", "-Isrc/Win95"]
# -DINCLUDE_DX_HEADERS=1 doesnt include the correct headers for some reasons. Missing -I ?
FLAGS = ["-s", "-shared", "-Wall", "-Wextra", "-Wno-unused-parameter", "-Wno-unused-variable", "-g"]
LIBS = ["-lgdi32", "-lcomctl32", "-lole32", "-lwinmm"]

IGNORED_SOURCES = [os.path.join(THISDIR, "src", "generated", "globals.c"), os.path.join(THISDIR, "src", "dllMainDInput.c")]
SOURCES = glob.glob(os.path.join(THISDIR, "src", "**", "*.c"), recursive=True)
for ignored in IGNORED_SOURCES:
    SOURCES.remove(ignored)

def printerr(s):
    print(f"{colors.FAIL}{s}{colors.ENDC}")

def cmdExists(cmd: str):
    if platform.system() == "Windows":
        _, _, status = run(["where", cmd])
    else:
        _, _, status = run(["command", "-v", cmd])
    return status == 0

def run(args: list[str], cwd=THISDIR):
    print(f"{colors.BOLD}{colors.OKCYAN}Running \"{' '.join(args)}\" in {cwd}{colors.ENDC}")
    try:
        if platform.system() == "Windows":
            process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, cwd=cwd)
        else:
            process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=cwd)

        stdout, stderr = process.communicate()

        stdout = stdout.decode('utf-8')
        stderr = stderr.decode('utf-8')

        return stdout, stderr, process.returncode
    except Exception as e:
        return None, str(e), 1

def runLogged(args, cwd=None):
    out = None
    err = None
    status = 0

    if cwd:
        out, err, status = run(args, cwd)
    else:
        out, err, status = run(args)

    if status != 0:
        printerr(err)
        printerr(f"Returned status code {status}")
    else:
        print(out)

    return status

def compileSource(sourceFile, objdir, force):
    status = 0
    name = os.path.splitext(os.path.basename(sourceFile))[0]
    objpath = os.path.join(objdir, name + ".o")
    if (not force and os.path.isfile(objpath) and os.path.getmtime(sourceFile) < os.path.getmtime(objpath)):
        return status, objpath

    status = runLogged(["gcc", "-c", sourceFile, "-o", objpath] + FLAGS + INCLUDES + LIBS)
    return status, objpath

def main(args):
    print(args)

    if not cmdExists("gcc"):
        print(f"{colors.FAIL}Missing gcc in PATH ! Please install gcc from https://github.com/brechtsanders/winlibs_mingw/releases/tag/13.2.0posix-17.0.6-11.0.1-ucrt-r5{colors.ENDC}")
        sys.exit(1)

    if not args.disable_generation:
        if (runLogged([THISPYTHON, os.path.join(THISDIR, "scripts", "GenerateGlobalHeaderFromSymbols.py")]) != 0):
            sys.exit(1)

        if (runLogged([THISPYTHON, os.path.join(THISDIR, "scripts", "GenerateHooks.py")]) != 0):
            sys.exit(1)

    # DLL compilation
    OBJS = []
    failed = False

    objdir = os.path.join(THISDIR, "build", "swr_reimpl")

    if not os.path.isdir(objdir):
        os.mkdir(objdir)

    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = [executor.submit(compileSource, SOURCES[i], objdir, args.force) for i in range(len(SOURCES))]
        results = [future.result() for future in concurrent.futures.as_completed(futures)]

    for status, result_objdir in results:
        OBJS.append(result_objdir)
        if status != 0:
            failed = True
            break

    if (failed):
        printerr("Some object file compilation failed. Aborting now")
        sys.exit(1)
    elif (runLogged(["gcc"] + OBJS + ["-o", os.path.join(THISDIR, "build", "swr_reimpl.dll")] + FLAGS + INCLUDES + LIBS) != 0):
        sys.exit(1)

    print(f"{colors.OKGREEN}Compilation successful ! Outputs are in build/{colors.ENDC}")
    return

if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='compile.py', description='Compile the reimplementation dll')
    parser.add_argument('-B', '--force', action='store_true', default=False, help='Force rebuild every file')
    parser.add_argument('-j', '--jobs', action='store', default=None, help='Number of parallel jobs', type=int)
    parser.add_argument('--disable-generation', action='store_true', default=False, help='Disable automatic generation from scripts/GenerateGlobalHeaderFromSymbols.py and scripts/GenerateHooks.py')
    args = parser.parse_args()
    if platform.system() == "Windows" and args.jobs is not None and args.jobs > 61:
        args.jobs = 61
    main(args)
