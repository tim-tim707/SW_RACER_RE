import os.path
import re
from pathlib import Path
from glob import glob

import idc
import ida_srclang
import ida_auto

src_dir = str(Path(__file__).parent.parent.parent / "src")

def relative_glob(dir, pattern):
    return [os.path.relpath(f, dir).replace("\\", "/") for f in glob(dir + "/" + pattern)]

headers = [
    "types.h",
    "types_model.h",
    "main.h",
    "stdPlatform.h",
    "swr.h",
    # "swr_stdlib.h",
    *relative_glob(src_dir, "Dss/*.h"),
    *relative_glob(src_dir, "Engine/*.h"),
    *relative_glob(src_dir, "General/*.h"),
    *relative_glob(src_dir, "Gui/*.h"),
    *relative_glob(src_dir, "Main/*.h"),
    *relative_glob(src_dir, "Platform/*.h"),
    *relative_glob(src_dir, "Raster/*.h"),
    *relative_glob(src_dir, "Primitives/*.h"),
    *relative_glob(src_dir, "Swr/*.h"),
    *relative_glob(src_dir, "Unknown/*.h"),
    *relative_glob(src_dir, "Win95/*.h"),
]

function_addresses = {}
function_names_per_file = {}
function_prototypes = {}

for h in headers:
    for line in open(src_dir + "/" + h, 'r'):
        m = re.match("#define (.+)_ADDR \\((0x[0-9A-Fa-f]+)\\)", line)
        if m:
            function_addresses[m.group(1)] = int(m.group(2), base=16)
            if not h in function_names_per_file:
                function_names_per_file[h] = []

            function_names_per_file[h].append(m.group(1))


for (func, addr) in function_addresses.items():
    idc.set_name(addr, func)

# TODO total hack...
for h in headers:
    if not h in function_names_per_file:
        continue
    for line in open(src_dir + "/" + h, 'r'):
        line = line.rstrip().lstrip()
        if line.startswith("//") or line.startswith("/*") or (not line.endswith(";")):
            continue

        names = []
        for name in function_names_per_file[h]:
            if name in line:
                names.append(name)
                break

        if len(names) > 1:
            print(f"error: found multiple names in line \"{line}\"")
        elif len(names) == 1:
            if not "__stdcall" in line:
                line = "__cdecl " + line

            decl = idc.parse_decl(line, idc.PT_SILENT)
            if decl is None:
                print(f"warning: could not parse decl \"{line}\"")

            idc.apply_type(function_addresses[names[0]], decl, idc.TINFO_GUESSED)


clang_argv = [
    "-target i686-pc-windows-gnu",
    "-x c",
    "-I", src_dir,
    "-mno-sse",
    "-fsyntax-only",
    "--sysroot", "C:/mingw32",
    "-isystem", "C:/mingw32/lib/clang/12.0.0/include",
    "-isystem", "C:/mingw32/lib/gcc/i686-w64-mingw32/13.2.0/include"
]
ida_srclang.set_parser_argv("clang", " ".join(clang_argv))

decl = "\n".join([f'#include "{h}"' for h in headers])

ida_srclang.parse_decls_with_parser("clang", None, decl, False)

for line in open(src_dir + "/../data_symbols.syms"):
    if "//" in line:
        line = line[0:line.index("//")]

    if "#" in line:
        line = line[0:line.index("#")]

    if ";" in line:
        line = line[0:line.index(";")]

    if "=" in line:
        line = line[0:line.index("=")]

    line = line.lstrip().rstrip()

    if len(line) == 0:
        continue

    elems = line.split(" ")
    if len(elems) < 3:
        print(f"error: could not parse data_symbols line \"{line}\"")

    name = elems[0]
    addr = int(elems[1], base=16)
    type = " ".join(elems[2:])

    # print(f"name={name} address={address} type={type}")

    idc.set_name(addr, name)
    decl = idc.parse_decl(type, idc.PT_SILENT)
    idc.apply_type(addr, decl)

