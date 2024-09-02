import os
import re
from glob import glob
from pathlib import Path
import ida_srclang

src_dir = str(Path(__file__).parent.parent.parent / "src")

def relative_glob(dir, pattern):
    return [os.path.relpath(f, dir).replace("\\", "/") for f in glob(dir + "/" + pattern)]

headers = [
    "types.h",
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


data_symbols = dict()

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

    data_symbols[name] = (addr, type)
    # print(f"name={name} address={addr} type={type}")


def parse_decls_with_clang(til, windows_types_only):
    clang_argv = [
        "-target i686-pc-windows-gnu",
        "-x c",
        "-I", src_dir,
        "-I", src_dir + "/generated/",
        "-mno-sse",
        "-fsyntax-only",
        "--sysroot", "C:/mingw32",
        "-isystem", "C:/mingw32/lib/clang/18/include",
        "-isystem", "C:/mingw32/lib/gcc/i686-w64-mingw32/14.1.0/include"
    ]
    ida_srclang.set_parser_argv("clang", " ".join(clang_argv))

    if windows_types_only:
        decl = """
        #include <windows.h>
        #include <stdio.h>
        #include <stdbool.h>
        #include <stdint.h>
        
        #include "types_a3d.h"
        #include "types_directx.h"
        """
    else:
        decl = "\n".join([f'#include "{h}"' for h in headers])

    ida_srclang.parse_decls_with_parser("clang", til, decl, False)
