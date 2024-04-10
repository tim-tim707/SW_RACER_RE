import os
import re
from glob import glob
from pathlib import Path

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
