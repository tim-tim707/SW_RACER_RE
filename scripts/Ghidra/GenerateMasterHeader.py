# This file concatenate all headers in src/ for use in Ghidra
# This is a convenience in order not to include headers one by one
# You can still import individual headers with the ImportHeaderInfos.py script

import os

if (not str.endswith(os.getcwd(), "SW_RACER_RE")):
    print("This scripts is not running from the correct directory ! Call from the SW_RE directory like so: python scripts\Ghidra\GenerateMasterHeader.py")
    exit(1)

dir_path = "src"

ignore_list = ["globals.h", "hook.h", "hook_addresses.h", "macros.h"]

res = []
for (dir_path, dir_names, file_names) in os.walk(dir_path):
    for f in file_names:
        if (str.endswith(f, ".h") and ignore_list.count(f) == 0):
            res.append(dir_path + '\\' + f)

buffer = ""
for path in res:
    with open(path, "r", encoding="ascii") as f:
        buffer += '\n' + f.read()

with open("scripts\Ghidra\master_header.h", "w", encoding="ascii") as output:
    output.write("\n //  \n" + buffer)

print("Generated scripts\Ghidra\master_header.h. Use the ImportHeaderInfos.py script to add the functions informations to Ghidra, after having parsed the types.h file using File -> Parse C Source -> types.h")
