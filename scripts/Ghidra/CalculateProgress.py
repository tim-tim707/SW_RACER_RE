# this will calculate how many functions have associated identified function names
#
# This is done through a three step process
# 1) Run GenerateMasterHeader.py to create master_header.h with all identified files
# 2) Run GenerateFunctionList.py within Ghidra to extract all function names
# 3) Run this script to calculate progress

import os
import re

if (not str.endswith(os.getcwd(), "SW_RACER_RE")):
    print("This scripts is not running from the correct directory ! Call from the SW_RE directory like so: python scripts\\Ghidra\\CalculateProgress.py")
    exit(1)

try:
    header = open("scripts/Ghidra/master_header.h", "r")
except FileNotFoundError:
    print("master_header.h does not exist, run GenerateMasterHeader.py")
    exit(1)

try:
    functions = open("scripts/Ghidra/master_functions.h", "r")
except FileNotFoundError:
    print("master_functions.h does not exist, run GenerateFunctionList.py")
    exit(1)

header_lines = header.readlines()
function_lines = functions.readlines()

# get the set of all function addresses
p = re.compile(r'ADDR_0x([0-9a-fA-F]+)')
f_addrs = set()
for f in function_lines:
    m = p.search(f)
    if m != None:
        f_addrs.add(m.group(1))

print("There are " + str(len(f_addrs)) + " decompiled functions found")

# get the set of all known functions
q = re.compile(r'\(0x([0-9a-fA-F]{8})\)')
h_addrs = set()
for h in header_lines:
    n = q.search(h)
    if n != None:
        h_addrs.add(n.group(1))

print("There are " + str(len(h_addrs)) + " identified functions found")

completion = (len(h_addrs)*100)/len(f_addrs)
print("Current completion rate is " + len(h_addrs)*100/len(f_addrs) + " (" + str(round(completion, 2)) + "%)")
