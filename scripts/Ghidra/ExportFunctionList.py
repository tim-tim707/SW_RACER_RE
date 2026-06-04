# Run this inside Ghidra Script Manager with the swep1r binary loaded

# This will take the binary and create a file with all the function names

import os

# access the ghidra decompiler
decomp = ghidra.app.decompiler.DecompInterface()
decomp.openProgram(currentProgram)

# folder paths
script_path=os.path.dirname(os.path.realpath(__file__))
c_root=script_path + "/"

# prototype file
header_fname = c_root + "master_functions.h"
header_file = open(header_fname, "w")

functions = list(currentProgram.functionManager.getFunctions(True))
for i, function in enumerate(functions):
    # write out the function signature and address
    if (i % 5 == 0):
        print("{}/{} ({}%)".format(i, len(functions), float(i) / float(len(functions)) * 100))
    dr = decomp.decompileFunction(function, 60, ghidra.util.task.TaskMonitor.DUMMY)
    df = dr.getDecompiledFunction()
    if (df is None):
        continue
    header_file.write('// ADDR_0x' + function.getEntryPoint().toString() + '\n')
    header_file.write(df.getSignature() + '\n')

print("File written at {}".format(header_fname))
header_file.close()
