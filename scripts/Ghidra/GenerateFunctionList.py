# Run this inside Ghidra Script Manager with the swep1r binary loaded

# This will take the binary and create a file with all the function names

import os

# access the ghidra decompiler
decomp = ghidra.app.decompiler.DecompInterface()
decomp.openProgram(currentProgram)

# folder paths
script_path=os.path.dirname(os.path.realpath(__file__))
c_root=script_path + "./"

# prototype file
header_fname = c_root + "master_functions.h"
header_file = open(header_fname, "w")

# for each function, create an assembly file and write it out
functions = list(currentProgram.functionManager.getFunctions(True))
for function in functions:
    # write out the corresponding C function
    dr = decomp.decompileFunction(function, 60, ghidra.util.task.TaskMonitor.DUMMY)
    df = dr.getDecompiledFunction()
    header_file.write(df.getSignature() + '\n')

header_file.close()
