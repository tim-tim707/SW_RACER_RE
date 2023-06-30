# From Ghidra: Window -> Script manager -> create new script -> CV paste this to the script created
# -> Select the .h file to parse #define from
from ghidra.program.model.symbol.SourceType import *
import string

functionManager = currentProgram.getFunctionManager()

f = askFile("Select any .h", "Select any .h")

for line in file(f.absolutePath):  # note, cannot use open(), since that is in GhidraScript
    if str.startswith(line, "#define "):
        tokens = line.split(" ")
        if not str.endswith(tokens[1], "_ADDR"):
            continue
        name = tokens[1][:-5]
        address = tokens[2][3:-2] # remove (0x*)\n
        print("function is@{}@address is@{}@".format(name, address))
        address = toAddr(long(address, 16))

        func = functionManager.getFunctionAt(address)

        if func is not None:
            old_name = func.getName()
            func.setName(name, USER_DEFINED)
            print("Renamed function {} to {} at address {}".format(old_name, name, address))
        else:
            func = createFunction(address, name)
            print("Created function {} at address {}".format(name, address))
