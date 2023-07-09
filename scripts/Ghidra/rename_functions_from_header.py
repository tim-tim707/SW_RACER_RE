# From Ghidra: Window -> Script manager -> create new script -> CV paste this to the script created
# -> Select the .h file to parse #define from

# Doesn't allow for multiline function declaration !
# const identifier is ignored

# Types must already be parsed from the types.h file !

from ghidra.app.util.parser import FunctionSignatureParser
from ghidra.app.services import DataTypeManagerService
from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
from ghidra.program.model.symbol.SourceType import USER_DEFINED
import string


f = askFile("Select any .h to parse functions definitions from", "Select any .h to parse functions definitions from")

functions_addresses = []
functions_names = []
functions_prototypes = {}
functions_prototypes_nb = 0

functionManager = currentProgram.getFunctionManager()
dtm = currentProgram.dataTypeManager
dtms = state.tool.getService(DataTypeManagerService)
parser = FunctionSignatureParser(dtm, dtms)

for line in file(f.absolutePath):  # note, cannot use open(), since that is in GhidraScript
    # Parse #define function_ADDR (0xADDR)
    # print("Parsing line @{}@".format(line))
    if line[:2] == "//": continue
    line = line.split("//")[0]

    if str.startswith(line, "#define "):
        tokens = line.split(" ")
        if not str.endswith(tokens[1], "_ADDR"):
            continue
        name = tokens[1][:-5]
        address = tokens[2][3:-2] # remove (0x*)\n
        print("function is@{}@address is@{}@".format(name, address))
        functions_addresses.append(toAddr(long(address, 16)))
        functions_names.append(name)
    # Parse function declaration
    elif str.endswith(line, ";\n"):
        for name in functions_names:
            if str.count(line, name + "(") >= 1: # Important to check the opening parenthesis !
                functions_prototypes[name] = line[:-2] # strip the ';'
                functions_prototypes_nb += 1

if len(functions_addresses) != functions_prototypes_nb:
    print("Error: number of addresses parsed and prototypes found are not the same: addresses: {} prototypes: {}".format(len(functions_addresses), functions_prototypes_nb))
    for name in functions_names:
        print("name: ", name)
    for prototype in functions_prototypes:
        print("prototype: ", prototype)
    exit(1)

for i, address in enumerate(functions_addresses):
    name = functions_names[i]
    signature = functions_prototypes[name]
    func = functionManager.getFunctionAt(address)

    if func is not None and signature != "":
        old_signature = func.getPrototypeString(True, True)
        sig = parser.parse(None, signature.replace("const", "")) # Discard const qualifier
        cmd = ApplyFunctionSignatureCmd(address, sig, USER_DEFINED)
        cmd.applyTo(currentProgram, monitor)
        print("Updated function {} to {} at address {}".format(old_signature, signature, address))
    elif func is None:
        func = createFunction(address, name)
        sig = parser.parse(None, signature)
        cmd = ApplyFunctionSignatureCmd(address, sig, USER_DEFINED)
        cmd.applyTo(currentProgram, monitor)
        print("Created function {} at address {}".format(signature, address))
