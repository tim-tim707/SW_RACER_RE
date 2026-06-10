# From Ghidra: Window -> Script manager -> create new script -> CV paste this to the script created
# -> Select the .h file to parse #define from

# Doesn't allow for multiline function declaration !
# Some identifiers are ignored ! See cleanupSignature

# Types must already be parsed from the types.h file !

from ghidra.app.util.parser import FunctionSignatureParser
from ghidra.app.services import DataTypeManagerService
from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
from ghidra.program.model.symbol.SourceType import USER_DEFINED
import string

def cleanupSignature(s):
    ignored = ["const", "__stdcall", "__cdecl", "__thiscall"]
    for identifier in ignored:
        s = s.replace(identifier, "")
    return s

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
    if line[-1] == '\n':
        line = line[:-1]
    if len(line) == 0: continue
    if line[-1] == ' ':
        line = line[:-1]
    if len(line) == 0: continue

    if str.startswith(line, "#define "):
        tokens = line.split(" ")
        if not str.endswith(tokens[1], "_ADDR"):
            continue
        name = tokens[1][:-5]
        address = tokens[2][3:-1] # remove (0x*)
        # print("function is@{}@address is@{}@".format(name, address))
        functions_addresses.append(toAddr(long(address, 16)))
        functions_names.append(name)
    # Parse function declaration
    elif line[-1] == ';':
        for name in functions_names:
            if str.count(line, name + "(") >= 1: # Important to check the opening parenthesis !
                if (name in functions_prototypes):
                    print("Warning: duplicate of {}".format(name))
                else:
                    functions_prototypes[name] = line[:-1] # strip the ';'
                    functions_prototypes_nb += 1

if len(functions_addresses) != functions_prototypes_nb:
    print("Error: number of addresses parsed and prototypes found are not the same: addresses: {} prototypes: {}".format(len(functions_addresses), functions_prototypes_nb))
    # Remove matching functions to find the missing ones
    i = 0
    while i < len(functions_names):
        if (functions_names[i] in functions_prototypes):
            functions_prototypes.pop(functions_names[i])
            functions_names.pop(i)
            continue
        i += 1
    for name in functions_names:
        print("name: ", name)
    for prototype in functions_prototypes:
        print("prototype: ", prototype)
    exit(1)

applied = 0
renamed_only = 0
failed = []
name_conflicts = []
for i, address in enumerate(functions_addresses):
    name = functions_names[i]
    signature = functions_prototypes[name]
    func = functionManager.getFunctionAt(address)

    if func is None:
        func = createFunction(address, name)
        if func is None:
            print("Skipped {}: could not create function at {}".format(name, address))
            failed.append(name)
            continue
    else:
        # Duplicate check: this address already has a function. If it already
        # carries a curated (non-default) name that differs from the header's,
        # the header is about to rename an established symbol -- flag it so a
        # parallel/wrong name doesn't silently overwrite the canonical one.
        existing = func.getName()
        if (existing != name
                and not existing.startswith("FUN_")
                and not existing.startswith("thunk_FUN_")):
            print("Warning: {} is already named '{}' but the header defines it as '{}'".format(address, existing, name))
            name_conflicts.append((str(address), existing, name))

    try:
        cleanedSignature = cleanupSignature(signature)
        sig = parser.parse(None, cleanedSignature)
        cmd = ApplyFunctionSignatureCmd(address, sig, USER_DEFINED)
        if (cmd.applyTo(currentProgram, monitor)):
            applied += 1
        else:
            print("Error applying signature for {} at {}".format(name, address))
            failed.append(name)
    except:  # bare except: also catches Java exceptions (e.g. ParseException on function pointer params)
        # signature did not parse, at least apply the name
        try:
            func.setName(name, USER_DEFINED)
            renamed_only += 1
            print("Renamed only (signature unparseable): {} at {}".format(name, address))
        except:
            print("Failed entirely: {} at {}".format(name, address))
            failed.append(name)

print("Done: {} signatures applied, {} renamed only, {} failed, {} name conflicts".format(applied, renamed_only, len(failed), len(name_conflicts)))
for name in failed:
    print("  failed: {}".format(name))
for addr, existing, wanted in name_conflicts:
    print("  name conflict @ {}: DB has '{}', header wants '{}'".format(addr, existing, wanted))
