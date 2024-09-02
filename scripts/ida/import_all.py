from utils import *

import idc

for (func, addr) in function_addresses.items():
    idc.set_name(addr, func)

parse_decls_with_clang(None, False)

for (name, props) in data_symbols.items():
    (addr, type) = props
    idc.set_name(addr, name)
    if type == "char":
        type = "uint8_t" # TODO hack: ida creates arrays out of "char" types automatically...

    decl = idc.parse_decl(type, idc.PT_SILENT)
    idc.apply_type(addr, decl, idc.TINFO_DEFINITE)


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