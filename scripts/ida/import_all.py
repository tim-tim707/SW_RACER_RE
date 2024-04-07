from utils import *

import idc
import ida_srclang
import ida_auto


for (func, addr) in function_addresses.items():
    idc.set_name(addr, func)


clang_argv = [
    "-target i686-pc-windows-gnu",
    "-x c",
    "-I", src_dir,
    "-I", src_dir + "/generated/"
    "-mno-sse",
    "-fsyntax-only",
    "--sysroot", "C:/mingw32",
    "-isystem", "C:/mingw32/lib/clang/12.0.0/include",
    "-isystem", "C:/mingw32/lib/gcc/i686-w64-mingw32/13.2.0/include"
]
ida_srclang.set_parser_argv("clang", " ".join(clang_argv))

decl = "\n".join([f'#include "{h}"' for h in headers])

ida_srclang.parse_decls_with_parser("clang", None, decl, False)

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