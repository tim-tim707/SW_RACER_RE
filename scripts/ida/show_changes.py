from utils import *

import idc
import ida_srclang
import ida_auto
import ida_bytes
import ida_funcs
import ida_nalt
import idautils
from pathlib import Path

# list all imports to skip imported names

imported_funcs = set()
nimps = ida_nalt.get_import_module_qty()

for i in range(nimps):
    def imp_cb(ea, name, ordinal):
        if name:
            imported_funcs.add(name)
        # True -> Continue enumeration
        # False -> Stop enumeration
        return True
    ida_nalt.enum_import_names(i, imp_cb)

data_sym_names = set(data_symbols.keys())

script_dir = Path(__file__).parent

out_header = open(script_dir / "new_functions.h", "w")
out_syms = open(script_dir / "new_data.syms", "w")

def try_fix_type(type_string):
    return type_string.replace("__int16", "short").replace("__cdecl", "")

prev_data_sym = None

for ea, name in idautils.Names():
    f = ida_bytes.get_flags(ea)
    if name.startswith("jpt_") or name.startswith("__imp_"):
        continue

    if not ida_bytes.has_user_name(f):
        continue

    if ida_bytes.is_func(f):
        func = ida_funcs.get_func(ea)
        if func.flags & ida_funcs.FUNC_LIB:
            continue

        if name in imported_funcs:
            continue

        if name not in function_addresses:
            print("NEW FUNCTION: %x: %s" % (ea, name))
            type = try_fix_type(str(idc.get_type(ea)))
            paren_index = type.find("(")

            out_header.write(
f"""#define {name}_ADDR (0x{ea:08X})
{type[0:paren_index]} {name}{type[paren_index:]};

// 0x{ea:08X}
{type[0:paren_index]} {name}{type[paren_index:]} {{
    HANG(\"TODO\");
}}


""")


    elif ida_bytes.is_data(f):
        if name in imported_funcs:
            continue

        if str(name) not in data_sym_names:
            print("NEW DATA: %x: %s" % (ea, name))
            type = try_fix_type(str(idc.get_type(ea)))
            if prev_data_sym is not None and prev_data_sym[1] in data_sym_names:
                out_syms.write(f"\n\n# after 0x{prev_data_sym[0]:08X}\n")

            out_syms.write(f"{name} 0x{ea:08X} {type.replace(' ', '')}\n")

        prev_data_sym = (ea, name)


out_header.close()
out_syms.close()