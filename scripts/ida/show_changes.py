from utils import *

import idc
import ida_srclang
import ida_auto
import ida_bytes
import ida_funcs
import ida_nalt
import idautils

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

for ea, name in idautils.Names():
    f = ida_bytes.get_flags(ea)
    if name.startswith("jpt_"):
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

    elif ida_bytes.is_data(f):
        if name in imported_funcs:
            continue

        if str(name) not in data_sym_names:
            print("NEW DATA: %x: %s" % (ea, name))



