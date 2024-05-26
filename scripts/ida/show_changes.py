from utils import *

import idc
import ida_srclang
import ida_auto
import ida_bytes
import ida_funcs
import ida_nalt
import ida_typeinf
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

out_types = open(script_dir / "new_types.h", "w")

def all_type_names(til):
    type = ida_typeinf.first_named_type(til, ida_typeinf.NTF_TYPE)

    while type:
        yield type
        type = ida_typeinf.next_named_type(til, type, ida_typeinf.NTF_TYPE)


til_windows = ida_typeinf.new_til("temp_windows.til", "test")
parse_decls_with_clang(til_windows, True)

windows_types = set(all_type_names(til_windows))

til_old = ida_typeinf.new_til("temp.til", "test")
parse_decls_with_clang(til_old, False)

til_cur = ida_typeinf.get_idati()

def dump_struct(name, tif, out, comments):
    print(f"struct {name}{{", file=out)

    data = ida_typeinf.udt_type_data_t()
    tif.get_udt_details(data)
    for member in data:
        print(f"    {member.type} {member.name}; // 0x{member.offset//8:x} {comments.get(member.offset, '')}", file=out)

    print(f"}};", file=out)
    print(file=out)

def diff_struct_members(tif_old, tif_new):
    changed_members = {}

    data_old = ida_typeinf.udt_type_data_t()
    tif_old.get_udt_details(data_old)

    members_old = {}
    for member in data_old:
        members_old[member.offset] = (member.name, member.size, str(member.type) if not member.type.is_anonymous_udt() else "")

    data_new = ida_typeinf.udt_type_data_t()
    tif_new.get_udt_details(data_new)
    for member in data_new:
        if member.offset not in members_old:
            changed_members[member.offset] = "new"
        else:
            changes = []
            (name, size, type) = members_old[member.offset]
            if member.name != name:
                changes.append("name")
            if member.size != size:
                changes.append("size")
            if (str(member.type) if not member.type.is_anonymous_udt() else "") != type:
                changes.append("type")

            if len(changes) != 0:
                changed_members[member.offset] = "changed " + ",".join(changes)

    return changed_members


for type in all_type_names(til_cur):
    if type in windows_types:
        continue

    tif = ida_typeinf.tinfo_t()
    tif.get_named_type(til_cur, type, ida_typeinf.BTF_STRUCT)

    if not tif.is_struct() or tif.is_anonymous_udt():
        continue

    tif_old = ida_typeinf.tinfo_t()
    if not tif_old.get_named_type(til_old, type, ida_typeinf.BTF_STRUCT):
        print(f"new struct: {type}")

        print("// NEW:", file=out_types)
        dump_struct(type, tif, out_types, {})
    else:
        changes = diff_struct_members(tif_old, tif)
        if len(changes) != 0:
            print(f"changed struct: {type}")
            print("// CHANGED:", file=out_types)
            dump_struct(type, tif, out_types, changes)


out_types.close()