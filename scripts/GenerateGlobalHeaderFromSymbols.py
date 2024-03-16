import re

from jinja2 import Environment, FileSystemLoader
import os

from pathlib import Path

# This generate the global variables header from the data_symbols.syms file, in order to be used by the C code

# get the project root directory
script_dir = Path(os.path.dirname(os.path.realpath(__file__)))
project_root = script_dir.parent.absolute()

data_syms_file = os.path.join(project_root, "data_symbols.syms")

data = {"globals": []}
with open(data_syms_file, "r", encoding="ascii") as global_symbols:
    for i, line in enumerate(global_symbols.readlines()):
        if len(line) <= 1:
            continue
        if line[:2] == "//":
            continue
        if line[:1] == "#":
            continue
        line = line.split("//")[0]
        line = line.split("#")[0]
        global_var = {}
        tokens = line.split(" ")
        global_var["line"] = i
        global_var["name"] = tokens[0]
        global_var["address"] = tokens[1]
        global_var["type"] = " ".join(tokens[2:]).replace("\n", "") # TODO: function pointer
        global_var["array_specifier"] = ""

        global_var["new_type"] = global_var["type"]
        global_var["new_name"] = global_var["name"]
        if global_var["new_type"].count("=") >= 1:
            parts = global_var["new_type"].split("=")
            global_var["new_type"] = parts[0]
            global_var["value"] = " =" + "".join(parts[1:])
        # [] case
        if global_var["new_type"].count("[") >= 1:
            parts = global_var["new_type"].split("[")
            global_var["new_type"] = parts[0]
            global_var["array_specifier"] = "[" + ("[".join(parts[1:]))

        if global_var["new_type"].count("(") >= 1:
            if not re.match(".+\\(\\*\\)\\([^)]*\\)", global_var["new_type"]):
                print("TODO: function type '" + global_var["new_type"] + "' too complicated to parse.")
                exit(1)

            split_index = global_var["new_type"].index("(*)")
            type = global_var["new_type"]
            global_var["new_type"] = type[0:split_index]
            global_var["function_specifier"] = type[split_index+3:]


        global_var["new_type"] = global_var["new_type"].strip()
        global_var["new_name"] = global_var["new_name"].strip()
        data["globals"].append(global_var)

output_file_h = os.path.join(project_root, "src", "globals.h")
output_file_c = os.path.join(project_root, "src", "globals.c")

env = Environment(loader=FileSystemLoader(project_root))
template = env.get_template("/src/globals.h.j2")
rendered_output = template.render(data)

with open(output_file_h, "w", encoding="ascii") as file:
    file.write(rendered_output)

env = Environment(loader=FileSystemLoader(project_root))
template = env.get_template("src/globals.c.j2")
rendered_output = template.render(data)

with open(output_file_c, "w", encoding="ascii") as file:
    file.write(rendered_output)
