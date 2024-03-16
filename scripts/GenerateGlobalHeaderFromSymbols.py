import re

from jinja2 import Environment, FileSystemLoader
import os

# This generate the global variables header from the data_symbols.syms file, in order to be used by the C code

if (not str.endswith(os.getcwd(), "SW_RACER_RE")):
    print("This scripts is not running from the correct directory ! Call from the SW_RE directory like so: python scripts\\GenerateGlobalHeaderFromSymbols.py")
    exit(1)

data = {"globals": []}
with open("data_symbols.syms", "r", encoding="ascii") as global_symbols:
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

template_file = "./src/globals.h.j2"
env = Environment(loader=FileSystemLoader("."))
template = env.get_template(template_file)
rendered_output = template.render(data)

with open("./src/globals.h", "w", encoding="ascii") as file:
    file.write(rendered_output)

template_file = "./src/globals.c.j2"
env = Environment(loader=FileSystemLoader("."))
template = env.get_template(template_file)
rendered_output = template.render(data)

with open("./src/globals.c", "w", encoding="ascii") as file:
    file.write(rendered_output)
