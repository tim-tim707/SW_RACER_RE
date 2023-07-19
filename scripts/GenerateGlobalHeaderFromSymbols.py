from jinja2 import Environment, FileSystemLoader
import os

# This generate the global variables header from the data_symbols.syms file, in order to be used by the C code

if (not str.endswith(os.getcwd(), "SW_RACER_RE")):
    print("This scripts is not running from the correct directory ! Call from the SW_RE directory like so: python scripts\Ghidra\GenerateGlobalHeaderFromSymbols.py")
    exit(1)

template_file = "./src/globals.h.j2"
env = Environment(loader=FileSystemLoader("."))
template = env.get_template(template_file)
data = {"globals": []}
with open("data_symbols.syms", "r", encoding="ascii") as global_symbols:
    for i, line in enumerate(global_symbols.readlines()):
        if len(line) <= 1:
            continue
        if line[:2] == "//":
            continue
        line = line.split("//")[0]
        global_var = {}
        tokens = line.split(" ")
        global_var["line"] = i
        global_var["name"] = tokens[0]
        global_var["address"] = tokens[1]
        global_var["type"] = " ".join(tokens[2:]).replace("\n", "") # TODO: function pointer

        global_var["new_type"] = global_var["type"]
        global_var["new_name"] = global_var["name"]
        if global_var["new_type"].count("[") >= 1:
            parts = global_var["new_type"].split("[")
            global_var["new_type"] = parts[0]
            global_var["new_name"] += "[" + ("[".join(parts[1:]))
        elif global_var["new_type"].count("=") >= 1:
            parts = global_var["new_type"].split("=")
            global_var["new_type"] = parts[0]
            global_var["new_name"] += " =" + "".join(parts[1:])
        data["globals"].append(global_var)

rendered_output = template.render(data)
with open("./src/globals.h", "w", encoding="ascii") as file:
    file.write(rendered_output)
