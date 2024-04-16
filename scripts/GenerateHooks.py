import os
import re
import sys

from jinja2 import Environment, FileSystemLoader
from pathlib import Path

# automatically generate a hook entry for any function annotated with
# // <address> HOOK

# for any function annotated with // <address> (anything else), generate a
# reverse hook back to the built in function

# put in a list of .c files to scan as input and .h files they depend on

print("Generating hooks...")

# get the project root directory
script_dir = Path(os.path.dirname(os.path.realpath(__file__)))
project_root = script_dir.parent.absolute()


# split the input into c files and h files
c_files = []
h_files = []
ignore_list = ["hook_generated.c"]

if len(sys.argv[1:]) > 0:
    for item in sys.argv[1:]:
        if item.endswith(".c") and ignore_list.count(item) == 0:
            c_files.append(item)
        elif item.endswith(".h") and ignore_list.count(item) == 0:
            h_files.append(item)
else:
    for (dir_path, _, file_names) in os.walk("src"):
        for f in file_names:
            if str.endswith(f, ".h") and ignore_list.count(f) == 0:
                h_files.append(dir_path + os.sep + f)
            elif str.endswith(f, ".c") and ignore_list.count(f) == 0:
                c_files.append(dir_path + os.sep + f)

# TODO: Use a log file as well to debug when something goes wrong
print(f"Running with {h_files} and {c_files}")


hook_regex = re.compile(r"//\s*(0x[0-9A-Fa-f]{8})\s+HOOK\s*")
no_hook_regex = re.compile(r"//\s*(0x[0-9A-Fa-f]{8})\s+")
function_match = re.compile(r"(\w+)(?=\()")
comment_match = re.compile(r"^\s*(//|\/\*)")

ccode = {"hook_complete_msg": "", "functions": [], "headers": h_files}
hook_count = 0
total_count = 0
hook_address = ""
next_line_is_hooked = False
next_line_is_reverse_hooked = False
for source in c_files:
    with open(source, "r") as sourcefile:
        lines = sourcefile.readlines()
        for line in lines:
            function = {"message": "", "hook_addr": "", "hook_dst": ""}
            if next_line_is_hooked:
                next_line_is_hooked = False
                # check if function is commented out
                c = comment_match.search(line)
                if c != None:
                    continue
                # otherwise capture function name
                f = function_match.search(line)
                if f != None:
                    function_name = f.group(1)
                    function["message"] = "\"\t[Replace] " + function_name + " -> " + hook_address + "\\n\"";
                    function["name"] = function_name
                    function["hook_addr"] = hook_address
                    function["hook_dst"] = function_name
                    ccode["functions"].append(function)
                    hook_count += 1
                    total_count += 1
                continue
            if next_line_is_reverse_hooked:
                next_line_is_reverse_hooked = False
                # check if function is commented out
                c = comment_match.search(line)
                if c != None:
                    continue
                f = function_match.search(line)
                if f != None:
                    function_name = f.group(1)
                    function["message"] = "\"\t[Original] " + function_name + " <- " + hook_address + "\\n\"";
                    function["name"] = function_name
                    function["hook_addr"] = function_name
                    function["hook_dst"] = hook_address
                    ccode["functions"].append(function)
                    total_count += 1
                continue
            h = hook_regex.search(line)
            if h != None:
                hook_address = h.group(1)
                next_line_is_hooked = True
                continue
            h = no_hook_regex.search(line)
            if h != None:
                hook_address = h.group(1)
                next_line_is_reverse_hooked = True
                continue

if (total_count > 0):
    percent = float(hook_count)/float(total_count) * 100.0
    ccode["hook_complete_msg"]  = "\"Hooked [" + str(hook_count) + "/" + str(total_count) + "] functions (" + str(round(percent,2)) + "%%)\\n\"" # double %% is to escape %
else:
    ccode["hook_complete_msg"]  = "\"Total Hook Count is 0 ! Something is wrong in GenerateHooks.py\""

# write out using a jinja template
template_file_c = "/src/templates/hook_generated.c.j2"
output_file_c = os.path.join(project_root, "src", "generated", "hook_generated.c")

env = Environment(loader=FileSystemLoader(project_root))
template = env.get_template(template_file_c)
rendered_output = template.render(ccode)

with open(output_file_c, "w", encoding="ascii") as file:
    file.write(rendered_output)
    print("Generated " + output_file_c)

print("Done")
