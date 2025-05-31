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
# reverse_hooks_blacklist = []
hooks_blacklist = [
    # main
    "WinMain",
    # rdMaterial
    "rdMaterial_InvertTextureAlphaR4G4B4A4",
    "rdMaterial_InvertTextureColorR4G4B4A4",
    "rdMaterial_RemoveTextureAlphaR5G5B5A1",
    "rdMaterial_RemoveTextureAlphaR4G4B4A4",
    "rdMaterial_SaturateTextureR4G4B4A4",
    # rdMatrix
    "rdMatrix_Multiply44",
    "rdMatrix_Multiply44Acc",
    "rdMatrix_TransformPoint44",
    "rdMatrix_Multiply3",
    "rdMatrix_Transform3",
    "rdMatrix_Multiply4",
    "rdMatrix_ScaleBasis44",
    "rdMatrix_Multiply34",
    "rdMatrix_PreMultiply34",
    "rdMatrix_PostMultiply34"
    "rdMatrix_TransformVector34",
    "rdMatrix_TransformPoint34",
    # std3D
    "std3D_Startup",
    "std3D_Open",
    "std3D_StartScene",
    "std3D_EndScene",
    "std3D_DrawRenderList",
    "std3D_SetRenderState",
    "std3D_AllocSystemTexture",
    "std3D_ClearTexture",
    "std3D_AddToTextureCache",
    "std3D_ClearCacheList",
    "std3D_SetTexFilterMode",
    "std3D_SetProjection",
    "std3D_AddTextureToCacheList",
    "std3D_RemoveTextureFromCacheList",
    "std3D_PurgeTextureCache",
    # stdControl
    "stdControl_Startup",
    "stdControl_ReadControls",
    "stdControl_SetActivation",
    # swrDisplay
    "swrDisplay_SetWindowSize",
    # DirectDraw
    "DirectDraw_InitProgressBar",
    "DirectDraw_Shutdown",
    "DirectDraw_BlitProgressBar",
    "DirectDraw_LockZBuffer",
    "DirectDraw_UnlockZBuffer",
    "Direct3d_SetFogMode",
    "Direct3d_IsLensflareCompatible",
    "Direct3d_ConfigFog",
    # stdConsole
    "stdConsole_GetCursorPos",
    "stdConsole_SetCursorPos",
    # stdDisplay
    "stdDisplay_Startup",
    "stdDisplay_Open",
    "stdDisplay_Close",
    "stdDisplay_SetMode",
    "stdDisplay_Refresh",
    "stdDisplay_VBufferNew",
    "stdDisplay_SetWindowMode",
    "stdDisplay_SetFullscreenMode",
    "stdDisplay_VBufferFill",
    "stdDisplay_Update",
    "stdDisplay_FillMainSurface",
    "stdDisplay_ColorFillSurface",
    # swrViewport
    "swrViewport_Render",
    # swrModel
    "swrModel_LoadFromId",
    # Window
    "Window_SetActivated",
    "Window_Resize",
    "Window_SmushPlayCallback",
    "Window_Main",
    "Window_CreateMainWindow",
    # ========== CUSTOM TRACKS ==========
    "HandleCircuits",
    "isTrackPlayable",
    "VerifySelectedTrack",
    "swrUI_GetTrackNameFromId",
    "swrObjHang_InitTrackSprites",
    "swrRace_CourseSelectionMenu",
    "swrRace_CourseInfoMenu",
    "swrRace_MainMenu",
]

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

h_files = [h[4:] if h.startswith("src\\") else h for h in h_files ]

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
                    if (function_name in hooks_blacklist):
                        continue
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
                    if (function_name in hooks_blacklist):
                        continue
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
