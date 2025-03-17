# Create the release with a command similar to:
# python dinput_hook\createReleaseArchive.py "C:\Users\Tim\Desktop\STAR WARS RACER DIR\STAR WARS Racer_OGL"

MAJOR_VERSION = 0
MINOR_VERSION = 2
REVISION = 9

import sys
import os
import zipfile

def main():
    with zipfile.ZipFile(f"model_replacement_mod_v{MAJOR_VERSION}_{MINOR_VERSION}_{REVISION}.zip", 'w', zipfile.ZIP_DEFLATED) as zipf:
        zipf.write(sys.argv[1] + "\\dinput.dll", "dinput.dll")
        zipf.write("./assets/gltf/replacement_names.md", "assets/gltf/replacement_names.md")

        shader_path = "assets/shaders"
        for root, dirs, files in os.walk(shader_path):
            for file in files:
                zipf.write(os.path.join(root, file), os.path.join(root, file))
        texture_path = "assets/textures"
        for root, dirs, files in os.walk(texture_path):
            for file in files:
                zipf.write(os.path.join(root, file), os.path.join(root, file))

if __name__ == "__main__":
    if (len(sys.argv) != 2):
        print(len(sys.argv))
        print("Missing argument for directory in which to get dinput.dll")
        sys.exit(1)

    main()
    sys.exit(0)
