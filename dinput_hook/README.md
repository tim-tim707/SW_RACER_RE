# HD replacement Mod Project

This mod enable artists to use glb and gltf 3D models as replacement models for the game.
Simply download a release zip, unzip it in the same directory as your game, add your 3d models in the `assets/gltf/` directory and run the game.
The 3D models need a specific name to be detected by the mod. The list is in the `replacement_names.md` file in the same directory.
Pods also need a specific structure: Three nodes named `cockpit`, `engineR` and `engineL` to be properly displayed.

This uses dll injection from the `dinput.dll` custom dll, which will replace some of the original game functions with our own.
If you want to uninstall this mod, remove `dinput.dll` and the `assets/` directory.

This mod also output some debug log in the `hook_log.txt` file. If your game crashes unexpectedly, the informations contained in it can often be used to understand what is happenning.

# Building
Instructions to compile on windows

## Build Setup
MingW-w64 from winlibs, gcc 14.2.0, ld.exe, cmake and make. See:

https://winlibs.com/
UCRT runtime
GCC 14.2.0 (with POSIX threads) + LLVM/Clang/LLD/LLDB 19.1.1 + MinGW-w64 12.0.0 UCRT - release 2
Win32: 7-Zip archive* | Zip archive   -   without LLVM/Clang/LLD/LLDB: 7-Zip archive* | Zip archive

Add `C:\msys64\mingw32\bin` to PATH

Install python 3 separately (from the windows store for example)

## Compiling
In the main directory (`SW_RACER_RE/`) run the following commands in a cmd:

```
cmake .. -DPYTHON_EXECUTABLE=<your python.exe> -DGAME_DIR=<your game dir>
ninja
```

For example:
```
cmake .. -DCMAKE_BUILD_TYPE=Release -DPYTHON_EXECUTABLE=C:\Users\Tim\AppData\Local\Programs\Python\Python312\python.exe -DGAME_DIR="C:\Users\Tim\Desktop\STAR WARS RACER DIR\STAR WARS Racer_OGL"
ninja
```
or for debug build:
```
cmake .. -DCMAKE_BUILD_TYPE=Debug -DPYTHON_EXECUTABLE=C:\Users\Tim\AppData\Local\Programs\Python\Python312\python.exe -DGAME_DIR="C:\Users\Tim\Desktop\STAR WARS RACER DIR\STAR WARS Racer_OGL"
ninja
```
which activate a separate scene to test gltf rendering, as well as having debug symbols
