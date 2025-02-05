hooks using dinput.dll. Currently used for renderer replacement.


# Compiling
Instructions to compile on windows

## Installation
MingW-w64 from winlibs, gcc 14.2.0, ld.exe, cmake and make. See:

https://winlibs.com/
UCRT runtime
GCC 14.2.0 (with POSIX threads) + LLVM/Clang/LLD/LLDB 19.1.1 + MinGW-w64 12.0.0 UCRT - release 2
Win32: 7-Zip archive* | Zip archive   -   without LLVM/Clang/LLD/LLDB: 7-Zip archive* | Zip archive

Add `C:\msys64\mingw32\bin` to PATH

Install python 3 separately from the store for example

## Building the dll
In the main directory (`SW_RACER_RE/`) run the following commands in a cmd:

```
cmake .. -DPYTHON_EXECUTABLE=<your python.exe> -DGAME_DIR=<your game dir>
ninja
```

For example:
```
cmake .. -DPYTHON_EXECUTABLE=C:\Users\Tim\AppData\Local\Programs\Python\Python312\python.exe -DGAME_DIR="C:\Users\Tim\Desktop\STAR WARS RACER DIR\STAR WARS Racer_OGL"
ninja
```
or for debug build:
```
cmake .. -DCMAKE_BUILD_TYPE=Debug -DPYTHON_EXECUTABLE=C:\Users\Tim\AppData\Local\Programs\Python\Python312\python.exe -DGAME_DIR="C:\Users\Tim\Desktop\STAR WARS RACER DIR\STAR WARS Racer_OGL"
ninja
```
