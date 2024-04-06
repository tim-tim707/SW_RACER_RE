# Star Wars Episode 1 Racer Decompilation Project

The goal of this repository is to document and re-implement functions of the original game for modding purposes.
The project is heavily influenced by the [OpenJKDF2](https://github.com/shinyquagsire23/OpenJKDF2) project

This makes use of DLL injection through a simple loader located at `./loader/loader.cpp`
The code for the DLL to inject is at `./src`

For development the `dinput.dll` at `./dinput_hook` is used (see section Development for more information).

## Progress
The progress here lists the functions which have been analysed (not necessarily re-implemented)
- 25 October 2023, 30.54% (656 / 2148).
- 30 March 2024, 51.3% (1106 / 2156)

## Programs used
- git
- Ghidra 10.2.2 (important for the ret-sync plugin)
- x32dbg

## File formats
blocks are still TODO

MAT file: https://www.massassi.net/
See also for COG and MOTS

## Contribute
This repository is still in early developement. Usage is not yet possible other than for decompilation purposes.

If you want to contribute, you'll need python, a windows C compiler and Ghidra.
Symbols can be imported using scripts in the `scripts/Ghidra` directory. You should "Parse C source" on the `src/types.h` file
before using the scripts to import functions prototypes via headers. Global variables can be imported from the
data\_symbols.syms file using the `GenerateGlobalHeaderFromSymbols.py` script in the `scripts/` directory. This will automatically
be generated at compile time when using the cmake build.

Update all submodules (for developpement purposes only):
`git submodule update --init --recursive`

## Development

Use 32-Bit MinGW and CMake to build the `dinput.dll` hook ([WinLibs GCC 13.2.0 (POSIX threads) + MinGW-w64 11.0.1 UCRT (release 5) i686](https://github.com/brechtsanders/winlibs_mingw/releases/tag/13.2.0posix-17.0.6-11.0.1-ucrt-r5) is known to work). If `-DGAME_DIR=<game directory>` is passed as a CMake parameter the compiled `dinput.dll` is automatically placed into the game directory.

The hook writes debug information into `hook.log` while running and makes all original game functions callable, as long as they have a valid address and function prototype in `./src`.

To test the decompilation of single functions they can be marked with a `// 0xADDRESS HOOK` comment to replace the original function in the game:

```cpp
// 0x004238d0 HOOK
int __stdcall WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PSTR pCmdLine, int nCmdShow)
{
    ... this function will be called instead of the original WinMain function.
}
```

Remove the word `HOOK` if you don't want to replace the original function:

```
// 0x004238d0
int __stdcall WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PSTR pCmdLine, int nCmdShow)
{
    ... this function will NOT be called.
}
```

## Usage

Run `compile.bat` script. The loader and the replacement dll should be generated in the `./build` directory. Copy these two files WITHOUT renaming them into the same directory as `SWEP1RCR.EXE`. Run the loader.

TODO Install python, gcc, g++ with MSYS2, git bash


This is based on the repository located [here](https://github.com/OpenSWE1R/swe1r-re.git), included as a submodule

The freshly installed GOG version of the game (`SWEP1RCR.EXE`) has the following md5: e1fcf50c8de2dbef70e6ad8e09371322
Other versions are not yet tested

[Wine](https://www.winehq.org/) will be used to run Visual C++ 5.0, the original compiler for the project. Through WSL, file transfer is much easier in both directions and Wine is much faster than a VM like Qemu or VirtualBox (and much simpler to setup as well)

Download the vcpp5 iso for initial compiler configuration here: https://winworldpc.com/product/visual-c/5x

See NOTES.md for more infos

## Special Thanks
Special thanks goes to
- George Lucas
- the LucasArt team that made all these years of fun possible,
- JayFoxRox for the original work on the decompilation back in 2018,
- LightningPirate and Galeforce from the SWEP1RCR discord community for their work on asset packing and decomp,
- Aphex from the SWEP1RCR discord for his work on asset export to modern file formats and decompilation symbols.
- Urgon from the Indiana Jones and the Infernal Machine decomp project, for his bindiff with swe1r

## Copyright Disclaimer
The original game (Star Wars Episode 1 Racer) is a property of the LucasArts Entertainment Company LLC.

## Fair Use Disclaimer
The content provided on this repository is for informational and educational purposes only. It is not intended to infringe upon any copyrighted material.

If you believe that any content on this repository violates your copyright or intellectual property rights, please contact us immediately to seek resolution.

I am not liable for any loss or damage, including but not limited to indirect or consequential loss or damage, arising from the use of or reliance on any content found on this repository.
