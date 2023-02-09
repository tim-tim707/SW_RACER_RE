# SW_RE
Star Wars Episode 1 Racer Decompilation project

This is based on the repository located here: https://github.com/OpenSWE1R/swe1r-re.git, included as a submodule

The goal is to produce an exact match of the executable SWE1R.EXE downloaded from GOG, to enable greater modding capabilities.
The freshly installed GOG version has the following md5: e1fcf50c8de2dbef70e6ad8e09371322

Wine (https://www.winehq.org/) is used to run Visual C++ 5.0, the original compiler for the project. Through WSL, file transfer is much easier in both directions and Wine is much faster than a VM like Qemu or VirtualBox (and much simpler to setup as well)

I used Ghidra to output a ~102523 lines file with more than a thousand functions called `SWEP1RCR_dump.c`: It contains pseudo-C that will help to decompile faster

# Useful resources:

Link to A3D headers and macros: https://github.com/OpenSWE1R/openswe1r/wiki/Useful-Resources


See NOTES.md for more infos

# Additionnal Informations

Except for A3D, everything must be -std=c89 or -std=c90
`inline` is c99 so we cannot use it /!\ Simply use `static` or Macros instead
