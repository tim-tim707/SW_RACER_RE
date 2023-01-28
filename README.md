# SW_RE
Star Wars Episode 1 Racer Decompilation project

This is based on the repository located here: https://github.com/OpenSWE1R/swe1r-re.git, included as a submodule

The goal is to produce an exact match of the executable SWE1R.EXE downloaded from GOG, to enable greater modding capabilities.
The freshly installed GOG version has the following md5: e1fcf50c8de2dbef70e6ad8e09371322

Wine (https://www.winehq.org/) is used to run Visual C++ 5.0, the original compiler for the project. Through WSL, file transfer is much easier in both directions and Wine is much faster than a VM like Qemu or VirtualBox (and much simpler to setup as well)
