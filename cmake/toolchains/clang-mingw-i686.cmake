# clang targeting 32-bit MinGW (the game is i686). Works with llvm-mingw
# (https://github.com/mstorsjo/llvm-mingw) and with the clang bundled in WinLibs.
#
# clang is looked up in $LLVM_MINGW_ROOT/bin first, then on PATH.

set(SWR_CLANG_HINTS "")
if (DEFINED ENV{LLVM_MINGW_ROOT})
    file(TO_CMAKE_PATH "$ENV{LLVM_MINGW_ROOT}/bin" SWR_CLANG_HINTS)
endif ()

find_program(SWR_CLANG clang HINTS ${SWR_CLANG_HINTS} REQUIRED)
find_program(SWR_CLANGXX clang++ HINTS ${SWR_CLANG_HINTS} REQUIRED)
get_filename_component(SWR_CLANG_BIN ${SWR_CLANG} DIRECTORY)

set(CMAKE_C_COMPILER ${SWR_CLANG})
set(CMAKE_CXX_COMPILER ${SWR_CLANGXX})
set(CMAKE_C_COMPILER_TARGET i686-w64-mingw32)
set(CMAKE_CXX_COMPILER_TARGET i686-w64-mingw32)

# Make ships with llvm-mingw; only for the MinGW Makefiles generator (the presets use Ninja).
if (CMAKE_GENERATOR STREQUAL "MinGW Makefiles" AND NOT CMAKE_MAKE_PROGRAM
        AND EXISTS ${SWR_CLANG_BIN}/mingw32-make.exe)
    set(CMAKE_MAKE_PROGRAM ${SWR_CLANG_BIN}/mingw32-make.exe CACHE FILEPATH "")
endif ()
