cmake_minimum_required(VERSION 3.16)
project(SW_RACER_RE)

add_library(swe1r_globals INTERFACE)
target_include_directories(swe1r_globals INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_compile_definitions(swe1r_globals INTERFACE INCLUDE_DX_HEADERS=1)

file(GLOB SOURCES
    src/Dss/*c
    src/Engine/*c
    src/General/*c
    src/Gui/*.c
    src/Main/*.c
    src/Platform/*.c
    src/Primitives/*.c
    src/Raster/*.c
    src/Swr/*.c
    src/Unknown/*.c
    src/Win95/*.c
)
add_library(swe1r_functions STATIC ${SOURCES})

add_subdirectory(dinput_hook)