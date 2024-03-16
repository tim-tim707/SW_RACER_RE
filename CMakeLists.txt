cmake_minimum_required(VERSION 3.16)
project(SW_RACER_RE)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_compile_options(
    -Wno-multichar
    -Werror=incompatible-pointer-types
    -Werror=implicit-function-declaration
    -mfpmath=387
)

# automatically generate globals.h/globals.c if data_symbols.syms is updated
add_custom_command(
    OUTPUT global_touch.stamp
    COMMAND ${CMAKE_COMMAND} -E touch global_touch.stamp
    COMMAND ${PYTHON_EXECUTABLE} ${CMAKE_SOURCE_DIR}/scripts/GenerateGlobalHeaderFromSymbols.py
    DEPENDS ${CMAKE_SOURCE_DIR}/data_symbols.syms
)
add_custom_target(generate_global_h ALL DEPENDS global_touch.stamp)

add_library(swe1r_globals INTERFACE)
target_include_directories(swe1r_globals INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_compile_definitions(swe1r_globals INTERFACE INCLUDE_DX_HEADERS=1)

file(GLOB SOURCES
    # base files
    src/swr.c
    src/stdPlatform.c
    # specifics
    src/Dss/*c
    src/Engine/*c
    src/General/*c
    src/Gui/*.c
    src/Main/*.c
    src/Platform/*.c
    src/Primitives/*.c
    src/Raster/*.c
    src/Unknown/*.c
    src/Win95/*.c
    # only add some of Swr at the moment because its a bit unfinished
    src/Swr/*.c
)
add_library(swe1r_functions OBJECT ${SOURCES})
add_dependencies(swe1r_functions generate_global_h)
target_include_directories(swe1r_functions PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(swe1r_functions PUBLIC swe1r_globals winmm Comctl32)

add_subdirectory(dinput_hook)
