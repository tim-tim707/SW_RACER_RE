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
    OUTPUT
        ${CMAKE_CURRENT_BINARY_DIR}/global_touch.stamp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/generated/globals.h
        ${CMAKE_CURRENT_SOURCE_DIR}/src/generated/globals.c
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
    src/main.c
    src/swr.c
    src/stdPlatform.c
    # specifics
    src/Dss/*c
    src/Engine/*.c
    src/General/*.c
    src/Gui/*.c
    src/Main/*.c
    src/Platform/*.c
    src/Primitives/*.c
    src/Raster/*.c
    src/Unknown/*.c
    src/Win95/*.c
    src/Swr/*.c
)
add_library(swe1r_functions OBJECT ${SOURCES})
add_dependencies(swe1r_functions generate_global_h)
target_include_directories(swe1r_functions PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_include_directories(swe1r_functions PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src/generated)
target_link_libraries(swe1r_functions PUBLIC swe1r_globals winmm Comctl32 dxguid)

# based on $SOURCES, generate the hooked functions
set(HOOK_HEADER_FILES "")
file(GLOB_RECURSE HOOK_HEADER_FILES RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}/src" "src/*.h")
add_custom_command(
    OUTPUT
        ${CMAKE_CURRENT_BINARY_DIR}/generated_hooks.stamp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/generated/hook_generated.c
    COMMAND ${CMAKE_COMMAND} -E touch generated_hooks.stamp
    COMMAND ${PYTHON_EXECUTABLE} ${CMAKE_SOURCE_DIR}/scripts/GenerateHooks.py ${SOURCES} ${HOOK_HEADER_FILES}
    DEPENDS ${SOURCES}
)
add_custom_target(generate_hooks ALL DEPENDS generated_hooks.stamp)

# create our hook library
file(GLOB HOOK_SOURCES
    src/hook.c
    src/generated/hook_generated.c
    src/dllMainDInput.c)
add_library(dinput_hook SHARED ${HOOK_SOURCES})
add_dependencies(dinput_hook generate_hooks)
target_link_libraries(dinput_hook PRIVATE swe1r_functions swe1r_globals ddraw)
target_link_options(dinput_hook PRIVATE "-Wl,--kill-at")

if (GAME_DIR)
    set_target_properties(dinput_hook PROPERTIES
            OUTPUT_NAME dinput
            PREFIX ""
            RUNTIME_OUTPUT_DIRECTORY "${GAME_DIR}")
else()
    message(WARNING "Set 'GAME_DIR' to the directory of the game to automatically place 'dinput.dll' there when building.")
endif()
