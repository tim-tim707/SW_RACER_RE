cmake_minimum_required(VERSION 3.16)
project(SW_RACER_RE)

if (NOT GAME_DIR)
    message(FATAL_ERROR "Please set 'GAME_DIR' to point to the directory of the game.")
endif()

file(GLOB IMGUI_SOURCES imgui-master/*.cpp)
add_library(imgui STATIC
        ${IMGUI_SOURCES}
        imgui-master/backends/imgui_impl_win32.cpp
        imgui-master/backends/imgui_impl_d3d.cpp
)
target_include_directories(imgui PUBLIC imgui-master)

add_library(detours STATIC
        detours-master/src/detours.cpp
        detours-master/src/modules.cpp
        detours-master/src/disasm.cpp
        detours-master/src/image.cpp
        detours-master/src/creatwth.cpp
        detours-master/src/disolx86.cpp
)
target_include_directories(detours PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/detours-master/include)
target_compile_definitions(detours PUBLIC DETOUR_DEBUG=0)

file(GLOB HOOK_SOURCES *.c *.cpp)
add_library(dinput_hook SHARED ${HOOK_SOURCES})
target_link_libraries(dinput_hook PRIVATE swe1r_functions swe1r_globals imgui kernel32 psapi dbghelp Dwmapi dxguid detours ddraw bfd iberty sframe "C:/mingw32/bin/libzstd.dll" "C:/mingw32/bin/libintl-8.dll" "C:/mingw32/bin/zlib1.dll")
target_link_options(dinput_hook PRIVATE "-Wl,--kill-at")
set_target_properties(dinput_hook PROPERTIES
        OUTPUT_NAME dinput
        PREFIX ""
        RUNTIME_OUTPUT_DIRECTORY "${GAME_DIR}")