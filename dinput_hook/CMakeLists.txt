cmake_minimum_required(VERSION 3.16)
project(SW_RACER_RE)

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

add_subdirectory(glfw-master)

add_library(glad STATIC glad/src/glad.c)
target_include_directories(glad PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/glad/include)

file(GLOB HOOK_SOURCES *.c *.cpp *.h)
add_library(dinput_hook SHARED
    ${HOOK_SOURCES}
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/generated/hook_generated.c
)
target_link_libraries(dinput_hook PRIVATE swe1r_functions swe1r_globals imgui kernel32  Dwmapi dxguid detours ddraw opengl32 glad glfw)
target_link_options(dinput_hook PRIVATE "-Wl,--kill-at")

if (GAME_DIR)
    set_target_properties(dinput_hook PROPERTIES
            OUTPUT_NAME dinput
            PREFIX ""
            RUNTIME_OUTPUT_DIRECTORY "${GAME_DIR}")
else()
    message(WARNING "Set 'GAME_DIR' to the directory of the game to automatically place 'dinput.dll' there when building.")
endif()