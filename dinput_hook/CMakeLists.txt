cmake_minimum_required(VERSION 3.16)
project(SW_RACER_RE)

file(GLOB IMGUI_SOURCES thirdparty/imgui-1.91.1/*.cpp)
add_library(imgui STATIC
        ${IMGUI_SOURCES}
        thirdparty/imgui-1.91.1/backends/imgui_impl_win32.cpp
        thirdparty/imgui-1.91.1/backends/imgui_impl_dx9.cpp
        thirdparty/imgui-1.91.1/backends/imgui_impl_glfw.cpp
        thirdparty/imgui-1.91.1/backends/imgui_impl_opengl3.cpp
        thirdparty/imgui-1.91.1/misc/cpp/imgui_stdlib.cpp
)
target_include_directories(imgui PUBLIC thirdparty/imgui-1.91.1 thirdparty/imgui-1.91.1/misc/cpp thirdparty/imgui-1.91.1/backends)
target_link_libraries(imgui PUBLIC glfw)

add_library(detours STATIC
        thirdparty/detours-master/src/detours.cpp
        thirdparty/detours-master/src/modules.cpp
        thirdparty/detours-master/src/disasm.cpp
        thirdparty/detours-master/src/image.cpp
        thirdparty/detours-master/src/creatwth.cpp
        thirdparty/detours-master/src/disolx86.cpp
)
target_include_directories(detours PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/thirdparty/detours-master/include)
target_compile_definitions(detours PUBLIC DETOUR_DEBUG=0)

add_subdirectory(thirdparty/glfw-master)

add_library(glad STATIC thirdparty/glad/src/glad.c)
target_include_directories(glad PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/thirdparty/glad/include)

if (NOT USE_RELEASE_HOOK)
    file(GLOB HOOK_SOURCES src/*.c src/*.cpp src/*.h src/hooks/*.cpp src/hooks/*.h src/utils/*.cpp src/utils/*.h thirdparty/tinygltf/*.cpp thirdparty/tinygltf/*.h thirdparty/tinygltf/*.hpp)
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
endif()
