cmake_minimum_required(VERSION 3.16)
project(SW_RACER_RE)

add_link_options(-static -static-libgcc)

file(GLOB IMGUI_SOURCES imgui-1.91.1/*.cpp)
add_library(imgui STATIC
        ${IMGUI_SOURCES}
        imgui-1.91.1/backends/imgui_impl_win32.cpp
        imgui-1.91.1/backends/imgui_impl_dx9.cpp
        imgui-1.91.1/backends/imgui_impl_glfw.cpp
        imgui-1.91.1/backends/imgui_impl_opengl3.cpp
        imgui-1.91.1/misc/cpp/imgui_stdlib.cpp
)
target_include_directories(imgui PUBLIC imgui-1.91.1 imgui-1.91.1/misc/cpp imgui-1.91.1/backends)
target_link_libraries(imgui PUBLIC glfw)

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

add_subdirectory(fastgltf-0.8.0)

set(CMAKE_CXX_FLAGS_DEBUG_INIT "-DDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE_INIT "-DNDEBUG")

# Embed the GLSL shaders into the DLL so the GL renderer runs even when the
# assets/ directory is absent (issue #236). readFileAsString() falls back to
# these copies when a shader file is not found on disk.
set(EMBEDDED_SHADERS_HEADER ${CMAKE_CURRENT_BINARY_DIR}/generated/embedded_shaders.h)
file(GLOB SHADER_FILES ${CMAKE_CURRENT_SOURCE_DIR}/../assets/shaders/*.vert
                       ${CMAKE_CURRENT_SOURCE_DIR}/../assets/shaders/*.frag)
add_custom_command(
    OUTPUT ${EMBEDDED_SHADERS_HEADER}
    COMMAND ${PYTHON_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/generate_embedded_shaders.py
            ${CMAKE_CURRENT_SOURCE_DIR}/../assets/shaders ${EMBEDDED_SHADERS_HEADER}
    DEPENDS ${SHADER_FILES} ${CMAKE_CURRENT_SOURCE_DIR}/generate_embedded_shaders.py
    COMMENT "Embedding GLSL shaders into dinput_hook"
    VERBATIM
)
add_custom_target(generate_embedded_shaders ALL DEPENDS ${EMBEDDED_SHADERS_HEADER})

if (NOT USE_RELEASE_HOOK)
    file(GLOB HOOK_SOURCES *.c *.cpp *.h game_deltas/*.c game_deltas/*.cpp game_deltas/*.h nv_dds/*.h nv_dds/*.cpp)
    add_library(dinput_hook SHARED
        ${HOOK_SOURCES}
        ${EMBEDDED_SHADERS_HEADER}
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/generated/hook_generated.c
    )
    add_dependencies(dinput_hook generate_embedded_shaders)
    target_include_directories(dinput_hook PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/generated)
    target_compile_definitions(dinput_hook PRIVATE ENABLE_GLFW_INPUT_HANDLING=0)
    target_compile_definitions(dinput_hook PRIVATE ENABLE_GAMEPAD_NAV=1)
    target_compile_definitions(dinput_hook PRIVATE ENABLE_UNIFIED_CONTROLS=1)
    target_link_libraries(dinput_hook PRIVATE swe1r_functions swe1r_globals imgui kernel32  Dwmapi dxguid detours ddraw opengl32 glad glfw fastgltf)
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
