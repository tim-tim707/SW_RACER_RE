# libFuzzer harnesses for parsers of untrusted files (ENABLE_FUZZERS; run with scripts/run_fuzzers.py).
# clang refuses -fsanitize=fuzzer for MinGW targets, so instrument with the coverage flags it implies
# and link the runtime by hand.

execute_process(
        COMMAND ${CMAKE_CXX_COMPILER} --target=${CMAKE_CXX_COMPILER_TARGET} -print-resource-dir
        OUTPUT_VARIABLE SWR_CLANG_RESOURCE_DIR OUTPUT_STRIP_TRAILING_WHITESPACE)
find_file(SWR_LIBFUZZER libclang_rt.fuzzer-i386.a HINTS ${SWR_CLANG_RESOURCE_DIR}/lib/windows
          NO_DEFAULT_PATH REQUIRED)

set(SWR_FUZZ_COMPILE_FLAGS -g -O1 -fsanitize=address
    -fsanitize-coverage=inline-8bit-counters,indirect-calls,trace-cmp,pc-table)
set(SWR_IMGUI_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../dinput_hook/imgui-1.91.1)

function(swr_add_fuzzer name)
    add_executable(${name} ${ARGN})
    target_include_directories(${name} PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/../src
            ${CMAKE_CURRENT_SOURCE_DIR}/../dinput_hook
            ${SWR_IMGUI_DIR})
    target_compile_definitions(${name} PRIVATE INCLUDE_DX_HEADERS=1)
    target_compile_options(${name} PRIVATE ${SWR_FUZZ_COMPILE_FLAGS})
    target_link_options(${name} PRIVATE -fsanitize=address)
    target_link_libraries(${name} PRIVATE ${SWR_LIBFUZZER})
    if (SWR_ASAN_RUNTIME_DLLS)
        add_custom_command(TARGET ${name} POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy_if_different ${SWR_ASAN_RUNTIME_DLLS} $<TARGET_FILE_DIR:${name}>)
    endif ()
endfunction()

# ImHashData (the hash the stock-block matching uses) lives in imgui.cpp.
swr_add_fuzzer(fuzz_custom_track_blocks
        fuzz_custom_track_blocks.cpp
        ../dinput_hook/custom_track_blocks.cpp
        ${SWR_IMGUI_DIR}/imgui.cpp
        ${SWR_IMGUI_DIR}/imgui_draw.cpp
        ${SWR_IMGUI_DIR}/imgui_tables.cpp
        ${SWR_IMGUI_DIR}/imgui_widgets.cpp)
