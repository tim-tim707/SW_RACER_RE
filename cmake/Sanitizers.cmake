# Memory-safety options; `swr_memsafety` carries the flags for the targets we own.
#   ENABLE_ASAN       clang only; libclang_rt.asan_dynamic-i386.dll must sit next to dinput.dll
#   ENABLE_UBSAN      clang only; null/bounds/return abort, other checks report and continue
#   ENABLE_HARDENING  stdlib assertions, stack protector, initialized locals (default ON)

option(ENABLE_ASAN "Build with AddressSanitizer (clang only)" OFF)
option(ENABLE_UBSAN "Build with UndefinedBehaviorSanitizer (clang only)" OFF)
option(ENABLE_HARDENING "stdlib assertions, stack protector, auto-initialized locals" ON)

add_library(swr_memsafety INTERFACE)

if ((ENABLE_ASAN OR ENABLE_UBSAN) AND NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "ENABLE_ASAN / ENABLE_UBSAN need clang: MinGW GCC ships no sanitizer runtimes.")
endif()

if (ENABLE_ASAN)
    target_compile_options(swr_memsafety INTERFACE -fsanitize=address -fno-omit-frame-pointer -g)
    target_link_options(swr_memsafety INTERFACE -fsanitize=address)
    target_compile_definitions(swr_memsafety INTERFACE SWR_ASAN=1)

    # The runtime DLL and its C++ runtime deps live in the toolchain's target bin dir (llvm-mingw)
    # or next to clang (WinLibs); target dir first, llvm-mingw's bin/ holds 64-bit host copies.
    get_filename_component(SWR_CC_DIR ${CMAKE_C_COMPILER} DIRECTORY)
    set(SWR_TOOLCHAIN_BIN_HINTS ${SWR_CC_DIR}/../i686-w64-mingw32/bin ${SWR_CC_DIR})
    set(SWR_ASAN_RUNTIME_DLLS "")
    foreach (dll libclang_rt.asan_dynamic-i386.dll libc++.dll libunwind.dll)
        find_file(SWR_DLL_${dll} ${dll} HINTS ${SWR_TOOLCHAIN_BIN_HINTS} NO_DEFAULT_PATH)
        if (SWR_DLL_${dll})
            list(APPEND SWR_ASAN_RUNTIME_DLLS ${SWR_DLL_${dll}})
        endif ()
    endforeach ()
    if (NOT SWR_DLL_libclang_rt.asan_dynamic-i386.dll)
        message(WARNING "libclang_rt.asan_dynamic-i386.dll not found; copy it next to dinput.dll by hand.")
    endif ()
endif()

if (ENABLE_UBSAN)
    # Faithful reimpls reproduce the original's signed wraparound and unaligned struct reads on
    # purpose, so those two checks would only report intended behavior.
    set(SWR_UBSAN_CHECKS undefined)
    target_compile_options(swr_memsafety INTERFACE
            -fsanitize=${SWR_UBSAN_CHECKS}
            -fno-sanitize=signed-integer-overflow,alignment,function
            -fno-sanitize-recover=null,bounds,return)
    target_link_options(swr_memsafety INTERFACE -fsanitize=${SWR_UBSAN_CHECKS})
endif()

if (ENABLE_HARDENING)
    target_compile_definitions(swr_memsafety INTERFACE
            $<$<COMPILE_LANGUAGE:CXX>:_GLIBCXX_ASSERTIONS>
            $<$<COMPILE_LANGUAGE:CXX>:_LIBCPP_HARDENING_MODE=$<IF:$<CONFIG:Debug>,_LIBCPP_HARDENING_MODE_DEBUG,_LIBCPP_HARDENING_MODE_FAST>>)
    target_compile_options(swr_memsafety INTERFACE
            -fstack-protector-strong
            -ftrivial-auto-var-init=$<IF:$<CONFIG:Debug>,pattern,zero>)
    target_link_options(swr_memsafety INTERFACE -fstack-protector-strong)
endif()
