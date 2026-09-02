# Run at build time (cmake -P) to capture the current git commit into a generated
# header. Rewrites the header only when the value changes, so an unchanged commit
# does not force a rebuild of everything that includes it.
#
# Inputs (passed with -D): SRC_DIR (repo path), OUT_FILE (header to write).

set(GIT_HASH "unknown")
set(GIT_DIRTY "")

find_package(Git QUIET)
if(GIT_FOUND)
    execute_process(
        COMMAND ${GIT_EXECUTABLE} -C ${SRC_DIR} rev-parse --short HEAD
        OUTPUT_VARIABLE GIT_HASH
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET)
    if(GIT_HASH STREQUAL "")
        set(GIT_HASH "unknown")
    endif()

    # Mark builds with uncommitted tracked changes so an on-screen hash is never
    # mistaken for a clean tagged build (untracked files are ignored).
    execute_process(
        COMMAND ${GIT_EXECUTABLE} -C ${SRC_DIR} status --porcelain --untracked-files=no
        OUTPUT_VARIABLE GIT_STATUS
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET)
    if(NOT GIT_STATUS STREQUAL "")
        set(GIT_DIRTY "-dirty")
    endif()
endif()

set(CONTENT "#pragma once\n// Auto-generated at build time by generate_git_version.cmake. Do not edit.\n#define MOD_GIT_HASH \"${GIT_HASH}${GIT_DIRTY}\"\n")

set(EXISTING "")
if(EXISTS ${OUT_FILE})
    file(READ ${OUT_FILE} EXISTING)
endif()
if(NOT EXISTING STREQUAL CONTENT)
    file(WRITE ${OUT_FILE} "${CONTENT}")
endif()
