# Regenerates build_id.h with the current git revision. Runs at BUILD time, not configure time,
# so the stamp cannot go stale after a commit; configure_file keeps the header byte-identical when
# nothing changed, so this does not force a rebuild.
# Expects: SRC_DIR (repo root), IN_FILE (template), OUT_FILE (generated header).

set(SWR_BUILD_COMMIT "unknown")
set(SWR_BUILD_BRANCH "unknown")
set(SWR_BUILD_DIRTY 0)

find_package(Git QUIET)
if(GIT_FOUND)
    execute_process(
        COMMAND "${GIT_EXECUTABLE}" rev-parse --short HEAD
        WORKING_DIRECTORY "${SRC_DIR}"
        OUTPUT_VARIABLE _commit
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
        RESULT_VARIABLE _commit_result)
    if(_commit_result EQUAL 0 AND _commit)
        set(SWR_BUILD_COMMIT "${_commit}")
    endif()

    execute_process(
        COMMAND "${GIT_EXECUTABLE}" rev-parse --abbrev-ref HEAD
        WORKING_DIRECTORY "${SRC_DIR}"
        OUTPUT_VARIABLE _branch
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
        RESULT_VARIABLE _branch_result)
    if(_branch_result EQUAL 0 AND _branch)
        set(SWR_BUILD_BRANCH "${_branch}")
    endif()

    # Uncommitted tracked changes: the revision alone no longer describes the binary.
    execute_process(
        COMMAND "${GIT_EXECUTABLE}" diff --quiet HEAD
        WORKING_DIRECTORY "${SRC_DIR}"
        RESULT_VARIABLE _dirty_result
        ERROR_QUIET)
    if(NOT _dirty_result EQUAL 0)
        set(SWR_BUILD_DIRTY 1)
    endif()
endif()

configure_file("${IN_FILE}" "${OUT_FILE}" @ONLY)
