# Bazarish project (c) 2026
function(bazarish_git_version sourceDir outName outCode)
    set(kUntaggedVersion "dev")
    execute_process(
        COMMAND git -C "${sourceDir}" describe --tags --exact-match
        OUTPUT_VARIABLE tag
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
        RESULT_VARIABLE tagStatus)
    execute_process(
        COMMAND git -C "${sourceDir}" rev-parse --short HEAD
        OUTPUT_VARIABLE commit
        OUTPUT_STRIP_TRAILING_WHITESPACE
        RESULT_VARIABLE commitStatus)
    execute_process(
        COMMAND git -C "${sourceDir}" rev-list --count HEAD
        OUTPUT_VARIABLE commits
        OUTPUT_STRIP_TRAILING_WHITESPACE
        RESULT_VARIABLE commitsStatus)
    if(NOT commitStatus STREQUAL "0" OR NOT commitsStatus STREQUAL "0")
        message(FATAL_ERROR "the version is read from git: ${sourceDir} has to be a git checkout")
    endif()
    if(tagStatus STREQUAL "0")
        set(${outName} "${tag}" PARENT_SCOPE)
    else()
        set(${outName} "${kUntaggedVersion} (${commit})" PARENT_SCOPE)
    endif()
    set(${outCode} "${commits}" PARENT_SCOPE)
endfunction()

# Stamped at every build, so a tag or a commit made after configure still reaches the binary.
function(bazarish_stamp_version target)
    set(stampDir "${CMAKE_CURRENT_BINARY_DIR}/${target}-version")
    add_custom_target(${target}-version ALL
        COMMAND ${CMAKE_COMMAND}
            -DBAZARISH_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
            -DBAZARISH_VERSION_HEADER=${stampDir}/BuildVersion.hpp
            -P ${CMAKE_CURRENT_FUNCTION_LIST_DIR}/StampVersion.cmake
        BYPRODUCTS ${stampDir}/BuildVersion.hpp
        COMMENT "Stamping the version of ${target} from git"
        VERBATIM)
    add_dependencies(${target} ${target}-version)
    target_include_directories(${target} PUBLIC ${stampDir})
endfunction()
