# Bazarish project (c) 2026
include("${CMAKE_CURRENT_LIST_DIR}/GitVersion.cmake")

bazarish_git_version("${BAZARISH_SOURCE_DIR}" BAZARISH_BUILD_VERSION unusedVersionCode)

configure_file("${CMAKE_CURRENT_LIST_DIR}/BuildVersion.hpp.in"
    "${BAZARISH_VERSION_HEADER}" @ONLY)
