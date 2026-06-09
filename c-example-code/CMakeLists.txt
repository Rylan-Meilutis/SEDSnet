cmake_minimum_required(VERSION 3.22)
project(c_example_code C)

set(CMAKE_C_STANDARD 11)

# 1) Define the target first
add_executable(c_example_code
        src/main.c
        src/telemetry.c
)

# 2) Local includes (your own headers)
target_include_directories(c_example_code PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/include"
)

# 3) Bring in the Rust crate (parent dir) with an explicit build dir
get_filename_component(SEDSPRINTF_RS_ROOT "${CMAKE_CURRENT_LIST_DIR}/.." REALPATH)
set(SEDSPRINTF_RS_ENABLE_C_WRAPPER ON CACHE BOOL "" FORCE)
add_subdirectory(
        "${SEDSPRINTF_RS_ROOT}"
        "${CMAKE_CURRENT_BINARY_DIR}/sedsprintf_rs-build"
        EXCLUDE_FROM_ALL
)

# 4) Link + add the crate's public headers
target_link_libraries(c_example_code PRIVATE sedsprintf_rs::c_wrapper)
target_include_directories(c_example_code PRIVATE "${SEDSPRINTF_RS_INCLUDE_DIR}")
