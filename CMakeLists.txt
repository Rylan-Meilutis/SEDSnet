cmake_minimum_required(VERSION 3.22)
project(sedsnet_cmake NONE)

# --- Find Python interpreter ---
find_package(Python3 COMPONENTS Interpreter REQUIRED)
set(PYTHON_EXECUTABLE "${Python3_EXECUTABLE}")

set(SEDSNET_DIR_DEFAULT "${CMAKE_CURRENT_LIST_DIR}/")
set(SEDSNET_DIR "${SEDSNET_DIR_DEFAULT}" CACHE PATH "Path to sedsnet crate root")
get_filename_component(RUST_DIR "${SEDSNET_DIR}" REALPATH)

# ============================================================
# Config overrides forwarded into the Rust build (via build.py)
# ============================================================

# Device identifier override for Rust (passed to build.py)
set(SEDSNET_DEVICE_IDENTIFIER "" CACHE STRING
    "Override DEVICE_IDENTIFIER passed to build.py (empty = use default)")

# New: proc-macro env var (define_stack_payload!(env = \"MAX_STACK_PAYLOAD\", default = ...))
set(SEDSNET_MAX_STACK_PAYLOAD "" CACHE STRING
    "Override MAX_STACK_PAYLOAD used by define_stack_payload! (empty = use macro default)")

set(SEDSNET_MAX_QUEUE_BUDGET "" CACHE STRING
    "Override MAX_QUEUE_BUDGET shared queue budget in bytes (empty = use Rust default)")

set(SEDSNET_MAX_QUEUE_SIZE "" CACHE STRING
    "Legacy alias for SEDSNET_MAX_QUEUE_BUDGET (empty = ignored)")

set(SEDSNET_MAX_RECENT_RX_IDS "" CACHE STRING
    "Override MAX_RECENT_RX_IDS preallocated recent packet ID entries (empty = use Rust default)")

# Schema JSON path override (forwarded as SEDSNET_SCHEMA_PATH)
set(SEDSNET_SCHEMA_PATH "" CACHE STRING
    "Override telemetry_config.json path (empty = use default)")

# For each env var you want to set, define a CMake var named:
#   SEDSNET_ENV_<ENVKEY>
# Example:
#   set(SEDSNET_ENV_QUEUE_GROW_STEP "2.0" CACHE STRING "" FORCE)
# Prefer the dedicated cache variables above for MAX_QUEUE_BUDGET and MAX_RECENT_RX_IDS.
#
# These will be forwarded as build.py args: env:ENVKEY=VALUE

# ============================================================
# Detect embedded build
# ============================================================
option(SEDSNET_EMBEDDED_BUILD "Build sedsnet for embedded" OFF)
option(SEDSNET_PREFER_DYNAMIC "Prefer dynamic linking for host builds when supported" ON)
option(SEDSNET_FORCE_RELEASE "Build sedsnet in release profile even when the parent CMake build is Debug" OFF)
option(SEDSNET_ENABLE_C_WRAPPER
    "Build the optional native C wrapper target sedsnet::c_wrapper"
    OFF)
option(SEDSNET_ENABLE_CPP_WRAPPER
    "Expose the optional header-only C++ convenience target sedsnet::cpp_wrapper"
    OFF)
option(SEDSNET_ENABLE_CRYPTOGRAPHY
    "Enable cryptography provider APIs and define SEDS_ENABLE_CRYPTOGRAPHY for C/C++ users"
    ON)

# Auto-detect embedded if user hasn't forced it
if (NOT SEDSNET_EMBEDDED_BUILD)
    if (CMAKE_C_COMPILER MATCHES "arm-none-eabi"
            OR CMAKE_TOOLCHAIN_FILE MATCHES "stm32"
            OR CMAKE_TOOLCHAIN_FILE MATCHES "gcc-arm-none-eabi"
            OR DEFINED ENV{STM32CUBEIDE_DIR}
    )
        set(SEDSNET_EMBEDDED_BUILD ON CACHE BOOL "Build sedsnet for embedded" FORCE)
    endif ()
endif ()

# ============================================================
# Rust target triple selection
# ============================================================
if (NOT DEFINED SEDSNET_TARGET)
    if (SEDSNET_EMBEDDED_BUILD)
        set(SEDSNET_TARGET "thumbv7em-none-eabihf" CACHE STRING "Rust target triple for sedsnet (empty = host default)")
    else ()
        set(SEDSNET_TARGET "" CACHE STRING "Rust target triple for sedsnet (empty = host default)")
    endif ()
endif ()

set(RUST_TRIPLE "${SEDSNET_TARGET}")

# ============================================================
# Compute Rust output paths
# ============================================================
set(RELEASE_PROFILE_DIR "release")
if (SEDSNET_EMBEDDED_BUILD)
    set(RELEASE_PROFILE_DIR "release-embedded")
endif ()

if (SEDSNET_FORCE_RELEASE)
    set(SEDSNET_ACTIVE_PROFILE "${RELEASE_PROFILE_DIR}")
else ()
    set(SEDSNET_ACTIVE_PROFILE "$<IF:$<CONFIG:Debug>,debug,${RELEASE_PROFILE_DIR}>")
endif ()

if (RUST_TRIPLE STREQUAL "")
    set(RS_STATIC_LIB_DBG "${RUST_DIR}/target/debug/libsedsnet.a")
    set(RS_STATIC_LIB_REL "${RUST_DIR}/target/release/libsedsnet.a")
else ()
    set(RS_STATIC_LIB_DBG "${RUST_DIR}/target/${RUST_TRIPLE}/debug/libsedsnet.a")
    set(RS_STATIC_LIB_REL "${RUST_DIR}/target/${RUST_TRIPLE}/${RELEASE_PROFILE_DIR}/libsedsnet.a")
endif ()

set(RS_LIB_DBG "${RS_STATIC_LIB_DBG}")
set(RS_LIB_REL "${RS_STATIC_LIB_REL}")
if (SEDSNET_FORCE_RELEASE)
    set(RS_LIB_DBG "${RS_LIB_REL}")
endif ()
set(RS_IMPORTED_KIND STATIC)
set(SEDSNET_LINK_DYNAMIC OFF)
set(RS_SHARED_LIB_DBG "")
set(RS_SHARED_LIB_REL "")

set(RS_INCLUDE "${RUST_DIR}/C-Headers")
set(RS_HEADER "${RS_INCLUDE}/sedsnet.h")
if (NOT EXISTS "${RS_HEADER}")
    message(FATAL_ERROR "Static sedsnet C header is missing: ${RS_HEADER}")
endif ()

# ============================================================
# Build.py args (for logging only)
# ============================================================
set(RS_ARGS_STR "")
if (SEDSNET_EMBEDDED_BUILD)
    set(RS_ARGS_STR "${RS_ARGS_STR} embedded")
endif ()
if (NOT RUST_TRIPLE STREQUAL "")
    set(RS_ARGS_STR "${RS_ARGS_STR} target=${RUST_TRIPLE}")
endif ()
if (NOT SEDSNET_DEVICE_IDENTIFIER STREQUAL "")
    set(RS_ARGS_STR "${RS_ARGS_STR} device_id=${SEDSNET_DEVICE_IDENTIFIER}")
endif ()
if (NOT SEDSNET_MAX_STACK_PAYLOAD STREQUAL "")
    set(RS_ARGS_STR "${RS_ARGS_STR} max_stack_payload=${SEDSNET_MAX_STACK_PAYLOAD}")
endif ()
set(_SEDSNET_EFFECTIVE_MAX_QUEUE_BUDGET "${SEDSNET_MAX_QUEUE_BUDGET}")
if (_SEDSNET_EFFECTIVE_MAX_QUEUE_BUDGET STREQUAL "" AND NOT SEDSNET_MAX_QUEUE_SIZE STREQUAL "")
    set(_SEDSNET_EFFECTIVE_MAX_QUEUE_BUDGET "${SEDSNET_MAX_QUEUE_SIZE}")
endif ()
if (NOT _SEDSNET_EFFECTIVE_MAX_QUEUE_BUDGET STREQUAL "")
    set(RS_ARGS_STR "${RS_ARGS_STR} max_queue_budget=${_SEDSNET_EFFECTIVE_MAX_QUEUE_BUDGET}")
endif ()
if (NOT SEDSNET_MAX_RECENT_RX_IDS STREQUAL "")
    set(RS_ARGS_STR "${RS_ARGS_STR} max_recent_rx_ids=${SEDSNET_MAX_RECENT_RX_IDS}")
endif ()
if (NOT SEDSNET_SCHEMA_PATH STREQUAL "")
    set(RS_ARGS_STR "${RS_ARGS_STR} schema_path=${SEDSNET_SCHEMA_PATH}")
endif ()
if (SEDSNET_ENABLE_CRYPTOGRAPHY)
    set(RS_ARGS_STR "${RS_ARGS_STR} cryptography")
endif ()

if (SEDSNET_FORCE_RELEASE)
    set(RS_ARGS_STR "${RS_ARGS_STR} release")
else ()
    # Show release in log string
    set(RS_ARG_REL " $<$<CONFIG:Release>:release>")
    set(RS_ARGS_STR "${RS_ARGS_STR} ${RS_ARG_REL}")
endif ()

# ============================================================
# Configure-time args passed to build.py (list form)
# ============================================================
set(RS_ARGS_BOOTSTRAP "")

if (SEDSNET_EMBEDDED_BUILD)
    list(APPEND RS_ARGS_BOOTSTRAP "embedded")
endif ()

if (NOT RUST_TRIPLE STREQUAL "")
    list(APPEND RS_ARGS_BOOTSTRAP "target=${RUST_TRIPLE}")
endif ()

# NOTE: When using multi-config generators (VS/Xcode), CMAKE_BUILD_TYPE is empty.
# We rely on the build step to rebuild as needed anyway; default to Debug.
if (SEDSNET_FORCE_RELEASE OR CMAKE_BUILD_TYPE STREQUAL "Release")
    list(APPEND RS_ARGS_BOOTSTRAP "release")
endif ()

if (NOT SEDSNET_DEVICE_IDENTIFIER STREQUAL "")
    list(APPEND RS_ARGS_BOOTSTRAP "device_id=${SEDSNET_DEVICE_IDENTIFIER}")
endif ()

# New: forward proc-macro env var
if (NOT SEDSNET_MAX_STACK_PAYLOAD STREQUAL "")
    list(APPEND RS_ARGS_BOOTSTRAP "max_stack_payload=${SEDSNET_MAX_STACK_PAYLOAD}")
endif ()
if (NOT _SEDSNET_EFFECTIVE_MAX_QUEUE_BUDGET STREQUAL "")
    list(APPEND RS_ARGS_BOOTSTRAP "max_queue_budget=${_SEDSNET_EFFECTIVE_MAX_QUEUE_BUDGET}")
endif ()
if (NOT SEDSNET_MAX_RECENT_RX_IDS STREQUAL "")
    list(APPEND RS_ARGS_BOOTSTRAP "max_recent_rx_ids=${SEDSNET_MAX_RECENT_RX_IDS}")
endif ()
if (NOT SEDSNET_SCHEMA_PATH STREQUAL "")
    list(APPEND RS_ARGS_BOOTSTRAP "schema_path=${SEDSNET_SCHEMA_PATH}")
endif ()
if (SEDSNET_ENABLE_CRYPTOGRAPHY)
    list(APPEND RS_ARGS_BOOTSTRAP "cryptography")
endif ()

# New: forward arbitrary option_env config vars: SEDSNET_ENV_<KEY> => env:KEY=VALUE
get_cmake_property(_all_cache_vars CACHE_VARIABLES)
foreach (_v ${_all_cache_vars})
    if (_v MATCHES "^SEDSNET_ENV_(.+)$")
        string(REGEX REPLACE "^SEDSNET_ENV_" "" _env_key "${_v}")
        # Value comes from the cache variable
        set(_env_val "${${_v}}")
        if (NOT _env_val STREQUAL "")
            list(APPEND RS_ARGS_BOOTSTRAP "env:${_env_key}=${_env_val}")
            # Also append to logging string
            set(RS_ARGS_STR "${RS_ARGS_STR} env:${_env_key}=${_env_val}")
        endif ()
    endif ()
endforeach ()

# Keep Rust staticlib object deployment target aligned with C/C++ link target on macOS.
set(_RS_ENV_CMD ${CMAKE_COMMAND} -E env)
if (APPLE AND CMAKE_OSX_DEPLOYMENT_TARGET)
    list(APPEND _RS_ENV_CMD "MACOSX_DEPLOYMENT_TARGET=${CMAKE_OSX_DEPLOYMENT_TARGET}")
endif ()

# ============================================================
# Track Rust source inputs
# ============================================================
file(GLOB_RECURSE RS_SRC CONFIGURE_DEPENDS
    "${RUST_DIR}/src/*.rs"
    "${RUST_DIR}/build.rs"
    "${RUST_DIR}/Cargo.toml"
    "${RUST_DIR}/Cargo.lock"
    "${RS_HEADER}"
    "${RUST_DIR}/c-wrapper/*.c"
    "${RUST_DIR}/c-wrapper/*.h"
    "${RUST_DIR}/c-wrapper/*.hpp"
)

if (SEDSNET_FORCE_RELEASE)
    set(RS_BUILD_OUTPUTS "${RS_LIB_REL}")
else ()
    set(RS_BUILD_OUTPUTS "${RS_LIB_DBG}" "${RS_LIB_REL}")
endif ()

# ============================================================
# Main build rule
# ============================================================
add_custom_command(
    OUTPUT ${RS_BUILD_OUTPUTS}
    COMMAND ${_RS_ENV_CMD} "${PYTHON_EXECUTABLE}" build.py ${RS_ARGS_BOOTSTRAP}
    WORKING_DIRECTORY "${RUST_DIR}"
    DEPENDS ${RS_SRC}
    COMMENT "Building sedsnet (${SEDSNET_ACTIVE_PROFILE}) ${RS_ARGS_STR}"
    USES_TERMINAL
    VERBATIM
)

add_custom_target(sedsnet_build
    DEPENDS ${RS_BUILD_OUTPUTS}
)

# ============================================================
# Import library for C/C++
# ============================================================
add_library(sedsnet ${RS_IMPORTED_KIND} IMPORTED GLOBAL)
set_target_properties(sedsnet PROPERTIES
    IMPORTED_LOCATION "${RS_LIB_DBG}"
    IMPORTED_LOCATION_DEBUG "${RS_LIB_DBG}"
    IMPORTED_LOCATION_RELEASE "${RS_LIB_REL}"
    INTERFACE_INCLUDE_DIRECTORIES "${RS_INCLUDE}"
)
if (SEDSNET_ENABLE_CRYPTOGRAPHY)
    target_compile_definitions(sedsnet INTERFACE SEDS_ENABLE_CRYPTOGRAPHY=1)
endif ()

add_dependencies(sedsnet sedsnet_build)

# Security flags for embedded
include(CheckLinkerFlag)
include(CheckCCompilerFlag)
check_linker_flag(C "-Wl,-z,noexecstack" HAVE_LD_NOEXECSTACK)
check_c_compiler_flag("-Wa,--noexecstack" HAVE_AS_NOEXECSTACK)

if (SEDSNET_EMBEDDED_BUILD)
    target_compile_options(sedsnet INTERFACE -Wa,--noexecstack)
    target_link_options(sedsnet INTERFACE -Wl,-z,noexecstack)
endif ()

# Optimize
add_compile_options(-ffunction-sections -fdata-sections -Os)
add_link_options(-Wl,--gc-sections -Wl,--icf=all)

add_library(sedsnet::sedsnet ALIAS sedsnet)

if (SEDSNET_ENABLE_C_WRAPPER)
    add_library(sedsnet_c_wrapper STATIC
        "${RUST_DIR}/c-wrapper/sedsnet_c_wrapper.c"
    )
    target_include_directories(sedsnet_c_wrapper PUBLIC
        "${RUST_DIR}/c-wrapper"
    )
    target_link_libraries(sedsnet_c_wrapper PUBLIC sedsnet)
    if (SEDSNET_ENABLE_CRYPTOGRAPHY)
        target_compile_definitions(sedsnet_c_wrapper PUBLIC SEDS_ENABLE_CRYPTOGRAPHY=1)
    endif ()
    add_dependencies(sedsnet_c_wrapper sedsnet_build)
    add_library(sedsnet::c_wrapper ALIAS sedsnet_c_wrapper)
endif ()

if (SEDSNET_ENABLE_CPP_WRAPPER)
    add_library(sedsnet_cpp_wrapper INTERFACE)
    target_include_directories(sedsnet_cpp_wrapper INTERFACE
        "${RUST_DIR}/c-wrapper"
    )
    target_link_libraries(sedsnet_cpp_wrapper INTERFACE sedsnet)
    if (SEDSNET_ENABLE_CRYPTOGRAPHY)
        target_compile_definitions(sedsnet_cpp_wrapper INTERFACE SEDS_ENABLE_CRYPTOGRAPHY=1)
    endif ()
    add_dependencies(sedsnet_cpp_wrapper sedsnet_build)
    add_library(sedsnet::cpp_wrapper ALIAS sedsnet_cpp_wrapper)
endif ()

set(SEDSNET_LIB_DEBUG "${RS_LIB_DBG}" PARENT_SCOPE)
set(SEDSNET_LIB_RELEASE "${RS_LIB_REL}" PARENT_SCOPE)
set(SEDSNET_STATIC_LIB_DEBUG "${RS_STATIC_LIB_DBG}" PARENT_SCOPE)
set(SEDSNET_STATIC_LIB_RELEASE "${RS_STATIC_LIB_REL}" PARENT_SCOPE)
set(SEDSNET_SHARED_LIB_DEBUG "${RS_SHARED_LIB_DBG}" PARENT_SCOPE)
set(SEDSNET_SHARED_LIB_RELEASE "${RS_SHARED_LIB_REL}" PARENT_SCOPE)
set(SEDSNET_INCLUDE_DIR "${RS_INCLUDE}" PARENT_SCOPE)
set(SEDSNET_C_WRAPPER_INCLUDE_DIR "${RUST_DIR}/c-wrapper" PARENT_SCOPE)

message(STATUS "sedsnet include dir: ${RS_INCLUDE}")
message(STATUS "sedsnet debug lib:  ${RS_LIB_DBG}")
message(STATUS "sedsnet release lib:${RS_LIB_REL}")
if (SEDSNET_LINK_DYNAMIC)
    set(_SEDSNET_LINK_MODE "dynamic")
else ()
    set(_SEDSNET_LINK_MODE "static")
endif ()
message(STATUS "sedsnet link mode: ${_SEDSNET_LINK_MODE}")
message(STATUS "sedsnet C wrapper target: ${SEDSNET_ENABLE_C_WRAPPER}")
message(STATUS "sedsnet C++ wrapper target: ${SEDSNET_ENABLE_CPP_WRAPPER}")
message(STATUS "sedsnet cryptography provider: ${SEDSNET_ENABLE_CRYPTOGRAPHY}")
message(STATUS "sedsnet build args: ${RS_ARGS_STR}")
