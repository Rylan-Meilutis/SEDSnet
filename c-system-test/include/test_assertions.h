#pragma once

/* A Release build must still execute setup and validate every test condition. */
#ifdef NDEBUG
#error "C system tests require active assertions; configure through c-system-test/CMakeLists.txt"
#endif
#include <assert.h>
