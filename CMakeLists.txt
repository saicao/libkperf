cmake_minimum_required(VERSION 3.28)

project(libkperf
    VERSION 0.1
    LANGUAGES C
)
set(LIBKPERF_TESTS ON CACHE BOOL "Enable tests for libkperf")
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
add_library(libkperf
    src/kperf.c
)
target_include_directories(libkperf
    PUBLIC include
)
#tests
if(LIBKPERF_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
