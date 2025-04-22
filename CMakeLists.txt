cmake_minimum_required(VERSION 3.28)
project(kperf
    VERSION 0.1
    LANGUAGES C
)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
add_executable(kperf
    src/kperf.c
)
target_include_directories(kperf PRIVATE include
)
