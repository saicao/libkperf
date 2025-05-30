add_executable(test_perf_func
    perf_func.c
)
target_link_libraries(test_perf_func
    libkperf
)
add_executable(test_perf_process
    perf_process.c
)
target_link_libraries(test_perf_process
    libkperf
)
add_test(NAME test_perf_func
    COMMAND test_perf_func
)
add_test(NAME test_perf_process
    COMMAND test_perf_process
)
