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

add_executable(grap_event
    grap_event.c
)
target_link_libraries(grap_event
    libkperf
)
add_executable(burn_cpu_pi
    burn_cpu_pi.c
)

add_executable(perf_process_pmi
    perf_process_pmi.c
)
target_link_libraries(perf_process_pmi
    libkperf
)
add_executable(read_pmi
    read_pmi.c
)
target_link_libraries(read_pmi
    libkperf
)



add_test(NAME test_perf_func
    COMMAND test_perf_func
)
add_test(NAME test_perf_process
    COMMAND test_perf_process
)
add_test(NAME grap_event
    COMMAND grap_event
)
