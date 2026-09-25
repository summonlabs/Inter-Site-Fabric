# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Summon Software Labs.

add_executable(isf_benchmarks bench_main.cpp)
target_link_libraries(isf_benchmarks PRIVATE isf::daemon)
isf_apply_warnings(isf_benchmarks)
