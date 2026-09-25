# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Summon Software Labs.

add_executable(isf_example_authority embedded_authority/main.cpp)
target_link_libraries(isf_example_authority PRIVATE isf::daemon)
isf_apply_warnings(isf_example_authority)

add_executable(isf_example_connectivity connectivity_probe/main.cpp)
target_link_libraries(isf_example_connectivity PRIVATE isf::daemon)
isf_apply_warnings(isf_example_connectivity)
