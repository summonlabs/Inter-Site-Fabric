# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Summon Software Labs.

add_library(isf_cli STATIC common/cli.cpp)
target_link_libraries(isf_cli PUBLIC isf::daemon)
target_include_directories(isf_cli PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/common)
isf_apply_warnings(isf_cli)

add_executable(isfd isfd/main.cpp)
target_link_libraries(isfd PRIVATE isf_cli)
isf_apply_warnings(isfd)

add_executable(isfsited isfsited/main.cpp)
target_link_libraries(isfsited PRIVATE isf_cli)
isf_apply_warnings(isfsited)

add_executable(isfctl isfctl/main.cpp)
target_link_libraries(isfctl PRIVATE isf_cli)
isf_apply_warnings(isfctl)
