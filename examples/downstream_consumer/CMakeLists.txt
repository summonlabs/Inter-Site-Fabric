# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Summon Software Labs.
#
# An independent downstream consumer of the installed Inter-Site Fabric package.
#
# This is a standalone CMake project: it is deliberately NOT added by the
# repository's top-level CMakeLists, because the whole point is to build it
# against an installed prefix only.
#
#   cmake --install <build-dir> --prefix <prefix>
#   cmake -S examples/downstream_consumer -B <consumer-build> \
#         -DCMAKE_PREFIX_PATH=<prefix>
#   cmake --build <consumer-build>
#   <consumer-build>/isf_downstream_consumer

cmake_minimum_required(VERSION 3.20)

project(isf_downstream_consumer
  VERSION 1.0.0
  DESCRIPTION "Independent consumer of the installed Inter-Site Fabric package"
  LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(isf CONFIG REQUIRED)

add_executable(isf_downstream_consumer main.cpp)
target_link_libraries(isf_downstream_consumer PRIVATE isf::daemon)

if(MSVC)
  target_compile_options(isf_downstream_consumer PRIVATE /W4 /WX /permissive- /utf-8)
else()
  target_compile_options(isf_downstream_consumer PRIVATE -Wall -Wextra -Werror)
endif()

message(STATUS "isf_downstream_consumer: found Inter-Site Fabric ${isf_VERSION}")
