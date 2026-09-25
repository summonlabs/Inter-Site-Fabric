# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Summon Software Labs.
#
# Inter-Site Fabric: controlled connectivity and capacity authority between
# physical sites. No third-party runtime dependencies.

cmake_minimum_required(VERSION 3.20)

project(InterSiteFabric
  VERSION 1.0.0
  DESCRIPTION "Controlled connectivity and capacity authority between physical sites"
  HOMEPAGE_URL "https://github.com/summonlabs/Inter-Site-Fabric"
  LANGUAGES CXX)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
  set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS Debug Release RelWithDebInfo MinSizeRel)
endif()

option(ISF_BUILD_APPS "Build the isfd, isfsited, and isfctl programs" ON)
option(ISF_BUILD_TESTS "Build the test suite" ON)
option(ISF_BUILD_EXAMPLES "Build the example programs" ON)
option(ISF_BUILD_BENCHMARKS "Build the benchmark programs" ON)
option(ISF_WERROR "Treat compiler warnings as errors" ON)
option(ISF_SANITIZE "Build with AddressSanitizer / UndefinedBehaviorSanitizer" OFF)
option(ISF_INSTALL "Generate install and package export rules" ON)

if(ISF_SANITIZE AND MSVC AND NOT CMAKE_MSVC_RUNTIME_LIBRARY)
  # MSVC AddressSanitizer requires a dynamic C runtime.
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
endif()

include(cmake/isfWarnings.cmake)
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
include(CTest)

# ---------------------------------------------------------------------------
# Generated headers
# ---------------------------------------------------------------------------

set(ISF_GENERATED_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated")
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/include/isf/version_config.hpp.in"
  "${ISF_GENERATED_DIR}/isf/version_config.hpp"
  @ONLY)

# ---------------------------------------------------------------------------
# isf_core: identities, capacity accounting, lifecycle, authority
# ---------------------------------------------------------------------------

add_library(isf_core STATIC
  src/status.cpp
  src/ids.cpp
  src/digest.cpp
  src/wire.cpp
  src/capacity.cpp
  src/lifecycle.cpp
  src/policy.cpp
  src/model.cpp
  src/authority.cpp
  src/authority_plan.cpp
  src/log.cpp
  src/version.cpp)
add_library(isf::core ALIAS isf_core)
set_target_properties(isf_core PROPERTIES EXPORT_NAME core)
target_include_directories(isf_core
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${ISF_GENERATED_DIR}>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
isf_apply_warnings(isf_core)

# ---------------------------------------------------------------------------
# isf_store: versioned, integrity chained persistence
# ---------------------------------------------------------------------------

add_library(isf_store STATIC
  src/store.cpp)
add_library(isf::store ALIAS isf_store)
set_target_properties(isf_store PROPERTIES EXPORT_NAME store)
target_link_libraries(isf_store PUBLIC isf::core)
isf_apply_warnings(isf_store)

# ---------------------------------------------------------------------------
# isf_net: framing, loopback TCP transport, protocol
# ---------------------------------------------------------------------------

add_library(isf_net STATIC
  src/net.cpp
  src/protocol.cpp)
add_library(isf::net ALIAS isf_net)
set_target_properties(isf_net PROPERTIES EXPORT_NAME net)
target_link_libraries(isf_net PUBLIC isf::core)
if(WIN32)
  target_link_libraries(isf_net PUBLIC ws2_32)
endif()
isf_apply_warnings(isf_net)

# ---------------------------------------------------------------------------
# isf_daemon: authority plus durable store plus request pipeline
# ---------------------------------------------------------------------------

add_library(isf_daemon STATIC
  src/daemon.cpp
  src/server.cpp
  src/client.cpp)
add_library(isf::daemon ALIAS isf_daemon)
set_target_properties(isf_daemon PROPERTIES EXPORT_NAME daemon)
target_link_libraries(isf_daemon PUBLIC isf::core isf::store isf::net)
isf_apply_warnings(isf_daemon)

# ---------------------------------------------------------------------------
# Programs
# ---------------------------------------------------------------------------

if(ISF_BUILD_APPS)
  add_subdirectory(apps)
endif()

if(ISF_BUILD_EXAMPLES)
  add_subdirectory(examples)
endif()

if(ISF_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

if(ISF_BUILD_BENCHMARKS)
  add_subdirectory(benchmarks)
endif()

# ---------------------------------------------------------------------------
# Install and package export
# ---------------------------------------------------------------------------

if(ISF_INSTALL)
  install(TARGETS isf_core isf_store isf_net isf_daemon
    EXPORT isfTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

  install(DIRECTORY include/isf DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    FILES_MATCHING PATTERN "*.hpp" PATTERN "*.in" EXCLUDE)
  install(FILES "${ISF_GENERATED_DIR}/isf/version_config.hpp"
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/isf)

  if(ISF_BUILD_APPS)
    install(TARGETS isfd isfsited isfctl
      RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
  endif()

  install(EXPORT isfTargets
    FILE isfTargets.cmake
    NAMESPACE isf::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/isf)

  configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/isfConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/isfConfig.cmake"
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/isf)

  write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/isfConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion)

  install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/isfConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/isfConfigVersion.cmake"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/isf)

  install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE" "${CMAKE_CURRENT_SOURCE_DIR}/NOTICE"
    DESTINATION ${CMAKE_INSTALL_DATADIR}/isf)
endif()

message(STATUS "Inter-Site Fabric ${PROJECT_VERSION}: apps=${ISF_BUILD_APPS} tests=${ISF_BUILD_TESTS} examples=${ISF_BUILD_EXAMPLES} benchmarks=${ISF_BUILD_BENCHMARKS} werror=${ISF_WERROR} sanitize=${ISF_SANITIZE}")
