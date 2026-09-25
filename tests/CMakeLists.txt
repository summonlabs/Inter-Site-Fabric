# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Summon Software Labs.

add_library(isf_testkit STATIC testkit.cpp process.cpp)
target_link_libraries(isf_testkit PUBLIC isf::daemon)
target_include_directories(isf_testkit PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
isf_apply_warnings(isf_testkit)

add_executable(isf_unit_tests unit/unit_main.cpp)
target_link_libraries(isf_unit_tests PRIVATE isf_testkit)
isf_apply_warnings(isf_unit_tests)

add_executable(isf_property_tests property/property_main.cpp)
target_link_libraries(isf_property_tests PRIVATE isf_testkit)
isf_apply_warnings(isf_property_tests)

add_executable(isf_adversarial_tests adversarial/adversarial_main.cpp)
target_link_libraries(isf_adversarial_tests PRIVATE isf_testkit)
isf_apply_warnings(isf_adversarial_tests)

add_executable(isf_concurrency_tests concurrency/concurrency_main.cpp)
target_link_libraries(isf_concurrency_tests PRIVATE isf_testkit)
isf_apply_warnings(isf_concurrency_tests)

add_executable(isf_multiprocess_tests multiprocess/multiprocess_main.cpp)
target_link_libraries(isf_multiprocess_tests PRIVATE isf_testkit)
isf_apply_warnings(isf_multiprocess_tests)

# Tests run to completion or they fail. No CTest TIMEOUT property is set
# anywhere in this project: a hang is a defect to diagnose, not to mask.
foreach(test_name IN ITEMS unit property adversarial concurrency multiprocess)
  add_test(NAME isf_${test_name} COMMAND isf_${test_name}_tests)
  set_tests_properties(isf_${test_name} PROPERTIES
    ENVIRONMENT "ISF_TEST_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}"
    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")
endforeach()
