# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Summon Software Labs.
#
# Central warning configuration. The project builds warning-clean with
# MSVC /W4 /WX and with GCC/Clang -Wall -Wextra -Werror.
#
# Warning flags are applied directly to each first-party target rather than
# through an INTERFACE library. An INTERFACE library linked PRIVATE into a
# STATIC library still lands in that library's INTERFACE_LINK_LIBRARIES as a
# LINK_ONLY entry, which would then have to be exported to consumers. Applying
# the flags directly keeps the exported package free of build-only targets.

set(ISF_MSVC_WARNING_FLAGS
  /W4
  /permissive-
  /utf-8
  /Zc:__cplusplus
  /Zc:preprocessor
  /Zc:inline
  /EHsc
  /MP
  /wd4324)  # structure padded due to alignment specifier

set(ISF_GNU_WARNING_FLAGS
  -Wall
  -Wextra
  -Wpedantic
  -Wshadow
  -Wconversion
  -Wsign-conversion
  -Wold-style-cast
  -Wnon-virtual-dtor
  -Wcast-align
  -Wunused
  -Woverloaded-virtual
  -Wnull-dereference
  -Wdouble-promotion
  -Wformat=2)

# Applies the project warning set, the optional /WX or -Werror promotion, and
# the sanitizer configuration to one target.
function(isf_apply_warnings target)
  if(MSVC)
    target_compile_options(${target} PRIVATE ${ISF_MSVC_WARNING_FLAGS})
    # The runtime uses the standard C file API deliberately; the MSVC
    # "unsafe" deprecation notice is not actionable here.
    target_compile_definitions(${target} PRIVATE _CRT_SECURE_NO_WARNINGS)
    if(ISF_WERROR)
      target_compile_options(${target} PRIVATE /WX)
    endif()
    if(ISF_SANITIZE)
      # MSVC AddressSanitizer requires a dynamic C runtime and is available for
      # x64 and ARM64 only.
      target_compile_options(${target} PRIVATE /fsanitize=address /Zi)
      target_link_options(${target} PRIVATE /INCREMENTAL:NO)
    endif()
  else()
    target_compile_options(${target} PRIVATE ${ISF_GNU_WARNING_FLAGS})
    if(ISF_WERROR)
      target_compile_options(${target} PRIVATE -Werror)
    endif()
    if(ISF_SANITIZE)
      target_compile_options(${target} PRIVATE
        -fsanitize=address,undefined -fno-omit-frame-pointer -g)
      target_link_options(${target} PRIVATE
        -fsanitize=address,undefined -fno-omit-frame-pointer)
    endif()
  endif()
endfunction()
