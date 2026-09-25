// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#ifndef ISF_CLOCK_HPP
#define ISF_CLOCK_HPP

#include <chrono>
#include <cstdint>

namespace isf {

/// Milliseconds since the Unix epoch from the system clock. The authority never
/// reads a clock itself; callers pass a time so that behaviour is deterministic
/// under test.
[[nodiscard]] inline std::uint64_t now_ms() {
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count());
}

/// Monotonic milliseconds for measuring elapsed time only.
[[nodiscard]] inline std::uint64_t monotonic_ms() {
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::steady_clock::now().time_since_epoch())
          .count());
}

}  // namespace isf

#endif  // ISF_CLOCK_HPP
