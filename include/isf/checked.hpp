// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Checked arithmetic. Capacity arithmetic must never wrap: a wrapped capacity
// total is indistinguishable from a legitimate small total and would silently
// fabricate headroom.

#ifndef ISF_CHECKED_HPP
#define ISF_CHECKED_HPP

#include "isf/status.hpp"

#include <cstdint>
#include <limits>

namespace isf {

using Amount = std::uint64_t;

inline constexpr Amount kAmountMax = std::numeric_limits<Amount>::max();

/// a + b, or Status::LimitExceeded on overflow.
[[nodiscard]] inline Expected<Amount> checked_add(Amount a, Amount b) {
  if (a > kAmountMax - b) {
    return Outcome(Status::LimitExceeded, "capacity addition overflowed 64 bits");
  }
  return a + b;
}

/// a - b, or Status::Invalid when the result would be negative. Capacity is
/// unsigned; a negative intermediate means the caller's invariant is broken.
[[nodiscard]] inline Expected<Amount> checked_sub(Amount a, Amount b) {
  if (b > a) {
    return Outcome(Status::Invalid, "capacity subtraction would underflow");
  }
  return a - b;
}

/// a * b, or Status::LimitExceeded on overflow.
[[nodiscard]] inline Expected<Amount> checked_mul(Amount a, Amount b) {
  if (a == 0 || b == 0) {
    return Amount{0};
  }
  if (a > kAmountMax / b) {
    return Outcome(Status::LimitExceeded, "capacity multiplication overflowed 64 bits");
  }
  return a * b;
}

/// Saturating addition; used only where saturation is explicitly the documented
/// behaviour (statistics counters), never for authority accounting.
[[nodiscard]] constexpr Amount saturating_add(Amount a, Amount b) noexcept {
  return a > kAmountMax - b ? kAmountMax : a + b;
}

/// Narrowing conversion with a range check.
[[nodiscard]] inline Expected<std::uint32_t> narrow_u32(std::uint64_t value) {
  if (value > std::numeric_limits<std::uint32_t>::max()) {
    return Outcome(Status::LimitExceeded, "value does not fit in 32 bits");
  }
  return static_cast<std::uint32_t>(value);
}

}  // namespace isf

#endif  // ISF_CHECKED_HPP
