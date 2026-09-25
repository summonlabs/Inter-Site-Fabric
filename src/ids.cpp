// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "isf/ids.hpp"

#include <array>
#include <chrono>
#include <cstdio>
#include <random>
#include <string>

namespace isf {
namespace {

constexpr char kHexDigits[] = "0123456789abcdef";

[[nodiscard]] int hex_value(char c) noexcept {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return 10 + (c - 'a');
  }
  if (c >= 'A' && c <= 'F') {
    return 10 + (c - 'A');
  }
  return -1;
}

[[nodiscard]] std::uint64_t splitmix64(std::uint64_t& state) noexcept {
  state += 0x9E3779B97F4A7C15ULL;
  std::uint64_t z = state;
  z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
  z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
  return z ^ (z >> 31);
}

}  // namespace

std::string Id128::to_hex() const {
  std::string out(32, '0');
  for (unsigned i = 0; i < 16; ++i) {
    const unsigned shift = (15U - i) * 4U;
    out[i] = kHexDigits[(hi >> shift) & 0xFULL];
    out[16U + i] = kHexDigits[(lo >> shift) & 0xFULL];
  }
  return out;
}

std::string Id128::to_canonical() const {
  const std::string flat = to_hex();
  std::string out;
  out.reserve(36);
  out.append(flat, 0, 8);
  out.push_back('-');
  out.append(flat, 8, 4);
  out.push_back('-');
  out.append(flat, 12, 4);
  out.push_back('-');
  out.append(flat, 16, 4);
  out.push_back('-');
  out.append(flat, 20, 12);
  return out;
}

Expected<Id128> Id128::parse(std::string_view text) {
  std::string compact;
  compact.reserve(32);
  for (const char c : text) {
    if (c == '-') {
      continue;
    }
    compact.push_back(c);
  }
  if (compact.size() != 32) {
    return Outcome(Status::Invalid, "identity must contain exactly 32 hex digits");
  }
  Id128 out;
  for (std::size_t i = 0; i < 32; ++i) {
    const int v = hex_value(compact[i]);
    if (v < 0) {
      return Outcome(Status::Invalid, "identity contains a non-hexadecimal character");
    }
    std::uint64_t& target = (i < 16) ? out.hi : out.lo;
    target = (target << 4) | static_cast<std::uint64_t>(v);
  }
  return out;
}

Id128 Id128::from_seed(std::uint64_t a, std::uint64_t b) noexcept {
  std::uint64_t state = a ^ (b * 0xD6E8FEB86659FD93ULL);
  Id128 out;
  out.hi = splitmix64(state);
  out.lo = splitmix64(state);
  if (out.is_nil()) {
    out.lo = 1;
  }
  return out;
}

Id128 Id128::random() noexcept {
  static thread_local std::mt19937_64 engine{[] {
    std::random_device rd;
    std::seed_seq seq{rd(), rd(), rd(), rd(),
                      static_cast<unsigned>(std::chrono::steady_clock::now().time_since_epoch().count())};
    return std::mt19937_64(seq);
  }()};
  Id128 out;
  out.hi = engine();
  out.lo = engine();
  if (out.is_nil()) {
    out.lo = 1;
  }
  return out;
}

std::uint64_t Id128::hash() const noexcept {
  std::uint64_t x = hi ^ (lo + 0x9E3779B97F4A7C15ULL + (hi << 6) + (hi >> 2));
  x ^= x >> 33;
  x *= 0xFF51AFD7ED558CCDULL;
  x ^= x >> 33;
  return x;
}

}  // namespace isf
