// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Integrity primitives. CRC32C is used for cheap frame/record damage detection;
// SHA-256 is used for hash chaining so that a corrupted or spliced record stream
// cannot be made to look internally consistent by editing one checksum.

#ifndef ISF_DIGEST_HPP
#define ISF_DIGEST_HPP

#include "isf/status.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace isf {

using Byte = std::uint8_t;
using ByteSpan = std::span<const Byte>;

/// CRC-32C (Castagnoli), reflected, init 0xFFFFFFFF, final xor 0xFFFFFFFF.
[[nodiscard]] std::uint32_t crc32c(ByteSpan data) noexcept;

/// Incremental CRC-32C.
class Crc32c {
 public:
  void update(ByteSpan data) noexcept;
  void update(Byte b) noexcept;
  [[nodiscard]] std::uint32_t value() const noexcept;
  void reset() noexcept { state_ = 0xFFFFFFFFU; }

 private:
  std::uint32_t state_{0xFFFFFFFFU};
};

/// A SHA-256 digest value.
class Digest256 {
 public:
  Digest256() = default;
  explicit Digest256(std::array<Byte, 32> bytes) : bytes_(bytes) {}

  [[nodiscard]] static Digest256 of(ByteSpan data) noexcept;
  [[nodiscard]] static Digest256 zero() noexcept { return Digest256{}; }

  [[nodiscard]] const std::array<Byte, 32>& bytes() const noexcept { return bytes_; }
  [[nodiscard]] bool is_zero() const noexcept;
  [[nodiscard]] std::string to_hex() const;
  [[nodiscard]] static Expected<Digest256> parse(std::string_view text);
  [[nodiscard]] std::string to_string() const { return "sha256:" + to_hex(); }

  friend bool operator==(const Digest256&, const Digest256&) = default;
  friend auto operator<=>(const Digest256&, const Digest256&) = default;

 private:
  std::array<Byte, 32> bytes_{};
};

/// Incremental SHA-256.
class Sha256 {
 public:
  Sha256() { reset(); }

  void reset() noexcept;
  void update(ByteSpan data) noexcept;
  void update(Byte b) noexcept;
  [[nodiscard]] Digest256 finish() noexcept;

 private:
  void compress(const Byte* block) noexcept;

  std::array<std::uint32_t, 8> state_{};
  std::array<Byte, 64> buffer_{};
  std::size_t buffered_{0};
  std::uint64_t total_{0};
};

/// FNV-1a 64-bit, used only for non-adversarial hash containers and sampling.
[[nodiscard]] std::uint64_t fnv1a64(std::string_view text) noexcept;

}  // namespace isf

#endif  // ISF_DIGEST_HPP
