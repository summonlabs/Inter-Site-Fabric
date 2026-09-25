// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Canonical, bounds-checked binary encoding. The same encoder produces the
// canonical byte image of authoritative state that is hashed for the ledger
// digest, so the encoding must be deterministic: little-endian fixed-width
// integers, length-prefixed byte strings, no padding, no optional field elision.

#ifndef ISF_WIRE_HPP
#define ISF_WIRE_HPP

#include "isf/digest.hpp"
#include "isf/ids.hpp"
#include "isf/status.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace isf {

/// Hard bounds applied to every decode. A decoder never allocates based on an
/// attacker supplied length before checking it against these limits.
struct WireLimits {
  std::size_t max_bytes{1U << 20};      ///< 1 MiB total record / frame payload
  std::size_t max_string{4096};         ///< bytes of one string field
  std::size_t max_container{4096};      ///< elements of one repeated field
  std::size_t max_nesting{8};           ///< nested structure depth

  static WireLimits strict() noexcept { return WireLimits{}; }
};

/// True when the bytes are well formed UTF-8 (no overlong forms, no surrogates,
/// no code points beyond U+10FFFF). Invalid input is rejected rather than
/// replaced, so that two different byte strings never encode to one name.
[[nodiscard]] bool is_valid_utf8(std::string_view text) noexcept;

/// Append-only canonical encoder.
class Writer {
 public:
  explicit Writer(WireLimits limits = WireLimits{}) : limits_(limits) {}

  void u8(std::uint8_t value);
  void u16(std::uint16_t value);
  void u32(std::uint32_t value);
  void u64(std::uint64_t value);
  void i64(std::int64_t value);
  void boolean(bool value);
  void bytes(ByteSpan value);
  void str(std::string_view value);
  void id128(const Id128& value);
  void digest(const Digest256& value);
  void generation(const Generation& value) { u64(value.value); }
  void epoch(const Epoch& value) { u64(value.value); }

  [[nodiscard]] const std::vector<Byte>& buffer() const noexcept { return buffer_; }
  [[nodiscard]] std::size_t size() const noexcept { return buffer_.size(); }
  [[nodiscard]] ByteSpan span() const noexcept { return ByteSpan(buffer_.data(), buffer_.size()); }
  void clear() noexcept { buffer_.clear(); }

  /// True when the encoder is still inside its byte budget.
  [[nodiscard]] bool within_limits() const noexcept { return buffer_.size() <= limits_.max_bytes; }

  [[nodiscard]] const WireLimits& limits() const noexcept { return limits_; }

 private:
  void raw(ByteSpan value);
  [[nodiscard]] Status check_size(std::size_t additional) const;

  WireLimits limits_{};
  std::vector<Byte> buffer_{};
};

/// Bounds-checked canonical decoder. Every read validates that enough bytes
/// remain before touching memory, and every length is validated against the
/// configured limit before allocation.
class Reader {
 public:
  explicit Reader(ByteSpan data, WireLimits limits = WireLimits{}) : data_(data), limits_(limits) {}

  [[nodiscard]] Expected<std::uint8_t> u8();
  [[nodiscard]] Expected<std::uint16_t> u16();
  [[nodiscard]] Expected<std::uint32_t> u32();
  [[nodiscard]] Expected<std::uint64_t> u64();
  [[nodiscard]] Expected<std::int64_t> i64();
  [[nodiscard]] Expected<bool> boolean();
  [[nodiscard]] Expected<std::string> str();
  [[nodiscard]] Expected<ByteSpan> bytes();
  [[nodiscard]] Expected<Id128> id128();
  [[nodiscard]] Expected<Digest256> digest();
  [[nodiscard]] Expected<Generation> generation();
  [[nodiscard]] Expected<Epoch> epoch();

  /// Validate and consume a repeated-field count before iterating.
  [[nodiscard]] Expected<std::uint32_t> container_count();

  [[nodiscard]] std::size_t remaining() const noexcept { return data_.size() - offset_; }
  [[nodiscard]] bool at_end() const noexcept { return offset_ == data_.size(); }
  [[nodiscard]] std::size_t offset() const noexcept { return offset_; }

  /// Status::Ok when fully consumed, Status::Invalid when trailing bytes remain.
  [[nodiscard]] Status require_end() const;

  [[nodiscard]] const WireLimits& limits() const noexcept { return limits_; }

 private:
  [[nodiscard]] Expected<ByteSpan> take(std::size_t count);

  ByteSpan data_{};
  WireLimits limits_{};
  std::size_t offset_{0};
};

}  // namespace isf

#endif  // ISF_WIRE_HPP
