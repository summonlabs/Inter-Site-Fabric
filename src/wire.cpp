// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "isf/wire.hpp"

#include "isf/checked.hpp"

#include <cstring>

namespace isf {

bool is_valid_utf8(std::string_view text) noexcept {
  const auto* p = reinterpret_cast<const unsigned char*>(text.data());
  const std::size_t n = text.size();
  std::size_t i = 0;
  while (i < n) {
    const unsigned char lead = p[i];
    std::size_t extra = 0;
    std::uint32_t code = 0;
    if (lead < 0x80U) {
      ++i;
      continue;
    } else if ((lead & 0xE0U) == 0xC0U) {
      extra = 1;
      code = lead & 0x1FU;
      if (code == 0) {
        return false;  // overlong
      }
    } else if ((lead & 0xF0U) == 0xE0U) {
      extra = 2;
      code = lead & 0x0FU;
    } else if ((lead & 0xF8U) == 0xF0U) {
      extra = 3;
      code = lead & 0x07U;
    } else {
      return false;  // continuation byte or 5/6-byte form
    }
    if (i + extra >= n) {
      return false;  // truncated sequence
    }
    for (std::size_t k = 1; k <= extra; ++k) {
      const unsigned char cont = p[i + k];
      if ((cont & 0xC0U) != 0x80U) {
        return false;
      }
      code = (code << 6) | static_cast<std::uint32_t>(cont & 0x3FU);
    }
    if (extra == 2 && code < 0x800U) {
      return false;  // overlong
    }
    if (extra == 3 && code < 0x10000U) {
      return false;  // overlong
    }
    if (code > 0x10FFFFU) {
      return false;
    }
    if (code >= 0xD800U && code <= 0xDFFFU) {
      return false;  // UTF-16 surrogate half
    }
    i += extra + 1;
  }
  return true;
}

Status Writer::check_size(std::size_t additional) const {
  if (additional > limits_.max_bytes || buffer_.size() > limits_.max_bytes - additional) {
    return Status::LimitExceeded;
  }
  return Status::Ok;
}

void Writer::raw(ByteSpan value) {
  buffer_.insert(buffer_.end(), value.begin(), value.end());
}

void Writer::u8(std::uint8_t value) { buffer_.push_back(value); }

void Writer::u16(std::uint16_t value) {
  buffer_.push_back(static_cast<Byte>(value & 0xFFU));
  buffer_.push_back(static_cast<Byte>((value >> 8) & 0xFFU));
}

void Writer::u32(std::uint32_t value) {
  for (unsigned i = 0; i < 4; ++i) {
    buffer_.push_back(static_cast<Byte>((value >> (i * 8U)) & 0xFFU));
  }
}

void Writer::u64(std::uint64_t value) {
  for (unsigned i = 0; i < 8; ++i) {
    buffer_.push_back(static_cast<Byte>((value >> (i * 8U)) & 0xFFU));
  }
}

void Writer::i64(std::int64_t value) { u64(static_cast<std::uint64_t>(value)); }

void Writer::boolean(bool value) { u8(value ? 1U : 0U); }

void Writer::bytes(ByteSpan value) {
  u32(static_cast<std::uint32_t>(value.size()));
  raw(value);
}

void Writer::str(std::string_view value) {
  u32(static_cast<std::uint32_t>(value.size()));
  raw(ByteSpan(reinterpret_cast<const Byte*>(value.data()), value.size()));
}

void Writer::id128(const Id128& value) {
  u64(value.hi);
  u64(value.lo);
}

void Writer::digest(const Digest256& value) { raw(ByteSpan(value.bytes().data(), value.bytes().size())); }

Expected<ByteSpan> Reader::take(std::size_t count) {
  if (count > remaining()) {
    return Outcome(Status::Invalid, "truncated field");
  }
  const ByteSpan out(data_.data() + offset_, count);
  offset_ += count;
  return out;
}

Expected<std::uint8_t> Reader::u8() {
  auto span = take(1);
  if (!span.ok()) {
    return span.status();
  }
  return span.value()[0];
}

Expected<std::uint16_t> Reader::u16() {
  auto span = take(2);
  if (!span.ok()) {
    return span.status();
  }
  return static_cast<std::uint16_t>(static_cast<std::uint16_t>(span.value()[0]) |
                                    (static_cast<std::uint16_t>(span.value()[1]) << 8));
}

Expected<std::uint32_t> Reader::u32() {
  auto span = take(4);
  if (!span.ok()) {
    return span.status();
  }
  std::uint32_t out = 0;
  for (unsigned i = 0; i < 4; ++i) {
    out |= static_cast<std::uint32_t>(span.value()[i]) << (i * 8U);
  }
  return out;
}

Expected<std::uint64_t> Reader::u64() {
  auto span = take(8);
  if (!span.ok()) {
    return span.status();
  }
  std::uint64_t out = 0;
  for (unsigned i = 0; i < 8; ++i) {
    out |= static_cast<std::uint64_t>(span.value()[i]) << (i * 8U);
  }
  return out;
}

Expected<std::int64_t> Reader::i64() {
  auto value = u64();
  if (!value.ok()) {
    return value.status();
  }
  return static_cast<std::int64_t>(value.value());
}

Expected<bool> Reader::boolean() {
  auto value = u8();
  if (!value.ok()) {
    return value.status();
  }
  if (value.value() > 1U) {
    return Outcome(Status::Invalid, "boolean field carried a value other than 0 or 1");
  }
  return value.value() == 1U;
}

Expected<ByteSpan> Reader::bytes() {
  auto length = u32();
  if (!length.ok()) {
    return length.status();
  }
  const std::size_t count = length.value();
  if (count > limits_.max_bytes) {
    return Outcome(Status::LimitExceeded, "byte field exceeds the configured byte limit");
  }
  auto span = take(count);
  if (!span.ok()) {
    return span.status();
  }
  return span.value();
}

Expected<std::string> Reader::str() {
  auto length = u32();
  if (!length.ok()) {
    return length.status();
  }
  const std::size_t count = length.value();
  if (count > limits_.max_string) {
    return Outcome(Status::LimitExceeded, "string field exceeds the configured string limit");
  }
  auto span = take(count);
  if (!span.ok()) {
    return span.status();
  }
  const std::string_view view(reinterpret_cast<const char*>(span.value().data()), span.value().size());
  if (!is_valid_utf8(view)) {
    return Outcome(Status::Invalid, "string field is not valid UTF-8");
  }
  return std::string(view);
}

Expected<Id128> Reader::id128() {
  auto high = u64();
  if (!high.ok()) {
    return high.status();
  }
  auto low = u64();
  if (!low.ok()) {
    return low.status();
  }
  return Id128{high.value(), low.value()};
}

Expected<Digest256> Reader::digest() {
  auto span = take(32);
  if (!span.ok()) {
    return span.status();
  }
  std::array<Byte, 32> bytes{};
  std::memcpy(bytes.data(), span.value().data(), 32);
  return Digest256(bytes);
}

Expected<Generation> Reader::generation() {
  auto value = u64();
  if (!value.ok()) {
    return value.status();
  }
  return Generation{value.value()};
}

Expected<Epoch> Reader::epoch() {
  auto value = u64();
  if (!value.ok()) {
    return value.status();
  }
  return Epoch{value.value()};
}

Expected<std::uint32_t> Reader::container_count() {
  auto count = u32();
  if (!count.ok()) {
    return count.status();
  }
  if (count.value() > limits_.max_container) {
    return Outcome(Status::LimitExceeded, "repeated field exceeds the configured element limit");
  }
  // A repeated field must be able to fit at least one byte per element; this
  // rejects absurd counts before the caller reserves storage for them.
  if (count.value() > remaining() + 1U) {
    return Outcome(Status::Invalid, "repeated field count exceeds the remaining payload");
  }
  return count.value();
}

Status Reader::require_end() const {
  return at_end() ? Status::Ok : Status::Invalid;
}

}  // namespace isf
