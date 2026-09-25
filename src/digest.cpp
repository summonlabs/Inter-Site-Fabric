// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "isf/digest.hpp"

#include <cstring>

namespace isf {
namespace {

// ---------------------------------------------------------------------------
// CRC-32C (Castagnoli)
// ---------------------------------------------------------------------------

struct Crc32cTable {
  std::array<std::uint32_t, 256> entries{};

  constexpr Crc32cTable() {
    constexpr std::uint32_t kPoly = 0x82F63B78U;  // reflected 0x1EDC6F41
    for (std::uint32_t i = 0; i < 256; ++i) {
      std::uint32_t crc = i;
      for (int bit = 0; bit < 8; ++bit) {
        crc = (crc & 1U) != 0U ? (crc >> 1) ^ kPoly : (crc >> 1);
      }
      entries[i] = crc;
    }
  }
};

constexpr Crc32cTable kCrc32cTable{};

// ---------------------------------------------------------------------------
// SHA-256
// ---------------------------------------------------------------------------

constexpr std::array<std::uint32_t, 64> kSha256K{{
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U,
    0xab1c5ed5U, 0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU,
    0x9bdc06a7U, 0xc19bf174U, 0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU,
    0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU, 0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
    0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U, 0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU,
    0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U, 0xa2bfe8a1U, 0xa81a664bU,
    0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U, 0x19a4c116U,
    0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U,
    0xc67178f2U,
}};

[[nodiscard]] constexpr std::uint32_t rotr(std::uint32_t x, unsigned n) noexcept {
  return (x >> n) | (x << (32U - n));
}

[[nodiscard]] constexpr std::uint32_t big_endian_u32(const Byte* p) noexcept {
  return (static_cast<std::uint32_t>(p[0]) << 24) | (static_cast<std::uint32_t>(p[1]) << 16) |
         (static_cast<std::uint32_t>(p[2]) << 8) | static_cast<std::uint32_t>(p[3]);
}

[[nodiscard]] constexpr char lower_hex(std::uint8_t nibble) noexcept {
  return static_cast<char>(nibble < 10 ? ('0' + nibble) : ('a' + (nibble - 10)));
}

[[nodiscard]] int hex_nibble(char c) noexcept {
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

}  // namespace

std::uint32_t crc32c(ByteSpan data) noexcept {
  std::uint32_t crc = 0xFFFFFFFFU;
  for (const Byte b : data) {
    crc = kCrc32cTable.entries[(crc ^ b) & 0xFFU] ^ (crc >> 8);
  }
  return crc ^ 0xFFFFFFFFU;
}

void Crc32c::update(ByteSpan data) noexcept {
  std::uint32_t crc = state_;
  for (const Byte b : data) {
    crc = kCrc32cTable.entries[(crc ^ b) & 0xFFU] ^ (crc >> 8);
  }
  state_ = crc;
}

void Crc32c::update(Byte b) noexcept {
  state_ = kCrc32cTable.entries[(state_ ^ b) & 0xFFU] ^ (state_ >> 8);
}

std::uint32_t Crc32c::value() const noexcept { return state_ ^ 0xFFFFFFFFU; }

void Sha256::reset() noexcept {
  state_ = {0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
            0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U};
  buffer_.fill(0);
  buffered_ = 0;
  total_ = 0;
}

void Sha256::compress(const Byte* block) noexcept {
  std::array<std::uint32_t, 64> w{};
  for (std::size_t i = 0; i < 16; ++i) {
    w[i] = big_endian_u32(block + (i * 4));
  }
  for (std::size_t i = 16; i < 64; ++i) {
    const std::uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
    const std::uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }

  std::uint32_t a = state_[0];
  std::uint32_t b = state_[1];
  std::uint32_t c = state_[2];
  std::uint32_t d = state_[3];
  std::uint32_t e = state_[4];
  std::uint32_t f = state_[5];
  std::uint32_t g = state_[6];
  std::uint32_t h = state_[7];

  for (std::size_t i = 0; i < 64; ++i) {
    const std::uint32_t s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
    const std::uint32_t ch = (e & f) ^ (~e & g);
    const std::uint32_t temp1 = h + s1 + ch + kSha256K[i] + w[i];
    const std::uint32_t s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
    const std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
    const std::uint32_t temp2 = s0 + maj;
    h = g;
    g = f;
    f = e;
    e = d + temp1;
    d = c;
    c = b;
    b = a;
    a = temp1 + temp2;
  }

  state_[0] += a;
  state_[1] += b;
  state_[2] += c;
  state_[3] += d;
  state_[4] += e;
  state_[5] += f;
  state_[6] += g;
  state_[7] += h;
}

void Sha256::update(ByteSpan data) noexcept {
  total_ += data.size();
  std::size_t offset = 0;
  if (buffered_ != 0) {
    const std::size_t want = 64 - buffered_;
    const std::size_t take = data.size() < want ? data.size() : want;
    std::memcpy(buffer_.data() + buffered_, data.data(), take);
    buffered_ += take;
    offset = take;
    if (buffered_ == 64) {
      compress(buffer_.data());
      buffered_ = 0;
    }
  }
  while (data.size() - offset >= 64) {
    compress(data.data() + offset);
    offset += 64;
  }
  if (offset < data.size()) {
    const std::size_t remaining = data.size() - offset;
    std::memcpy(buffer_.data(), data.data() + offset, remaining);
    buffered_ = remaining;
  }
}

void Sha256::update(Byte b) noexcept {
  const Byte local[1] = {b};
  update(ByteSpan(local, 1));
}

Digest256 Sha256::finish() noexcept {
  const std::uint64_t bit_length = total_ * 8ULL;
  const Byte pad = 0x80;
  update(ByteSpan(&pad, 1));
  const Byte zero = 0x00;
  while (buffered_ != 56) {
    update(ByteSpan(&zero, 1));
  }
  Byte length_bytes[8];
  for (int i = 0; i < 8; ++i) {
    length_bytes[i] = static_cast<Byte>((bit_length >> (56 - (i * 8))) & 0xFFULL);
  }
  // update() advances total_, but the digest is already captured in bit_length.
  update(ByteSpan(length_bytes, 8));
  std::array<Byte, 32> out{};
  for (std::size_t i = 0; i < 8; ++i) {
    out[i * 4 + 0] = static_cast<Byte>((state_[i] >> 24) & 0xFFU);
    out[i * 4 + 1] = static_cast<Byte>((state_[i] >> 16) & 0xFFU);
    out[i * 4 + 2] = static_cast<Byte>((state_[i] >> 8) & 0xFFU);
    out[i * 4 + 3] = static_cast<Byte>(state_[i] & 0xFFU);
  }
  return Digest256(out);
}

Digest256 Digest256::of(ByteSpan data) noexcept {
  Sha256 hasher;
  hasher.update(data);
  return hasher.finish();
}

bool Digest256::is_zero() const noexcept {
  for (const Byte b : bytes_) {
    if (b != 0) {
      return false;
    }
  }
  return true;
}

std::string Digest256::to_hex() const {
  std::string out(64, '0');
  for (std::size_t i = 0; i < 32; ++i) {
    out[i * 2] = lower_hex(static_cast<std::uint8_t>(bytes_[i] >> 4));
    out[i * 2 + 1] = lower_hex(static_cast<std::uint8_t>(bytes_[i] & 0x0FU));
  }
  return out;
}

Expected<Digest256> Digest256::parse(std::string_view text) {
  std::string_view body = text;
  constexpr std::string_view kPrefix = "sha256:";
  if (body.size() > kPrefix.size() && body.substr(0, kPrefix.size()) == kPrefix) {
    body.remove_prefix(kPrefix.size());
  }
  if (body.size() != 64) {
    return Outcome(Status::Invalid, "digest must contain exactly 64 hex digits");
  }
  std::array<Byte, 32> out{};
  for (std::size_t i = 0; i < 32; ++i) {
    const int high = hex_nibble(body[i * 2]);
    const int low = hex_nibble(body[i * 2 + 1]);
    if (high < 0 || low < 0) {
      return Outcome(Status::Invalid, "digest contains a non-hexadecimal character");
    }
    out[i] = static_cast<Byte>((high << 4) | low);
  }
  return Digest256(out);
}

std::uint64_t fnv1a64(std::string_view text) noexcept {
  std::uint64_t hash = 0xCBF29CE484222325ULL;
  for (const char c : text) {
    hash ^= static_cast<std::uint8_t>(c);
    hash *= 0x100000001B3ULL;
  }
  return hash;
}

}  // namespace isf
