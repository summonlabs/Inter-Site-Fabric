// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Strongly typed identities. A SiteId can never be assigned to a PathId, and
// every identity carries 128 bits so that independently generated identities in
// independent processes do not collide in practice. Identities are values: they
// are copyable, orderable, hashable, and parseable from their canonical text.

#ifndef ISF_IDS_HPP
#define ISF_IDS_HPP

#include "isf/status.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>

namespace isf {

/// A 128-bit opaque identity value.
struct Id128 {
  std::uint64_t hi{0};
  std::uint64_t lo{0};

  friend bool operator==(const Id128&, const Id128&) = default;
  friend auto operator<=>(const Id128&, const Id128&) = default;

  [[nodiscard]] bool is_nil() const noexcept { return hi == 0 && lo == 0; }

  /// 32 lowercase hex digits, no separators.
  [[nodiscard]] std::string to_hex() const;

  /// Canonical grouped form: 8-4-4-4-12 lowercase hex digits.
  [[nodiscard]] std::string to_canonical() const;

  /// Parse either the 32-digit flat form or the 8-4-4-4-12 grouped form.
  /// Returns Status::Invalid when the text is not a well formed identity.
  [[nodiscard]] static Expected<Id128> parse(std::string_view text);

  /// Deterministic construction from two 64-bit seeds (SplitMix64 mixing).
  /// Used by tests and by deterministic reference models.
  [[nodiscard]] static Id128 from_seed(std::uint64_t a, std::uint64_t b) noexcept;

  /// Cryptographically seeded construction from the process entropy source.
  [[nodiscard]] static Id128 random() noexcept;

  [[nodiscard]] std::uint64_t hash() const noexcept;
};

/// Tag types. Each names a distinct identity domain.
struct SiteIdTag {
  static constexpr const char* prefix = "site";
};
struct PathIdTag {
  static constexpr const char* prefix = "path";
};
struct EdgeIdTag {
  static constexpr const char* prefix = "edge";
};
struct GrantIdTag {
  static constexpr const char* prefix = "grant";
};
struct LeaseIdTag {
  static constexpr const char* prefix = "lease";
};
struct RequestIdTag {
  static constexpr const char* prefix = "req";
};
struct SessionIdTag {
  static constexpr const char* prefix = "sess";
};
struct DomainIdTag {
  static constexpr const char* prefix = "srd";
};
struct PrincipalIdTag {
  static constexpr const char* prefix = "principal";
};
struct IncarnationTag {
  static constexpr const char* prefix = "inc";
};
struct PolicyIdTag {
  static constexpr const char* prefix = "policy";
};
struct StoreIdTag {
  static constexpr const char* prefix = "store";
};
struct VerificationIdTag {
  static constexpr const char* prefix = "verify";
};
struct OversubscriptionIdTag {
  static constexpr const char* prefix = "oversub";
};
struct AttestationIdTag {
  static constexpr const char* prefix = "attest";
};
struct AttemptIdTag {
  static constexpr const char* prefix = "attempt";
};

/// A strongly typed 128-bit identity. Distinct Tag types are distinct,
/// non-convertible C++ types.
template <class Tag>
class TypedId {
 public:
  TypedId() = default;
  explicit TypedId(Id128 value) : value_(value) {}

  [[nodiscard]] static TypedId from_raw(Id128 value) { return TypedId(value); }
  [[nodiscard]] static TypedId from_seed(std::uint64_t a, std::uint64_t b) {
    return TypedId(Id128::from_seed(a, b));
  }
  [[nodiscard]] static TypedId random() { return TypedId(Id128::random()); }

  [[nodiscard]] static Expected<TypedId> parse(std::string_view text) {
    std::string_view body = text;
    const std::string_view pfx{Tag::prefix};
    if (body.size() > pfx.size() + 1 && body.substr(0, pfx.size()) == pfx &&
        body[pfx.size()] == ':') {
      body.remove_prefix(pfx.size() + 1);
    }
    auto parsed = Id128::parse(body);
    if (!parsed.ok()) {
      return parsed.status();
    }
    return TypedId(parsed.value());
  }

  [[nodiscard]] const Id128& raw() const noexcept { return value_; }
  [[nodiscard]] bool is_nil() const noexcept { return value_.is_nil(); }

  /// Canonical text form: "<prefix>:<8-4-4-4-12>".
  [[nodiscard]] std::string to_string() const {
    std::string out{Tag::prefix};
    out.push_back(':');
    out += value_.to_canonical();
    return out;
  }

  [[nodiscard]] std::uint64_t hash() const noexcept { return value_.hash(); }

  friend bool operator==(const TypedId&, const TypedId&) = default;
  friend auto operator<=>(const TypedId&, const TypedId&) = default;

 private:
  Id128 value_{};
};

using SiteId = TypedId<SiteIdTag>;
using PathId = TypedId<PathIdTag>;
using EdgeId = TypedId<EdgeIdTag>;
using GrantId = TypedId<GrantIdTag>;
using LeaseId = TypedId<LeaseIdTag>;
using RequestId = TypedId<RequestIdTag>;
using SessionId = TypedId<SessionIdTag>;
using DomainId = TypedId<DomainIdTag>;
using PrincipalId = TypedId<PrincipalIdTag>;
using Incarnation = TypedId<IncarnationTag>;
using PolicyId = TypedId<PolicyIdTag>;
using StoreId = TypedId<StoreIdTag>;
using VerificationId = TypedId<VerificationIdTag>;
using OversubscriptionId = TypedId<OversubscriptionIdTag>;
using AttestationId = TypedId<AttestationIdTag>;
using AttemptId = TypedId<AttemptIdTag>;

/// Monotonic per-object generation. Generation 0 means "never assigned".
struct Generation {
  std::uint64_t value{0};

  friend bool operator==(const Generation&, const Generation&) = default;
  friend auto operator<=>(const Generation&, const Generation&) = default;

  [[nodiscard]] bool is_nil() const noexcept { return value == 0; }
  [[nodiscard]] Generation next() const noexcept { return Generation{value + 1}; }
  [[nodiscard]] std::string to_string() const { return std::to_string(value); }
};

/// Monotonic authority epoch. An epoch bump invalidates every artifact issued
/// under an earlier epoch, including leases that would otherwise still be live.
struct Epoch {
  std::uint64_t value{0};

  friend bool operator==(const Epoch&, const Epoch&) = default;
  friend auto operator<=>(const Epoch&, const Epoch&) = default;

  [[nodiscard]] Generation as_generation() const noexcept { return Generation{value}; }
  [[nodiscard]] std::string to_string() const { return std::to_string(value); }
};

/// Monotonic arbitration sequence. Assigned exactly once, under the authority
/// lock, at the moment a mutating request enters the authority. The sequence is
/// the total order that makes concurrent reservation outcomes deterministic:
/// the resulting state is a pure function of (initial state, request order).
struct ArbSeq {
  std::uint64_t value{0};

  friend bool operator==(const ArbSeq&, const ArbSeq&) = default;
  friend auto operator<=>(const ArbSeq&, const ArbSeq&) = default;

  [[nodiscard]] std::string to_string() const { return std::to_string(value); }
};

}  // namespace isf

namespace std {
template <class Tag>
struct hash<isf::TypedId<Tag>> {
  std::size_t operator()(const isf::TypedId<Tag>& id) const noexcept {
    return static_cast<std::size_t>(id.hash());
  }
};

template <>
struct hash<isf::Id128> {
  std::size_t operator()(const isf::Id128& id) const noexcept {
    return static_cast<std::size_t>(id.hash());
  }
};
}  // namespace std

#endif  // ISF_IDS_HPP
