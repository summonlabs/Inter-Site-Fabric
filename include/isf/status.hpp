// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Typed outcomes. Every failure mode that the runtime can report is a distinct,
// named status; no failure is ever collapsed into a generic "false" and no
// missing evidence is ever reported as success.

#ifndef ISF_STATUS_HPP
#define ISF_STATUS_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace isf {

/// Discrete outcome of an operation.
///
/// The states below are deliberately kept distinct:
///   - Unknown        : the authority has no evidence either way.
///   - Unsupported    : the request is well formed but not implemented here.
///   - Stale          : the request was valid for a superseded generation,
///                      epoch, incarnation, or lease.
///   - Conflicting    : two pieces of evidence disagree; no winner is selected.
///   - Incomplete     : evidence exists but does not cover the whole question.
///   - Indeterminate  : the durable record does not say whether a commit
///                      happened. Conservatively treated as committed.
///   - Refused        : policy declined the request. Not an error.
///   - Cancelled      : the caller withdrew the request before a decision.
///   - Invalid       : the request is malformed or violates a structural rule.
enum class Status : std::uint8_t {
  Ok = 0,
  Unknown,
  Unsupported,
  Stale,
  Conflicting,
  Incomplete,
  Indeterminate,
  Refused,
  Cancelled,
  Invalid,
  NotFound,
  Duplicate,
  Exhausted,
  Denied,
  LimitExceeded,
  InvalidTransition,
  Corrupt,
  VersionMismatch,
  Unauthorized,
  Busy,
  Expired,
  Fenced,
  Unavailable,
  Ambiguous,
};

/// Stable machine readable name of a status. Never localized.
[[nodiscard]] const char* status_name(Status s) noexcept;

/// Parse a status name produced by status_name(). Returns Status::Invalid when
/// the name is not recognized (the caller cannot distinguish "no such status"
/// from "the invalid status" by design; use the bool out-parameter).
[[nodiscard]] Status status_from_name(std::string_view name, bool& recognized) noexcept;

/// True only for Status::Ok.
[[nodiscard]] constexpr bool is_ok(Status s) noexcept { return s == Status::Ok; }

/// True for statuses that indicate the request was structurally acceptable but
/// could not be satisfied. Refusals are normal protocol outcomes.
[[nodiscard]] constexpr bool is_refusal(Status s) noexcept {
  return s == Status::Refused || s == Status::Denied || s == Status::Exhausted ||
         s == Status::LimitExceeded;
}

/// True for statuses that mean "the authority cannot prove a positive answer".
[[nodiscard]] constexpr bool is_indeterminate(Status s) noexcept {
  return s == Status::Unknown || s == Status::Incomplete ||
         s == Status::Indeterminate || s == Status::Conflicting ||
         s == Status::Ambiguous || s == Status::Unavailable;
}

/// A status plus optional human readable context. The context is diagnostic
/// only; program logic must branch on the status.
class Outcome {
 public:
  Outcome() = default;
  Outcome(Status s) : status_(s) {}  // NOLINT(google-explicit-constructor)
  Outcome(Status s, std::string detail) : status_(s), detail_(std::move(detail)) {}

  [[nodiscard]] static Outcome success() { return Outcome{}; }
  [[nodiscard]] static Outcome of(Status s, std::string detail = {}) {
    return Outcome(s, std::move(detail));
  }

  [[nodiscard]] Status status() const noexcept { return status_; }
  [[nodiscard]] bool ok() const noexcept { return status_ == Status::Ok; }
  [[nodiscard]] const std::string& detail() const noexcept { return detail_; }
  [[nodiscard]] std::string to_string() const;

  /// An Outcome is its status plus diagnostics. Converting to the bare status
  /// is explicit in intent but implicit in syntax, so that a function returning
  /// Status can report a typed failure with context in one statement.
  [[nodiscard]] operator Status() const noexcept { return status_; }  // NOLINT

 private:
  Status status_{Status::Ok};
  std::string detail_{};
};

/// A value or a failure. Construction from T yields success; construction from
/// Outcome or Status yields failure. value() must not be called on a failure.
template <class T>
class Expected {
 public:
  Expected(T value) : value_(std::move(value)) {}          // NOLINT(google-explicit-constructor)
  Expected(Outcome outcome) : outcome_(std::move(outcome)) {}  // NOLINT(google-explicit-constructor)
  Expected(Status status) : outcome_(status) {}            // NOLINT(google-explicit-constructor)

  [[nodiscard]] bool ok() const noexcept { return value_.has_value(); }
  [[nodiscard]] Status status() const noexcept {
    return value_.has_value() ? Status::Ok : outcome_.status();
  }
  [[nodiscard]] const std::string& detail() const noexcept { return outcome_.detail(); }
  [[nodiscard]] Outcome outcome() const {
    return value_.has_value() ? Outcome{} : outcome_;
  }

  T& value() & { return *value_; }
  const T& value() const& { return *value_; }
  T&& value() && { return std::move(*value_); }

  T value_or(T fallback) const { return value_.has_value() ? *value_ : std::move(fallback); }

  const T* operator->() const { return &*value_; }
  T* operator->() { return &*value_; }
  const T& operator*() const& { return *value_; }
  T& operator*() & { return *value_; }

 private:
  std::optional<T> value_{};
  Outcome outcome_{};
};

}  // namespace isf

#endif  // ISF_STATUS_HPP
