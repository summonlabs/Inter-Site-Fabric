// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "isf/status.hpp"

#include <array>

namespace isf {
namespace {

struct StatusName {
  Status status;
  const char* name;
};

constexpr std::array<StatusName, 24> kStatusNames{{
    {Status::Ok, "OK"},
    {Status::Unknown, "UNKNOWN"},
    {Status::Unsupported, "UNSUPPORTED"},
    {Status::Stale, "STALE"},
    {Status::Conflicting, "CONFLICTING"},
    {Status::Incomplete, "INCOMPLETE"},
    {Status::Indeterminate, "INDETERMINATE"},
    {Status::Refused, "REFUSED"},
    {Status::Cancelled, "CANCELLED"},
    {Status::Invalid, "INVALID"},
    {Status::NotFound, "NOT_FOUND"},
    {Status::Duplicate, "DUPLICATE"},
    {Status::Exhausted, "EXHAUSTED"},
    {Status::Denied, "DENIED"},
    {Status::LimitExceeded, "LIMIT_EXCEEDED"},
    {Status::InvalidTransition, "INVALID_TRANSITION"},
    {Status::Corrupt, "CORRUPT"},
    {Status::VersionMismatch, "VERSION_MISMATCH"},
    {Status::Unauthorized, "UNAUTHORIZED"},
    {Status::Busy, "BUSY"},
    {Status::Expired, "EXPIRED"},
    {Status::Fenced, "FENCED"},
    {Status::Unavailable, "UNAVAILABLE"},
    {Status::Ambiguous, "AMBIGUOUS"},
}};

}  // namespace

const char* status_name(Status s) noexcept {
  for (const auto& entry : kStatusNames) {
    if (entry.status == s) {
      return entry.name;
    }
  }
  return "INVALID";
}

Status status_from_name(std::string_view name, bool& recognized) noexcept {
  for (const auto& entry : kStatusNames) {
    if (name == entry.name) {
      recognized = true;
      return entry.status;
    }
  }
  recognized = false;
  return Status::Invalid;
}

std::string Outcome::to_string() const {
  std::string out = status_name(status_);
  if (!detail_.empty()) {
    out += ": ";
    out += detail_;
  }
  return out;
}

}  // namespace isf
