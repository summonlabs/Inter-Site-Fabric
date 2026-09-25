// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "isf/lifecycle.hpp"

#include <array>
#include <string_view>

namespace isf {
namespace {

struct GrantTransition {
  GrantState from;
  std::array<GrantState, 5> to;
  std::uint8_t count;
};

constexpr std::array<GrantTransition, 10> kGrantTransitions{{
    {GrantState::Proposed, {GrantState::Eligible, GrantState::Refused, GrantState::Cancelled}, 3},
    {GrantState::Eligible,
     {GrantState::Reserved, GrantState::Refused, GrantState::Cancelled, GrantState::Expired},
     4},
    {GrantState::Reserved,
     {GrantState::Active, GrantState::Withdrawing, GrantState::Cancelled, GrantState::Expired},
     4},
    {GrantState::Active,
     {GrantState::Degraded, GrantState::Withdrawing, GrantState::Expired},
     3},
    {GrantState::Degraded,
     {GrantState::Active, GrantState::Withdrawing, GrantState::Expired},
     3},
    {GrantState::Withdrawing, {GrantState::Retired, GrantState::Expired}, 2},
    {GrantState::Retired, {}, 0},
    {GrantState::Refused, {}, 0},
    {GrantState::Cancelled, {}, 0},
    {GrantState::Expired, {}, 0},
}};

const GrantTransition* find_transition(GrantState from) noexcept {
  for (const auto& entry : kGrantTransitions) {
    if (entry.from == from) {
      return &entry;
    }
  }
  return nullptr;
}

}  // namespace

const char* grant_state_name(GrantState s) noexcept {
  switch (s) {
    case GrantState::Proposed:
      return "PROPOSED";
    case GrantState::Eligible:
      return "ELIGIBLE";
    case GrantState::Reserved:
      return "RESERVED";
    case GrantState::Active:
      return "ACTIVE";
    case GrantState::Degraded:
      return "DEGRADED";
    case GrantState::Withdrawing:
      return "WITHDRAWING";
    case GrantState::Retired:
      return "RETIRED";
    case GrantState::Refused:
      return "REFUSED";
    case GrantState::Cancelled:
      return "CANCELLED";
    case GrantState::Expired:
      return "EXPIRED";
  }
  return "INVALID";
}

bool grant_state_from_name(std::string_view name, GrantState& out) noexcept {
  constexpr std::array<GrantState, 10> kAll{GrantState::Proposed, GrantState::Eligible,
                                            GrantState::Reserved, GrantState::Active,
                                            GrantState::Degraded, GrantState::Withdrawing,
                                            GrantState::Retired,  GrantState::Refused,
                                            GrantState::Cancelled, GrantState::Expired};
  for (const GrantState s : kAll) {
    if (name == grant_state_name(s)) {
      out = s;
      return true;
    }
  }
  return false;
}

bool is_terminal(GrantState s) noexcept {
  return s == GrantState::Retired || s == GrantState::Refused || s == GrantState::Cancelled ||
         s == GrantState::Expired;
}

bool holds_capacity(GrantState s) noexcept {
  switch (s) {
    case GrantState::Reserved:
    case GrantState::Active:
    case GrantState::Degraded:
    case GrantState::Withdrawing:
      return true;
    default:
      return false;
  }
}

bool is_reclaimable(GrantState s) noexcept {
  return s == GrantState::Reserved || s == GrantState::Degraded || s == GrantState::Withdrawing;
}

bool is_live_obligation(GrantState s) noexcept {
  return s == GrantState::Active || s == GrantState::Degraded;
}

bool can_transition(GrantState from, GrantState to) noexcept {
  const GrantTransition* entry = find_transition(from);
  if (entry == nullptr) {
    return false;
  }
  for (std::uint8_t i = 0; i < entry->count; ++i) {
    if (entry->to[i] == to) {
      return true;
    }
  }
  return false;
}

std::uint32_t successor_mask(GrantState s) noexcept {
  const GrantTransition* entry = find_transition(s);
  if (entry == nullptr) {
    return 0;
  }
  std::uint32_t mask = 0;
  for (std::uint8_t i = 0; i < entry->count; ++i) {
    mask |= 1U << static_cast<std::uint32_t>(entry->to[i]);
  }
  return mask;
}

const char* site_state_name(SiteState s) noexcept {
  switch (s) {
    case SiteState::Unknown:
      return "UNKNOWN";
    case SiteState::Up:
      return "UP";
    case SiteState::Degraded:
      return "DEGRADED";
    case SiteState::Partitioned:
      return "PARTITIONED";
    case SiteState::Maintenance:
      return "MAINTENANCE";
    case SiteState::Draining:
      return "DRAINING";
    case SiteState::Down:
      return "DOWN";
    case SiteState::Fenced:
      return "FENCED";
  }
  return "INVALID";
}

bool site_state_from_name(std::string_view name, SiteState& out) noexcept {
  constexpr std::array<SiteState, 8> kAll{SiteState::Unknown,     SiteState::Up,
                                          SiteState::Degraded,    SiteState::Partitioned,
                                          SiteState::Maintenance, SiteState::Draining,
                                          SiteState::Down,        SiteState::Fenced};
  for (const SiteState s : kAll) {
    if (name == site_state_name(s)) {
      out = s;
      return true;
    }
  }
  return false;
}

bool site_accepts_new_reservations(SiteState s) noexcept {
  return s == SiteState::Up || s == SiteState::Degraded;
}

bool site_requires_degradation(SiteState s) noexcept {
  switch (s) {
    case SiteState::Partitioned:
    case SiteState::Down:
    case SiteState::Fenced:
    case SiteState::Maintenance:
      return true;
    default:
      return false;
  }
}

const char* path_state_name(PathState s) noexcept {
  switch (s) {
    case PathState::Unknown:
      return "UNKNOWN";
    case PathState::Up:
      return "UP";
    case PathState::Degraded:
      return "DEGRADED";
    case PathState::Down:
      return "DOWN";
    case PathState::Maintenance:
      return "MAINTENANCE";
    case PathState::Draining:
      return "DRAINING";
    case PathState::Fenced:
      return "FENCED";
  }
  return "INVALID";
}

bool path_state_from_name(std::string_view name, PathState& s) noexcept {
  constexpr std::array<PathState, 7> kAll{PathState::Unknown,     PathState::Up,
                                          PathState::Degraded,    PathState::Down,
                                          PathState::Maintenance, PathState::Draining,
                                          PathState::Fenced};
  for (const PathState state : kAll) {
    if (name == path_state_name(state)) {
      s = state;
      return true;
    }
  }
  return false;
}

bool path_accepts_new_reservations(PathState s) noexcept {
  return s == PathState::Up || s == PathState::Degraded;
}

bool path_requires_degradation(PathState s) noexcept {
  switch (s) {
    case PathState::Down:
    case PathState::Fenced:
    case PathState::Maintenance:
      return true;
    default:
      return false;
  }
}

const char* verification_state_name(VerificationState s) noexcept {
  switch (s) {
    case VerificationState::Unverified:
      return "UNVERIFIED";
    case VerificationState::Verified:
      return "VERIFIED";
    case VerificationState::Failed:
      return "FAILED";
    case VerificationState::Indeterminate:
      return "INDETERMINATE";
  }
  return "INVALID";
}

const char* provenance_name(Provenance p) noexcept {
  switch (p) {
    case Provenance::Live:
      return "LIVE";
    case Provenance::RecoveredFromSnapshot:
      return "RECOVERED_FROM_SNAPSHOT";
    case Provenance::RecoveredFromLog:
      return "RECOVERED_FROM_LOG";
    case Provenance::PartitionRecovery:
      return "PARTITION_RECOVERY";
    case Provenance::OperatorReconcile:
      return "OPERATOR_RECONCILE";
    case Provenance::AmbiguousCommit:
      return "AMBIGUOUS_COMMIT";
    case Provenance::FencedIncarnation:
      return "FENCED_INCARNATION";
  }
  return "INVALID";
}

bool provenance_is_historical(Provenance p) noexcept { return p != Provenance::Live; }

}  // namespace isf
