// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Lifecycle state machines. Transitions are explicit and total: every
// (from, to) pair has a defined answer, so an invalid transition is reported as
// Status::InvalidTransition rather than being silently accepted.

#ifndef ISF_LIFECYCLE_HPP
#define ISF_LIFECYCLE_HPP

#include <cstdint>
#include <string>
#include <string_view>

namespace isf {

/// Grant lifecycle.
///
///  proposed -> eligible -> reserved -> active -> degraded -> withdrawing -> retired
/// with refused/cancelled/expired as additional terminal outcomes. A grant that
/// is not in a capacity holding state consumes no authoritative capacity.
enum class GrantState : std::uint8_t {
  Proposed = 0,
  Eligible,
  Reserved,
  Active,
  Degraded,
  Withdrawing,
  Retired,
  Refused,
  Cancelled,
  Expired,
};

[[nodiscard]] const char* grant_state_name(GrantState s) noexcept;
[[nodiscard]] bool grant_state_from_name(std::string_view name, GrantState& out) noexcept;

/// True for Retired, Refused, Cancelled, Expired.
[[nodiscard]] bool is_terminal(GrantState s) noexcept;

/// True when the state holds authoritative capacity. Reserved holds the reserved
/// bucket, Active and Degraded hold the committed bucket, and Withdrawing keeps
/// holding the committed bucket until the grant reaches Retired. Releasing
/// capacity before Retired would risk overcommit.
[[nodiscard]] bool holds_capacity(GrantState s) noexcept;

/// True when the held capacity could be reclaimed by an operator action.
[[nodiscard]] bool is_reclaimable(GrantState s) noexcept;

/// True when the state represents an obligation in force.
[[nodiscard]] bool is_live_obligation(GrantState s) noexcept;

/// True when the transition from -> to is legal.
[[nodiscard]] bool can_transition(GrantState from, GrantState to) noexcept;

/// Legal successor states of a state, in canonical order, as a bit mask over the
/// enumerator values. Used by tests and by the CLI to explain refusals.
[[nodiscard]] std::uint32_t successor_mask(GrantState s) noexcept;

/// Site lifecycle as the authority sees it.
enum class SiteState : std::uint8_t {
  Unknown = 0,
  Up,
  Degraded,
  Partitioned,
  Maintenance,
  Draining,
  Down,
  Fenced,
};

[[nodiscard]] const char* site_state_name(SiteState s) noexcept;
[[nodiscard]] bool site_state_from_name(std::string_view name, SiteState& out) noexcept;

/// True when the authority will accept new reservations for this site.
[[nodiscard]] bool site_accepts_new_reservations(SiteState s) noexcept;

/// True when existing obligations of this site must be conservatively degraded.
[[nodiscard]] bool site_requires_degradation(SiteState s) noexcept;

/// Inter-site path lifecycle.
enum class PathState : std::uint8_t {
  Unknown = 0,
  Up,
  Degraded,
  Down,
  Maintenance,
  Draining,
  Fenced,
};

[[nodiscard]] const char* path_state_name(PathState s) noexcept;
[[nodiscard]] bool path_state_from_name(std::string_view name, PathState& s) noexcept;
[[nodiscard]] bool path_accepts_new_reservations(PathState s) noexcept;
[[nodiscard]] bool path_requires_degradation(PathState s) noexcept;

/// Result of independently verifying connectivity for a grant. Acknowledgement
/// by the holder is *not* verification and never sets this to Verified.
enum class VerificationState : std::uint8_t {
  Unverified = 0,
  Verified,
  Failed,
  Indeterminate,
};

[[nodiscard]] const char* verification_state_name(VerificationState s) noexcept;

/// Where a record came from. Recovered records are historical: they describe
/// what a previous incarnation believed, not what is true now.
enum class Provenance : std::uint8_t {
  Live = 0,
  RecoveredFromSnapshot,
  RecoveredFromLog,
  PartitionRecovery,
  OperatorReconcile,
  AmbiguousCommit,
  FencedIncarnation,
};

[[nodiscard]] const char* provenance_name(Provenance p) noexcept;
[[nodiscard]] bool provenance_is_historical(Provenance p) noexcept;

}  // namespace isf

#endif  // ISF_LIFECYCLE_HPP
