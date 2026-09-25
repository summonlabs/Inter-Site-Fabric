// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Fabric policy. Policy is versioned and generation bound: every grant records
// the policy generation it was evaluated against, and a policy change
// invalidates grants whose binding no longer matches.

#ifndef ISF_POLICY_HPP
#define ISF_POLICY_HPP

#include "isf/checked.hpp"
#include "isf/ids.hpp"
#include "isf/status.hpp"

#include <cstdint>
#include <string>

namespace isf {

/// Hard limits applied while validating a policy document.
inline constexpr std::uint32_t kMaxOversubscriptionBps = 100000;   ///< 10x
inline constexpr std::uint64_t kMaxLeaseDurationMs = 30ULL * 24ULL * 60ULL * 60ULL * 1000ULL;
inline constexpr std::uint32_t kMaxGrantsPerPathLimit = 1U << 20;
inline constexpr std::uint64_t kMinSiteLeaseTimeoutMs = 100;
inline constexpr std::uint64_t kMaxSiteLeaseTimeoutMs = 60ULL * 60ULL * 1000ULL;

/// The full policy document that governs capacity authority decisions.
struct Policy {
  PolicyId id{};
  Generation generation{};

  /// Headroom kept out of general allocation on every path. The effective floor
  /// is max(protected_floor_units, protected_floor_bps of usable capacity).
  Amount protected_floor_units{0};
  std::uint32_t protected_floor_bps{0};

  /// Minimum free headroom that must remain after any allocation.
  Amount min_free_units{0};
  std::uint32_t min_free_bps{0};

  /// Ceiling on authorised oversubscription. Zero forbids oversubscription
  /// entirely; any non-zero value additionally requires a live, generation
  /// matched OversubscriptionAuthority record.
  std::uint32_t max_oversubscription_bps{0};

  /// Longest lease the authority will issue.
  std::uint64_t max_lease_duration_ms{3600000};

  std::uint32_t max_grants_per_path{1024};
  std::uint32_t max_grants_per_site{4096};

  /// Maximum share of a shared-risk domain's usable capacity that may be
  /// committed at once. 10000 means no concentration limit.
  std::uint32_t max_srd_concentration_bps{10000};

  /// Whether a grant may become Active while the path is Degraded.
  bool allow_degraded_activation{false};

  /// Whether a partitioned site's reservations survive partition recovery
  /// without reconciliation. Default false: recovery is conservative.
  bool allow_partition_optimistic_recovery{false};

  /// Whether Active requires an independent verification record.
  bool require_verification_for_active{false};

  /// Whether grants recovered from a previous incarnation may be resumed
  /// automatically. Default false: recovered dynamic evidence is historical.
  bool auto_reconcile_on_restart{false};

  /// How long a site may go without a heartbeat before it is degraded.
  std::uint64_t site_lease_timeout_ms{30000};

  /// Structural validation. Returns Status::Invalid with a specific reason.
  [[nodiscard]] Status validate() const;

  /// A conservative default policy: no oversubscription, hard protected floor
  /// of zero units, 10% protected headroom, no optimistic recovery.
  [[nodiscard]] static Policy conservative_default();

  [[nodiscard]] std::string to_string() const;
};

/// Canonical encoding of a policy (used by the store and the wire protocol).
[[nodiscard]] std::string policy_digest_hex(const Policy& policy);

}  // namespace isf

#endif  // ISF_POLICY_HPP
