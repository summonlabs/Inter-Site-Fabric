// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Capacity accounting. The ledger is always *derived* from authoritative
// inputs (the capacity attestation for a path, the live grant set, policy, and
// maintenance state); it is never maintained as an independently mutated
// counter that could drift. That makes the closure identity structural and
// checkable after every mutation.

#ifndef ISF_CAPACITY_HPP
#define ISF_CAPACITY_HPP

#include "isf/checked.hpp"
#include "isf/status.hpp"

#include <cstdint>
#include <string>

namespace isf {

/// How a path's authoritative capacity is currently classified. The classes are
/// disjoint and their sum plus free equals the authoritative usable total (plus
/// any explicitly authorised oversubscription).
enum class CapacityClass : std::uint8_t {
  Free = 0,        ///< allocatable right now
  Reserved,        ///< held by grants that are reserved but not yet active
  Committed,       ///< held by grants that are active or degraded
  Protected,       ///< headroom policy keeps out of general allocation
  Unavailable,     ///< removed by maintenance, drain, or failure
};

[[nodiscard]] const char* capacity_class_name(CapacityClass c) noexcept;

/// The derived capacity ledger for one path.
///
/// The classes are disjoint and the closure identity is structural:
///
///   free + committed + withdrawing + reserved + protected_headroom + unavailable
///     == authoritative_usable + oversubscribed
///
/// where
///   committed    grants in ACTIVE or DEGRADED: authorised obligations in force
///   withdrawing  grants in WITHDRAWING: no longer authorised, but the authority
///                has not yet confirmed the holder stopped, so the capacity is
///                retained and is never reallocated
///   reserved     grants in RESERVED
///   protected_headroom  the part of the policy floor not yet taken by protected
///                obligations. Protected grants are counted in committed and
///                reserved, so reporting the whole floor here would double
///                count them.
///   unavailable  capacity removed by maintenance, drain, or failure
///   free         the allocatable remainder, never negative
///   oversubscribed      the derived shortfall when obligations plus the floor
///                       plus unavailable exceed the authoritative basis
///
/// oversubscribed is a report, not a permission. It becomes non-zero only when
/// the basis shrinks (an attestation, a path state change) or the policy floor
/// rises; the allocation path never creates it. A live oversubscription
/// authority raises the allocatable ceiling for general capacity only, and
/// protected obligations are never oversubscribed under any circumstances.
struct CapacityLedger {
  Amount authoritative_usable{0};
  Amount committed{0};
  Amount withdrawing{0};
  Amount reserved{0};
  Amount protected_headroom{0};
  Amount unavailable{0};
  Amount free{0};
  /// Headroom a new grant may actually consume right now. This is `free` minus
  /// capacity held by grants that are withdrawing: that capacity is no longer
  /// authorised, but it must not be reallocated until the holder has released
  /// it, so it is reported but never handed out.
  Amount allocatable{0};
  Amount reclaimable{0};
  Amount oversubscribed{0};
  /// Additional capacity the authority is currently permitted to allocate
  /// beyond the authoritative basis, from a live oversubscription authority.
  Amount authorized_extension{0};

  /// committed + withdrawing + reserved, checked.
  [[nodiscard]] Expected<Amount> allocated() const;

  /// authoritative_usable + authorized_extension, checked.
  [[nodiscard]] Expected<Amount> basis() const;

  /// Verify the accounting closure identity and the structural relations
  /// reclaimable <= committed + withdrawing + reserved.
  [[nodiscard]] Status verify_closure() const;

  /// Human readable one-line summary.
  [[nodiscard]] std::string to_string() const;
};

/// Compute a basis-point fraction of an amount without overflowing. Saturates at
/// Amount max, which is the conservative direction for headroom floors: more is
/// reserved, less is allocatable.
[[nodiscard]] Amount fraction_bps(Amount value, std::uint32_t basis_points) noexcept;

/// Additional capacity an oversubscription authority permits beyond the
/// authoritative basis. The ratio is expressed as a ceiling multiplier in basis
/// points, so 10000 means "no oversubscription" and 15000 permits allocating up
/// to 1.5 times the authoritative usable capacity.
[[nodiscard]] Amount oversubscription_extension(Amount usable,
                                                std::uint32_t ratio_bps) noexcept;

/// Compute the larger of two amounts.
[[nodiscard]] constexpr Amount max_amount(Amount a, Amount b) noexcept { return a > b ? a : b; }

}  // namespace isf

#endif  // ISF_CAPACITY_HPP
