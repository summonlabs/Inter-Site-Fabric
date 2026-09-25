// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "isf/policy.hpp"

#include "isf/digest.hpp"
#include "isf/wire.hpp"

#include <string>

namespace isf {

Status Policy::validate() const {
  if (generation.is_nil()) {
    return Status::Invalid;
  }
  if (protected_floor_bps > 10000U) {
    return Status::Invalid;
  }
  if (min_free_bps > 10000U) {
    return Status::Invalid;
  }
  if (max_oversubscription_bps > kMaxOversubscriptionBps) {
    return Status::LimitExceeded;
  }
  if (max_srd_concentration_bps > 10000U) {
    return Status::Invalid;
  }
  if (max_lease_duration_ms == 0 || max_lease_duration_ms > kMaxLeaseDurationMs) {
    return Status::LimitExceeded;
  }
  if (max_grants_per_path == 0 || max_grants_per_path > kMaxGrantsPerPathLimit) {
    return Status::LimitExceeded;
  }
  if (max_grants_per_site < max_grants_per_path || max_grants_per_site > (1U << 24)) {
    return Status::LimitExceeded;
  }
  if (site_lease_timeout_ms < kMinSiteLeaseTimeoutMs || site_lease_timeout_ms > kMaxSiteLeaseTimeoutMs) {
    return Status::LimitExceeded;
  }
  if (allow_partition_optimistic_recovery && !auto_reconcile_on_restart) {
    // Optimistic partition recovery without restart reconciliation is a
    // contradiction: refuse to install a policy that says both.
    return Status::Conflicting;
  }
  return Status::Ok;
}

Policy Policy::conservative_default() {
  Policy policy;
  policy.id = PolicyId::from_seed(0x15F0000000000001ULL, 0);
  policy.generation = Generation{1};
  policy.protected_floor_units = 0;
  policy.protected_floor_bps = 1000;  // 10% of usable, kept out of general allocation
  policy.min_free_units = 0;
  policy.min_free_bps = 0;
  policy.max_oversubscription_bps = 0;
  policy.max_lease_duration_ms = 3600000;
  policy.max_grants_per_path = 1024;
  policy.max_grants_per_site = 4096;
  policy.max_srd_concentration_bps = 10000;
  policy.allow_degraded_activation = false;
  policy.allow_partition_optimistic_recovery = false;
  policy.require_verification_for_active = false;
  policy.auto_reconcile_on_restart = false;
  policy.site_lease_timeout_ms = 30000;
  return policy;
}

std::string Policy::to_string() const {
  std::string out = "policy generation=";
  out += generation.to_string();
  out += " protected=";
  out += std::to_string(protected_floor_units);
  out += "+";
  out += std::to_string(protected_floor_bps);
  out += "bps min_free=";
  out += std::to_string(min_free_units);
  out += "+";
  out += std::to_string(min_free_bps);
  out += "bps max_oversubscription=";
  out += std::to_string(max_oversubscription_bps);
  out += "bps srd_concentration=";
  out += std::to_string(max_srd_concentration_bps);
  out += "bps";
  return out;
}

std::string policy_digest_hex(const Policy& policy) {
  Writer writer;
  writer.id128(policy.id.raw());
  writer.generation(policy.generation);
  writer.u64(policy.protected_floor_units);
  writer.u32(policy.protected_floor_bps);
  writer.u64(policy.min_free_units);
  writer.u32(policy.min_free_bps);
  writer.u32(policy.max_oversubscription_bps);
  writer.u64(policy.max_lease_duration_ms);
  writer.u32(policy.max_grants_per_path);
  writer.u32(policy.max_grants_per_site);
  writer.u32(policy.max_srd_concentration_bps);
  writer.boolean(policy.allow_degraded_activation);
  writer.boolean(policy.allow_partition_optimistic_recovery);
  writer.boolean(policy.require_verification_for_active);
  writer.boolean(policy.auto_reconcile_on_restart);
  writer.u64(policy.site_lease_timeout_ms);
  return Digest256::of(writer.span()).to_hex();
}

}  // namespace isf
