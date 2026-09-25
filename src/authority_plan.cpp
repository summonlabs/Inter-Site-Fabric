// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Mutation planning. Every plan_* method computes post-images from current
// authoritative state without modifying it, so a caller can durably record the
// intent before anything takes effect.

#include "isf/authority.hpp"

#include "isf/checked.hpp"

#include <algorithm>
#include <string>
#include <vector>

namespace isf {
namespace {

constexpr std::size_t kMaxNameLength = 128;
constexpr std::size_t kMaxReasonText = 512;
/// A site that has missed three consecutive heartbeat windows is taken down.
constexpr std::uint64_t kHeartbeatDownMultiplier = 3;

[[nodiscard]] std::string bounded(std::string text) {
  if (text.size() > kMaxReasonText) {
    text.resize(kMaxReasonText);
  }
  return text;
}

[[nodiscard]] bool valid_name(const std::string& name) {
  return !name.empty() && name.size() <= kMaxNameLength;
}

[[nodiscard]] bool holding_bucket_committed(GrantState s) {
  return s == GrantState::Active || s == GrantState::Degraded || s == GrantState::Withdrawing;
}

[[nodiscard]] bool holding_bucket_reserved(GrantState s) { return s == GrantState::Reserved; }

}  // namespace

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

MutationResult Authority::plan_install_policy(const Policy& policy, PrincipalId principal,
                                              ArbSeq arb) {
  const Status valid = policy.validate();
  if (valid != Status::Ok) {
    return Outcome(valid, "policy document failed structural validation");
  }
  if (policy.generation.value <= config_.policy.generation.value) {
    return Outcome(Status::Stale, "policy generation must strictly increase; got " +
                                      policy.generation.to_string() + " after " +
                                      config_.policy.generation.to_string());
  }
  Mutation mutation;
  mutation.arbitration = arb;
  mutation.changes.push_back(change_for(policy));
  for (const auto& entry : paths_) {
    rebalance_path(mutation.changes, entry.second, policy, /*now_ms=*/0,
                   "policy generation changed", /*rebind_policy=*/true,
                   /*rebind_path_capacity=*/false);
  }
  mutation.summary = "install policy generation " + policy.generation.to_string() + " by " +
                     (principal.is_nil() ? std::string("<anonymous>") : principal.to_string());
  return mutation;
}

MutationResult Authority::plan_bump_epoch(Epoch epoch, PrincipalId principal, ArbSeq arb) {
  if (epoch.value <= config_.epoch.value) {
    return Outcome(Status::Stale, "epoch must strictly increase");
  }
  Mutation mutation;
  mutation.arbitration = arb;
  mutation.changes.push_back(change_for_epoch(epoch));
  // Every live grant is bound to the superseded epoch. Dependency invalidation
  // is explicit: each one moves to Withdrawing, which still holds capacity, so
  // no capacity is silently freed by an epoch change.
  const std::string reason = "authority epoch advanced to " + epoch.to_string();
  for (const auto& entry : grants_) {
    const GrantRecord& grant = entry.second;
    if (!holds_capacity(grant.state) || grant.state == GrantState::Withdrawing) {
      continue;
    }
    GrantRecord updated = grant;
    updated.state = GrantState::Withdrawing;
    updated.reason = bounded(reason);
    mutation.changes.push_back(change_for(updated, false));
  }
  mutation.summary = "bump epoch to " + epoch.to_string() + " by " +
                     (principal.is_nil() ? std::string("<anonymous>") : principal.to_string());
  return mutation;
}

void Authority::rebalance_path(std::vector<StateChange>& out, const PathRecord& path,
                               const Policy& policy, std::uint64_t now_ms, const std::string& reason,
                               bool rebind_policy, bool rebind_path_capacity) const {
  const Amount basis = path.authoritative_usable > path.unavailable
                           ? path.authoritative_usable - path.unavailable
                           : 0;
  const Amount floor_amount =
      max_amount(policy.protected_floor_units,
                 fraction_bps(path.authoritative_usable, policy.protected_floor_bps));
  const Amount effective_floor = floor_amount > basis ? basis : floor_amount;
  const Amount wanted_free =
      max_amount(policy.min_free_units,
                 fraction_bps(path.authoritative_usable, policy.min_free_bps));
  const Amount effective_min_free = wanted_free > basis ? basis : wanted_free;

  std::uint32_t oversub_bps = 0;
  for (const auto& entry : oversubscriptions_) {
    const OversubscriptionAuthority& candidate = entry.second;
    if (!(candidate.path == path.id) || candidate.ratio_bps <= 10000) {
      continue;
    }
    if (candidate.epoch.value != config_.epoch.value ||
        candidate.policy_generation != policy.generation ||
        candidate.path_generation != path.generation ||
        candidate.capacity_generation != path.capacity_generation) {
      continue;
    }
    if (now_ms != 0 && !candidate.is_live_at(now_ms)) {
      continue;
    }
    oversub_bps = std::max(oversub_bps, candidate.ratio_bps);
  }
  oversub_bps = std::min(oversub_bps, policy.max_oversubscription_bps);

  const Amount ceiling = saturating_add(
      path.authoritative_usable, oversubscription_extension(path.authoritative_usable, oversub_bps));
  const Amount available = ceiling > path.unavailable ? ceiling - path.unavailable : 0;
  Amount guard = saturating_add(effective_floor, effective_min_free);
  if (guard > available) {
    guard = available;
  }
  const Amount general_ceiling = available > guard ? available - guard : 0;

  // Collect the path's holding grants ordered by arbitration sequence. The
  // order makes the outcome a deterministic function of the request order, and
  // protected obligations are withdrawn last.
  std::vector<GrantRecord> holding;
  for (const auto& entry : grants_) {
    const GrantRecord& grant = entry.second;
    if (!(grant.binding.path == path.id) || !holds_capacity(grant.state)) {
      continue;
    }
    holding.push_back(grant);
  }
  std::sort(holding.begin(), holding.end(), [](const GrantRecord& a, const GrantRecord& b) {
    if (a.arbitration.value != b.arbitration.value) {
      return a.arbitration.value < b.arbitration.value;
    }
    return a.id.raw() < b.id.raw();
  });

  Amount authorized_general = 0;
  Amount authorized_protected = 0;
  for (const auto& grant : holding) {
    if (grant.state == GrantState::Withdrawing) {
      continue;
    }
    if (grant.grant_class == GrantClass::Protected) {
      authorized_protected = saturating_add(authorized_protected, grant.amount);
    } else {
      authorized_general = saturating_add(authorized_general, grant.amount);
    }
  }

  const auto withdraw_to_fit = [&](Amount& remaining, Amount limit, GrantClass klass) {
    for (auto it = holding.rbegin(); it != holding.rend(); ++it) {
      if (remaining <= limit) {
        return;
      }
      if (it->grant_class != klass || it->state == GrantState::Withdrawing) {
        continue;
      }
      GrantRecord updated = *it;
      updated.state = GrantState::Withdrawing;
      updated.reason = bounded(reason);
      updated.updated_at_ms = now_ms;
      out.push_back(change_for(updated, false));
      remaining = remaining > it->amount ? remaining - it->amount : 0;
      it->state = GrantState::Withdrawing;
    }
  };

  withdraw_to_fit(authorized_protected, effective_floor, GrantClass::Protected);
  withdraw_to_fit(authorized_general, general_ceiling, GrantClass::General);

  if (!rebind_policy && !rebind_path_capacity) {
    return;
  }
  for (auto& grant : holding) {
    if (!(grant.state == GrantState::Reserved || grant.state == GrantState::Active ||
          grant.state == GrantState::Degraded)) {
      continue;
    }
    GrantRecord updated = grant;
    bool touched = false;
    if (rebind_policy && !(updated.binding.policy_generation == policy.generation)) {
      updated.binding.policy_generation = policy.generation;
      touched = true;
    }
    if (rebind_path_capacity) {
      if (!(updated.binding.path_generation == path.generation)) {
        updated.binding.path_generation = path.generation;
        touched = true;
      }
      if (!(updated.binding.capacity_generation == path.capacity_generation)) {
        updated.binding.capacity_generation = path.capacity_generation;
        touched = true;
      }
    }
    if (touched) {
      updated.updated_at_ms = now_ms;
      updated.reason = bounded(reason);
      out.push_back(change_for(updated, false));
    }
  }
}

// ---------------------------------------------------------------------------
// Sites
// ---------------------------------------------------------------------------

MutationResult Authority::plan_register_site(const SiteRegistration& registration, ArbSeq arb) {
  const SiteDescriptor& descriptor = registration.descriptor;
  if (descriptor.id.is_nil()) {
    return Outcome(Status::Invalid, "site identity must not be nil");
  }
  if (!valid_name(descriptor.name)) {
    return Outcome(Status::Invalid, "site name must be 1..128 bytes");
  }
  if (registration.incarnation.is_nil()) {
    return Outcome(Status::Invalid, "site incarnation must not be nil");
  }
  if (registration.epoch.value != config_.epoch.value) {
    return Outcome(Status::Stale, "registration carries a superseded authority epoch");
  }

  Mutation mutation;
  mutation.arbitration = arb;

  const auto existing = sites_.find(descriptor.id.raw());
  if (existing == sites_.end()) {
    if (sites_.size() >= config_.max_sites) {
      return Outcome(Status::LimitExceeded, "site table is full");
    }
    SiteRecord record;
    record.id = descriptor.id;
    record.name = descriptor.name;
    record.incarnation = registration.incarnation;
    record.generation = Generation{1};
    record.epoch = registration.epoch;
    record.state = SiteState::Up;
    record.advertised_capacity = descriptor.advertised_capacity;
    record.registered_at_ms = registration.now_ms;
    record.last_heartbeat_ms = registration.now_ms;
    record.provenance = Provenance::Live;
    mutation.changes.push_back(change_for(record));
    mutation.summary = "register site " + descriptor.id.to_string() + " generation 1";
    return mutation;
  }

  const SiteRecord& current = existing->second;
  if (current.state == SiteState::Fenced) {
    return Outcome(Status::Fenced,
                   "site is fenced; an operator must clear the fence before re-registration");
  }
  if (registration.epoch.value < current.epoch.value) {
    return Outcome(Status::Stale, "registration carries an older authority epoch than the site");
  }

  if (registration.incarnation == current.incarnation) {
    SiteRecord updated = current;
    updated.name = descriptor.name;
    updated.advertised_capacity = descriptor.advertised_capacity;
    updated.last_heartbeat_ms = registration.now_ms;
    updated.missed_heartbeats = 0;
    if (updated.state == SiteState::Unknown) {
      updated.state = SiteState::Up;
    }
    mutation.changes.push_back(change_for(updated));
    mutation.summary = "re-register site " + descriptor.id.to_string() + " incarnation unchanged";
    return mutation;
  }

  // A different incarnation supersedes the previous one. The old incarnation is
  // fenced: its live grants stop advancing, keep holding capacity, and are
  // marked historical so that recovered dynamic evidence is not treated as
  // fresh.
  const std::string reason = "site incarnation superseded";
  for (const auto& entry : grants_) {
    const GrantRecord& grant = entry.second;
    if (!(grant.binding.holder == descriptor.id) || !holds_capacity(grant.state)) {
      continue;
    }
    if (grant.state == GrantState::Withdrawing) {
      continue;
    }
    GrantRecord updated = grant;
    updated.state = GrantState::Withdrawing;
    updated.reason = bounded(reason);
    updated.updated_at_ms = registration.now_ms;
    updated.historical = true;
    updated.provenance = Provenance::FencedIncarnation;
    updated.verification = VerificationState::Unverified;
    mutation.changes.push_back(change_for(updated, false));
  }

  SiteRecord updated = current;
  updated.name = descriptor.name;
  updated.incarnation = registration.incarnation;
  updated.generation = current.generation.next();
  updated.epoch = registration.epoch;
  updated.state = SiteState::Up;
  updated.advertised_capacity = descriptor.advertised_capacity;
  updated.registered_at_ms = registration.now_ms;
  updated.last_heartbeat_ms = registration.now_ms;
  updated.missed_heartbeats = 0;
  updated.fence_reason.clear();
  updated.provenance = Provenance::Live;
  mutation.changes.push_back(change_for(updated));
  mutation.summary = "register site " + descriptor.id.to_string() + " generation " +
                     updated.generation.to_string() + " (new incarnation)";
  return mutation;
}

MutationResult Authority::plan_heartbeat(const SiteHeartbeat& heartbeat, ArbSeq arb) {
  const auto it = sites_.find(heartbeat.id.raw());
  if (it == sites_.end()) {
    return Outcome(Status::NotFound, "heartbeat from an unregistered site");
  }
  const SiteRecord& current = it->second;
  if (!(heartbeat.incarnation == current.incarnation)) {
    return Outcome(Status::Fenced, "heartbeat from a superseded site incarnation");
  }
  if (heartbeat.epoch.value != config_.epoch.value) {
    return Outcome(Status::Stale, "heartbeat carries a superseded authority epoch");
  }
  if (current.state == SiteState::Fenced) {
    return Outcome(Status::Fenced, "site is fenced");
  }
  if (!heartbeat.generation.is_nil() && !(heartbeat.generation == current.generation)) {
    return Outcome(Status::Stale, "heartbeat carries a superseded site generation");
  }
  SiteRecord updated = current;
  updated.last_heartbeat_ms = heartbeat.now_ms;
  updated.missed_heartbeats = 0;
  updated.advertised_capacity = heartbeat.advertised_capacity;
  if (updated.state == SiteState::Up || updated.state == SiteState::Degraded ||
      updated.state == SiteState::Unknown) {
    updated.state = SiteState::Up;
  }
  Mutation mutation;
  mutation.arbitration = arb;
  mutation.changes.push_back(change_for(updated));
  mutation.summary = "heartbeat site " + heartbeat.id.to_string();
  return mutation;
}

MutationResult Authority::plan_set_site_state(SiteId site, SiteState state,
                                              const std::string& reason, std::uint64_t now_ms,
                                              ArbSeq arb) {
  const auto it = sites_.find(site.raw());
  if (it == sites_.end()) {
    return Outcome(Status::NotFound, "no such site");
  }
  Mutation mutation;
  mutation.arbitration = arb;
  SiteRecord updated = it->second;
  if (state == SiteState::Fenced) {
    updated.fence_reason = bounded(reason.empty() ? std::string("operator fence") : reason);
  } else if (updated.state == SiteState::Fenced) {
    updated.fence_reason.clear();
  }
  updated.state = state;
  mutation.changes.push_back(change_for(updated));
  if (site_requires_degradation(state)) {
    append_downgrades(mutation.changes,
                      reason.empty() ? ("site moved to " + std::string(site_state_name(state)))
                                     : reason,
                      site, std::nullopt, now_ms);
  }
  mutation.summary = "set site " + site.to_string() + " state " + site_state_name(state);
  return mutation;
}

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

MutationResult Authority::plan_register_path(const PathRegistration& registration, ArbSeq arb) {
  const PathDescriptor& descriptor = registration.descriptor;
  if (descriptor.id.is_nil()) {
    return Outcome(Status::Invalid, "path identity must not be nil");
  }
  if (!valid_name(descriptor.name)) {
    return Outcome(Status::Invalid, "path name must be 1..128 bytes");
  }
  if (descriptor.endpoint_a.is_nil() || descriptor.endpoint_b.is_nil()) {
    return Outcome(Status::Invalid, "both path endpoints must be identified");
  }
  if (descriptor.endpoint_a == descriptor.endpoint_b) {
    return Outcome(Status::Invalid, "a path must join two distinct sites");
  }
  if (sites_.find(descriptor.endpoint_a.raw()) == sites_.end() ||
      sites_.find(descriptor.endpoint_b.raw()) == sites_.end()) {
    return Outcome(Status::Incomplete, "both path endpoints must be registered sites");
  }

  Mutation mutation;
  mutation.arbitration = arb;

  DomainId domain = descriptor.shared_risk_domain;
  if (domain.is_nil()) {
    domain = DomainId::from_seed(0x15F0D0A1ULL, 0);
  }
  if (domains_.find(domain.raw()) == domains_.end()) {
    if (domains_.size() >= config_.max_domains) {
      return Outcome(Status::LimitExceeded, "shared risk domain table is full");
    }
    SharedRiskDomain record;
    record.id = domain;
    record.name = "domain-" + domain.to_string();
    record.description = "auto-created on path registration";
    mutation.changes.push_back([&] {
      StateChange change;
      change.kind = ObjectKind::Domain;
      change.key = domain.raw();
      Writer w;
      encode(w, record);
      change.image.assign(w.buffer().begin(), w.buffer().end());
      return change;
    }());
  }

  const auto existing = paths_.find(descriptor.id.raw());
  if (existing == paths_.end()) {
    if (paths_.size() >= config_.max_paths) {
      return Outcome(Status::LimitExceeded, "path table is full");
    }
    PathRecord record;
    record.id = descriptor.id;
    record.name = descriptor.name;
    record.edge = descriptor.edge.is_nil() ? EdgeId::from_seed(descriptor.id.raw().hi, descriptor.id.raw().lo)
                                           : descriptor.edge;
    record.shared_risk_domain = domain;
    record.endpoint_a = descriptor.endpoint_a;
    record.endpoint_b = descriptor.endpoint_b;
    record.generation = Generation{1};
    // No capacity attestation exists yet, so the authoritative capacity
    // generation is zero until one arrives. Nothing is allocatable until then.
    record.capacity_generation = Generation{0};
    record.state = registration.state;
    record.advertised = registration.advertised;
    record.observed = registration.observed;
    // Authoritative usable capacity starts at zero. Advertised and observed
    // numbers are recorded but nothing may be committed against them until an
    // attestation establishes the authoritative figure.
    record.authoritative_usable = 0;
    record.unavailable = 0;
    record.updated_at_ms = registration.now_ms;
    record.provenance = Provenance::Live;
    mutation.changes.push_back(change_for(record));
    mutation.summary = "register path " + descriptor.id.to_string() + " generation 1";
    return mutation;
  }

  const PathRecord& current = existing->second;
  if (registration.path_generation.value <= current.generation.value) {
    return Outcome(Status::Stale, "path generation must strictly increase");
  }
  PathRecord updated = current;
  updated.name = descriptor.name;
  updated.edge = descriptor.edge.is_nil() ? current.edge : descriptor.edge;
  updated.shared_risk_domain = domain;
  updated.endpoint_a = descriptor.endpoint_a;
  updated.endpoint_b = descriptor.endpoint_b;
  updated.generation = registration.path_generation;
  updated.state = registration.state;
  updated.advertised = registration.advertised;
  updated.observed = registration.observed;
  updated.updated_at_ms = registration.now_ms;
  updated.provenance = Provenance::Live;
  mutation.changes.push_back(change_for(updated));
  rebalance_path(mutation.changes, updated, config_.policy, registration.now_ms,
                 "path generation changed", /*rebind_policy=*/false,
                 /*rebind_path_capacity=*/true);
  mutation.summary = "register path " + descriptor.id.to_string() + " generation " +
                     updated.generation.to_string();
  return mutation;
}

MutationResult Authority::plan_set_path_state(PathId path, PathState state,
                                              const std::string& reason, std::uint64_t now_ms,
                                              ArbSeq arb) {
  const auto it = paths_.find(path.raw());
  if (it == paths_.end()) {
    return Outcome(Status::NotFound, "no such path");
  }
  Mutation mutation;
  mutation.arbitration = arb;
  PathRecord updated = it->second;
  updated.state = state;
  updated.updated_at_ms = now_ms;
  switch (state) {
    case PathState::Down:
    case PathState::Fenced:
    case PathState::Maintenance:
      updated.unavailable = updated.authoritative_usable;
      break;
    case PathState::Up:
    case PathState::Degraded:
    case PathState::Draining:
    case PathState::Unknown:
      updated.unavailable = 0;
      break;
  }
  mutation.changes.push_back(change_for(updated));
  if (state == PathState::Down || state == PathState::Fenced || state == PathState::Maintenance ||
      state == PathState::Draining) {
    append_downgrades(mutation.changes,
                      reason.empty() ? ("path moved to " + std::string(path_state_name(state)))
                                     : reason,
                      std::nullopt, path, now_ms);
  }
  if (state == PathState::Down || state == PathState::Fenced || state == PathState::Maintenance) {
    rebalance_path(mutation.changes, updated, config_.policy, now_ms, "path capacity withdrawn",
                   /*rebind_policy=*/false, /*rebind_path_capacity=*/false);
  }
  mutation.summary = "set path " + path.to_string() + " state " + path_state_name(state);
  return mutation;
}

MutationResult Authority::plan_attest_capacity(const CapacityAttestation& attestation, ArbSeq arb) {
  if (attestation.id.is_nil()) {
    return Outcome(Status::Invalid, "attestation identity must not be nil");
  }
  if (attestation.issuer.is_nil()) {
    return Outcome(Status::Unauthorized, "attestation must name the issuing incarnation");
  }
  if (attestation.principal.is_nil()) {
    return Outcome(Status::Unauthorized, "attestation must name the responsible principal");
  }
  if (attestation.evidence.is_zero()) {
    return Outcome(Status::Incomplete, "attestation must carry an evidence digest");
  }
  if (attestation.epoch.value != config_.epoch.value) {
    return Outcome(Status::Stale, "attestation carries a superseded authority epoch");
  }
  const auto it = paths_.find(attestation.path.raw());
  if (it == paths_.end()) {
    return Outcome(Status::NotFound, "no such path");
  }
  const PathRecord& current = it->second;
  if (!(attestation.path_generation == current.generation)) {
    return Outcome(Status::Stale, "attestation is bound to a superseded path generation");
  }
  if (attestation.capacity_generation.value <= current.capacity_generation.value) {
    return Outcome(Status::Stale, "capacity generation must strictly increase");
  }
  if (attestations_.size() >= config_.max_attestations) {
    return Outcome(Status::LimitExceeded, "attestation table is full");
  }

  Mutation mutation;
  mutation.arbitration = arb;
  PathRecord updated = current;
  updated.capacity_generation = attestation.capacity_generation;
  updated.advertised = attestation.advertised;
  updated.observed = attestation.observed;
  updated.authoritative_usable = attestation.usable;
  updated.updated_at_ms = attestation.observed_at_ms;
  updated.provenance = Provenance::Live;
  if (updated.unavailable > updated.authoritative_usable) {
    updated.unavailable = updated.authoritative_usable;
  }
  mutation.changes.push_back(change_for(attestation));
  mutation.changes.push_back(change_for(updated));
  rebalance_path(mutation.changes, updated, config_.policy, attestation.observed_at_ms,
                 "authoritative capacity changed", /*rebind_policy=*/false,
                 /*rebind_path_capacity=*/true);
  mutation.summary = "attest capacity for path " + attestation.path.to_string() + " usable=" +
                     std::to_string(attestation.usable);
  return mutation;
}

MutationResult Authority::plan_issue_oversubscription(const OversubscriptionAuthority& authority,
                                                      ArbSeq arb) {
  if (authority.id.is_nil()) {
    return Outcome(Status::Invalid, "oversubscription identity must not be nil");
  }
  if (authority.issuer.is_nil()) {
    return Outcome(Status::Unauthorized, "oversubscription authority must name its issuer");
  }
  if (authority.principal.is_nil()) {
    return Outcome(Status::Unauthorized, "oversubscription authority must name its principal");
  }
  if (authority.ratio_bps <= 10000) {
    return Outcome(Status::Invalid, "oversubscription ratio must exceed 1.0");
  }
  if (authority.ratio_bps > kMaxOversubscriptionBps) {
    return Outcome(Status::LimitExceeded, "oversubscription ratio exceeds the hard ceiling");
  }
  if (config_.policy.max_oversubscription_bps == 0) {
    return Outcome(Status::Refused, "policy forbids oversubscription entirely");
  }
  if (authority.ratio_bps > config_.policy.max_oversubscription_bps) {
    return Outcome(Status::Refused, "ratio exceeds the policy ceiling");
  }
  if (authority.epoch.value != config_.epoch.value) {
    return Outcome(Status::Stale, "oversubscription authority carries a superseded epoch");
  }
  if (!(authority.policy_generation == config_.policy.generation)) {
    return Outcome(Status::Stale, "oversubscription authority carries a superseded policy generation");
  }
  const auto it = paths_.find(authority.path.raw());
  if (it == paths_.end()) {
    return Outcome(Status::NotFound, "no such path");
  }
  if (!(authority.path_generation == it->second.generation)) {
    return Outcome(Status::Stale, "oversubscription authority carries a superseded path generation");
  }
  if (!(authority.capacity_generation == it->second.capacity_generation)) {
    return Outcome(Status::Stale,
                   "oversubscription authority carries a superseded capacity generation");
  }
  if (oversubscriptions_.size() >= config_.max_oversubscriptions) {
    return Outcome(Status::LimitExceeded, "oversubscription table is full");
  }
  Mutation mutation;
  mutation.arbitration = arb;
  mutation.changes.push_back(change_for(authority));
  mutation.summary = "issue oversubscription authority for path " + authority.path.to_string();
  return mutation;
}

// ---------------------------------------------------------------------------
// Grants
// ---------------------------------------------------------------------------

MutationResult Authority::plan_propose_grant(const GrantProposal& proposal, ArbSeq arb) {
  if (proposal.request.is_nil()) {
    return Outcome(Status::Invalid, "grant proposal must carry a request identity");
  }
  if (proposal.amount == 0) {
    return Outcome(Status::Invalid, "grant amount must be greater than zero");
  }
  if (proposal.duration_ms == 0 || proposal.duration_ms > config_.policy.max_lease_duration_ms) {
    return Outcome(Status::LimitExceeded, "requested lease duration is outside the policy window");
  }
  if (grants_.size() >= config_.max_grants) {
    return Outcome(Status::LimitExceeded, "grant table is full");
  }
  if (proposal.holder_incarnation.is_nil()) {
    return Outcome(Status::Invalid, "grant proposal must name the holder incarnation");
  }
  const auto request_it = request_index_.find(proposal.request.raw());
  if (request_it != request_index_.end()) {
    return Outcome(Status::Duplicate, "a grant already exists for this request identity");
  }
  const auto site_it = sites_.find(proposal.holder.raw());
  if (site_it == sites_.end()) {
    return Outcome(Status::NotFound, "no such site");
  }
  const SiteRecord& site = site_it->second;
  if (!(proposal.holder_incarnation == site.incarnation)) {
    return Outcome(Status::Fenced, "grant proposal names a superseded site incarnation");
  }
  if (!proposal.holder_generation.is_nil() && !(proposal.holder_generation == site.generation)) {
    return Outcome(Status::Stale, "grant proposal names a superseded site generation");
  }
  const auto path_it = paths_.find(proposal.path.raw());
  if (path_it == paths_.end()) {
    return Outcome(Status::NotFound, "no such path");
  }
  const PathRecord& path = path_it->second;
  if (!(path.endpoint_a == proposal.holder) && !(path.endpoint_b == proposal.holder)) {
    return Outcome(Status::Denied, "requesting site is not an endpoint of this path");
  }

  GrantRecord grant;
  grant.id = derive_grant_id(arb, proposal);
  if (grants_.find(grant.id.raw()) != grants_.end()) {
    return Outcome(Status::Duplicate, "derived grant identity already exists");
  }
  grant.request = proposal.request;
  grant.arbitration = arb;
  grant.binding.holder = proposal.holder;
  grant.binding.holder_incarnation = site.incarnation;
  grant.binding.holder_generation = site.generation;
  grant.binding.path = path.id;
  grant.binding.path_generation = path.generation;
  grant.binding.capacity_generation = path.capacity_generation;
  grant.binding.policy_generation = config_.policy.generation;
  grant.binding.epoch = config_.epoch;
  grant.binding.lease = proposal.lease.is_nil()
                            ? LeaseId::from_seed(arb.value ^ 0x1EA5EULL, proposal.request.raw().lo)
                            : proposal.lease;
  grant.grant_class = proposal.grant_class;
  grant.amount = proposal.amount;
  grant.state = GrantState::Proposed;
  grant.created_at_ms = proposal.now_ms;
  grant.updated_at_ms = proposal.now_ms;
  grant.expires_at_ms = proposal.now_ms + proposal.duration_ms;
  grant.reason = bounded(proposal.reason);
  grant.provenance = Provenance::Live;
  grant.verification = VerificationState::Unverified;

  Mutation mutation;
  mutation.arbitration = arb;
  mutation.changes.push_back(change_for(grant, false));
  mutation.summary = "propose grant " + grant.id.to_string() + " amount " +
                     std::to_string(grant.amount);
  return mutation;
}

MutationResult Authority::plan_evaluate_grant(const GrantOperation& op, ArbSeq arb) {
  const auto it = grants_.find(op.grant.raw());
  if (it == grants_.end()) {
    return Outcome(Status::NotFound, "no such grant");
  }
  const GrantRecord& grant = it->second;
  if (grant.state != GrantState::Proposed) {
    return Outcome(Status::InvalidTransition, "only a proposed grant can be evaluated");
  }
  const Status binding = check_binding(grant, op);
  if (binding != Status::Ok) {
    return Outcome(binding, "grant evaluation failed binding validation");
  }
  const SiteRecord& site = sites_.at(grant.binding.holder.raw());
  const PathRecord& path = paths_.at(grant.binding.path.raw());

  std::string refusal;
  if (!site_accepts_new_reservations(site.state)) {
    refusal = std::string("site is ") + site_state_name(site.state);
  } else if (!path_accepts_new_reservations(path.state)) {
    refusal = std::string("path is ") + path_state_name(path.state);
  } else {
    std::uint32_t per_path = 0;
    for (const auto& entry : grants_) {
      if (entry.second.binding.path == path.id && !is_terminal(entry.second.state)) {
        ++per_path;
      }
    }
    if (per_path >= config_.policy.max_grants_per_path) {
      refusal = "policy grant limit reached for this path";
    } else {
      std::uint32_t per_site = 0;
      for (const auto& entry : grants_) {
        if (entry.second.binding.holder == site.id && !is_terminal(entry.second.state)) {
          ++per_site;
        }
      }
      if (per_site >= config_.policy.max_grants_per_site) {
        refusal = "policy grant limit reached for this site";
      }
    }
  }

  Mutation mutation;
  mutation.arbitration = arb;
  GrantRecord updated = grant;
  updated.updated_at_ms = op.now_ms;
  if (refusal.empty()) {
    updated.state = GrantState::Eligible;
    mutation.summary = "grant " + grant.id.to_string() + " eligible";
  } else {
    updated.state = GrantState::Refused;
    updated.reason = bounded(refusal);
    mutation.summary = "grant " + grant.id.to_string() + " refused: " + refusal;
  }
  mutation.changes.push_back(change_for(updated, false));
  return mutation;
}

MutationResult Authority::plan_reserve_grant(const GrantOperation& op, ArbSeq arb) {
  const auto it = grants_.find(op.grant.raw());
  if (it == grants_.end()) {
    return Outcome(Status::NotFound, "no such grant");
  }
  const GrantRecord& grant = it->second;
  if (grant.state != GrantState::Eligible) {
    return Outcome(Status::InvalidTransition, "only an eligible grant can be reserved");
  }
  const Status binding = check_binding(grant, op);
  if (binding != Status::Ok) {
    return Outcome(binding, "grant reservation failed binding validation");
  }
  const SiteRecord& site = sites_.at(grant.binding.holder.raw());
  const PathRecord& path = paths_.at(grant.binding.path.raw());
  if (!site_accepts_new_reservations(site.state)) {
    return Outcome(Status::Refused, std::string("site is ") + site_state_name(site.state));
  }
  if (!path_accepts_new_reservations(path.state)) {
    return Outcome(Status::Refused, std::string("path is ") + path_state_name(path.state));
  }

  auto available = allocatable(path.id, grant.grant_class, op.now_ms);
  if (!available.ok()) {
    return Outcome(available.status(), "capacity could not be evaluated: " + available.detail());
  }
  if (available.value() < grant.amount) {
    return Outcome(Status::Exhausted, "requested " + std::to_string(grant.amount) +
                                          " but only " + std::to_string(available.value()) +
                                          " is allocatable on this path");
  }

  // Shared risk domain concentration.
  if (config_.policy.max_srd_concentration_bps < 10000 && !path.shared_risk_domain.is_nil()) {
    Amount domain_usable = 0;
    Amount domain_held = 0;
    for (const auto& entry : paths_) {
      if (!(entry.second.shared_risk_domain == path.shared_risk_domain)) {
        continue;
      }
      domain_usable = saturating_add(domain_usable, entry.second.authoritative_usable);
      const PathTotals totals = totals_for(entry.second.id);
      domain_held = saturating_add(domain_held, totals.committed);
      domain_held = saturating_add(domain_held, totals.reserved);
    }
    auto projected = checked_add(domain_held, grant.amount);
    if (!projected.ok()) {
      return Outcome(Status::LimitExceeded, "shared risk domain projection overflowed");
    }
    auto scaled = checked_mul(projected.value(), 10000);
    if (!scaled.ok()) {
      return Outcome(Status::LimitExceeded, "shared risk domain projection overflowed");
    }
    auto allowed = checked_mul(domain_usable, config_.policy.max_srd_concentration_bps);
    if (!allowed.ok()) {
      return Outcome(Status::LimitExceeded, "shared risk domain ceiling overflowed");
    }
    if (scaled.value() > allowed.value()) {
      return Outcome(Status::Refused,
                     "shared risk domain concentration limit would be exceeded");
    }
  }

  Mutation mutation;
  mutation.arbitration = arb;
  GrantRecord updated = grant;
  updated.state = GrantState::Reserved;
  updated.updated_at_ms = op.now_ms;
  updated.binding.holder_incarnation = site.incarnation;
  updated.binding.holder_generation = site.generation;
  updated.binding.path_generation = path.generation;
  updated.binding.capacity_generation = path.capacity_generation;
  updated.binding.policy_generation = config_.policy.generation;
  updated.binding.epoch = config_.epoch;
  mutation.changes.push_back(change_for(updated, false));
  mutation.summary = "reserve grant " + grant.id.to_string() + " amount " +
                     std::to_string(grant.amount);
  return mutation;
}

MutationResult Authority::plan_activate_grant(const GrantOperation& op, ArbSeq arb) {
  const auto it = grants_.find(op.grant.raw());
  if (it == grants_.end()) {
    return Outcome(Status::NotFound, "no such grant");
  }
  const GrantRecord& grant = it->second;
  if (grant.state != GrantState::Reserved) {
    return Outcome(Status::InvalidTransition, "only a reserved grant can be activated");
  }
  const Status binding = check_binding(grant, op);
  if (binding != Status::Ok) {
    return Outcome(binding, "grant activation failed binding validation");
  }
  const SiteRecord& site = sites_.at(grant.binding.holder.raw());
  const PathRecord& path = paths_.at(grant.binding.path.raw());
  if (!site_accepts_new_reservations(site.state)) {
    return Outcome(Status::Refused, std::string("site is ") + site_state_name(site.state));
  }
  if (path.state == PathState::Degraded && !config_.policy.allow_degraded_activation) {
    return Outcome(Status::Refused, "policy forbids activation while the path is degraded");
  }
  if (!path_accepts_new_reservations(path.state)) {
    return Outcome(Status::Refused, std::string("path is ") + path_state_name(path.state));
  }
  if (config_.policy.require_verification_for_active &&
      grant.verification != VerificationState::Verified) {
    return Outcome(Status::Incomplete,
                   "policy requires independent verification before activation");
  }

  Mutation mutation;
  mutation.arbitration = arb;
  GrantRecord updated = grant;
  updated.state = GrantState::Active;
  updated.updated_at_ms = op.now_ms;
  mutation.changes.push_back(change_for(updated, false));
  mutation.summary = "activate grant " + grant.id.to_string();
  return mutation;
}

MutationResult Authority::plan_degrade_grant(const GrantOperation& op, ArbSeq arb) {
  const auto it = grants_.find(op.grant.raw());
  if (it == grants_.end()) {
    return Outcome(Status::NotFound, "no such grant");
  }
  const GrantRecord& grant = it->second;
  if (grant.state != GrantState::Active) {
    return Outcome(Status::InvalidTransition, "only an active grant can be degraded");
  }
  const Status binding = check_binding(grant, op);
  if (binding != Status::Ok) {
    return Outcome(binding, "grant degradation failed binding validation");
  }
  Mutation mutation;
  mutation.arbitration = arb;
  GrantRecord updated = grant;
  updated.state = GrantState::Degraded;
  updated.updated_at_ms = op.now_ms;
  updated.reason = bounded(op.reason.empty() ? std::string("degraded") : op.reason);
  updated.verification = VerificationState::Unverified;
  mutation.changes.push_back(change_for(updated, false));
  mutation.summary = "degrade grant " + grant.id.to_string();
  return mutation;
}

MutationResult Authority::plan_withdraw_grant(const GrantOperation& op, ArbSeq arb) {
  const auto it = grants_.find(op.grant.raw());
  if (it == grants_.end()) {
    return Outcome(Status::NotFound, "no such grant");
  }
  const GrantRecord& grant = it->second;
  if (!(grant.state == GrantState::Reserved || grant.state == GrantState::Active ||
        grant.state == GrantState::Degraded)) {
    return Outcome(Status::InvalidTransition, "grant is not in a withdrawable state");
  }
  const Status binding = check_binding(grant, op);
  if (binding != Status::Ok) {
    return Outcome(binding, "grant withdrawal failed binding validation");
  }
  Mutation mutation;
  mutation.arbitration = arb;
  GrantRecord updated = grant;
  updated.state = GrantState::Withdrawing;
  updated.updated_at_ms = op.now_ms;
  updated.reason = bounded(op.reason.empty() ? std::string("withdrawing") : op.reason);
  mutation.changes.push_back(change_for(updated, false));
  mutation.summary = "withdraw grant " + grant.id.to_string();
  return mutation;
}

MutationResult Authority::plan_retire_grant(const GrantOperation& op, ArbSeq arb) {
  const auto it = grants_.find(op.grant.raw());
  if (it == grants_.end()) {
    return Outcome(Status::NotFound, "no such grant");
  }
  const GrantRecord& grant = it->second;
  if (grant.state != GrantState::Withdrawing) {
    return Outcome(Status::InvalidTransition, "only a withdrawing grant can be retired");
  }
  if (!op.actor.is_nil() && !(op.actor == grant.binding.holder)) {
    return Status::Denied;
  }
  if (!op.lease.is_nil() && !(op.lease == grant.binding.lease)) {
    return Status::Stale;
  }
  Mutation mutation;
  mutation.arbitration = arb;
  GrantRecord updated = grant;
  updated.state = GrantState::Retired;
  updated.updated_at_ms = op.now_ms;
  updated.reason = bounded(op.reason.empty() ? std::string("retired") : op.reason);
  updated.verification = VerificationState::Unverified;
  // Retiring releases capacity. The change is marked as releasing so that a
  // durable intent without a completion record is never applied blindly.
  mutation.changes.push_back(change_for(updated, true));
  mutation.summary = "retire grant " + grant.id.to_string();
  return mutation;
}

MutationResult Authority::plan_cancel_grant(const GrantOperation& op, ArbSeq arb) {
  const auto it = grants_.find(op.grant.raw());
  if (it == grants_.end()) {
    return Outcome(Status::NotFound, "no such grant");
  }
  const GrantRecord& grant = it->second;
  if (!can_transition(grant.state, GrantState::Cancelled)) {
    return Outcome(Status::InvalidTransition, "grant cannot be cancelled from its current state");
  }
  if (!op.actor.is_nil() && !(op.actor == grant.binding.holder)) {
    return Status::Denied;
  }
  if (!op.lease.is_nil() && !(op.lease == grant.binding.lease)) {
    return Status::Stale;
  }
  Mutation mutation;
  mutation.arbitration = arb;
  GrantRecord updated = grant;
  updated.state = GrantState::Cancelled;
  updated.updated_at_ms = op.now_ms;
  updated.reason = bounded(op.reason.empty() ? std::string("cancelled") : op.reason);
  const bool releases = holds_capacity(grant.state);
  mutation.changes.push_back(change_for(updated, releases));
  mutation.summary = "cancel grant " + grant.id.to_string();
  return mutation;
}

MutationResult Authority::plan_acknowledge_grant(const GrantAcknowledgement& ack, ArbSeq arb) {
  const auto it = grants_.find(ack.grant.raw());
  if (it == grants_.end()) {
    return Outcome(Status::NotFound, "no such grant");
  }
  const GrantRecord& grant = it->second;
  if (is_terminal(grant.state)) {
    return Outcome(Status::InvalidTransition, "a terminal grant cannot be acknowledged");
  }
  const auto site_it = sites_.find(grant.binding.holder.raw());
  if (site_it == sites_.end()) {
    return Outcome(Status::NotFound, "grant holder is not a registered site");
  }
  if (!ack.actor.is_nil() && !(ack.actor == grant.binding.holder)) {
    return Status::Denied;
  }
  if (!ack.actor_incarnation.is_nil() && !(ack.actor_incarnation == site_it->second.incarnation)) {
    return Status::Fenced;
  }
  if (ack.epoch.value != 0 && ack.epoch.value != config_.epoch.value) {
    return Status::Stale;
  }
  Mutation mutation;
  mutation.arbitration = arb;
  GrantRecord updated = grant;
  updated.acknowledged = true;
  updated.ack_count = grant.ack_count + 1;
  updated.updated_at_ms = ack.now_ms;
  // Acknowledgement is a claim by the holder. It deliberately does not change
  // the verification state: only an independent verification does that.
  mutation.changes.push_back(change_for(updated, false));
  mutation.summary = "acknowledge grant " + grant.id.to_string();
  return mutation;
}

MutationResult Authority::plan_verify_grant(const GrantVerification& verification, ArbSeq arb) {
  const auto it = grants_.find(verification.grant.raw());
  if (it == grants_.end()) {
    return Outcome(Status::NotFound, "no such grant");
  }
  if (verification.id.is_nil()) {
    return Outcome(Status::Invalid, "verification identity must not be nil");
  }
  if (verification.verifier.is_nil()) {
    return Outcome(Status::Unauthorized, "verification must name an independent verifier");
  }
  if (verification.result == VerificationState::Unverified) {
    return Outcome(Status::Invalid, "a verification record must carry a result");
  }
  if (verifications_.size() >= config_.max_verifications) {
    return Outcome(Status::LimitExceeded, "verification table is full");
  }
  const GrantRecord& grant = it->second;
  VerificationRecord record;
  record.id = verification.id;
  record.grant = grant.id;
  record.binding = grant.binding;
  record.result = verification.result;
  record.verifier = verification.verifier;
  record.evidence = verification.evidence;
  record.at_ms = verification.now_ms;
  record.detail = bounded(verification.detail);

  Mutation mutation;
  mutation.arbitration = arb;
  mutation.changes.push_back(change_for(record));
  GrantRecord updated = grant;
  updated.verification = verification.result;
  updated.updated_at_ms = verification.now_ms;
  if (verification.result == VerificationState::Failed) {
    updated.reason = bounded("independent verification failed");
  }
  mutation.changes.push_back(change_for(updated, false));
  mutation.summary = "verify grant " + grant.id.to_string() + " result " +
                     verification_state_name(verification.result);
  return mutation;
}

MutationResult Authority::plan_reconcile_grant(const GrantOperation& op, GrantState target,
                                               PrincipalId principal, ArbSeq arb) {
  if (principal.is_nil()) {
    return Outcome(Status::Unauthorized, "reconciliation requires an identified principal");
  }
  if (!(target == GrantState::Retired || target == GrantState::Active)) {
    return Outcome(Status::Invalid, "reconciliation target must be RETIRED or ACTIVE");
  }
  const auto it = grants_.find(op.grant.raw());
  if (it == grants_.end()) {
    return Outcome(Status::NotFound, "no such grant");
  }
  const GrantRecord& grant = it->second;
  if (is_terminal(grant.state)) {
    return Outcome(Status::InvalidTransition, "grant is already terminal");
  }
  if (target == GrantState::Active) {
    if (!holds_capacity(grant.state) && grant.state != GrantState::Eligible) {
      return Outcome(Status::InvalidTransition, "grant holds no capacity to re-activate");
    }
    const auto site_it = sites_.find(grant.binding.holder.raw());
    if (site_it == sites_.end()) {
      return Outcome(Status::NotFound, "grant holder is not a registered site");
    }
    const auto path_it = paths_.find(grant.binding.path.raw());
    if (path_it == paths_.end()) {
      return Outcome(Status::NotFound, "grant path is no longer registered");
    }
    const SiteRecord& site = site_it->second;
    const PathRecord& path = path_it->second;
    if (!site_accepts_new_reservations(site.state)) {
      return Outcome(Status::Refused, std::string("site is ") + site_state_name(site.state));
    }
    if (!path_accepts_new_reservations(path.state)) {
      return Outcome(Status::Refused, std::string("path is ") + path_state_name(path.state));
    }
    Mutation mutation;
    mutation.arbitration = arb;
    GrantRecord updated = grant;
    updated.state = GrantState::Active;
    updated.binding.holder_incarnation = site.incarnation;
    updated.binding.holder_generation = site.generation;
    updated.binding.path_generation = path.generation;
    updated.binding.capacity_generation = path.capacity_generation;
    updated.binding.policy_generation = config_.policy.generation;
    updated.binding.epoch = config_.epoch;
    updated.ambiguous = false;
    updated.provenance = Provenance::OperatorReconcile;
    updated.verification = VerificationState::Unverified;
    updated.updated_at_ms = op.now_ms;
    updated.reason = bounded(op.reason);
    mutation.changes.push_back(change_for(updated, false));
    mutation.summary = "reconcile grant " + grant.id.to_string() + " to ACTIVE";
    return mutation;
  }

  Mutation mutation;
  mutation.arbitration = arb;
  GrantRecord updated = grant;
  updated.state = GrantState::Retired;
  updated.ambiguous = false;
  updated.provenance = Provenance::OperatorReconcile;
  updated.verification = VerificationState::Unverified;
  updated.updated_at_ms = op.now_ms;
  updated.reason = bounded(op.reason);
  mutation.changes.push_back(change_for(updated, true));
  mutation.summary = "reconcile grant " + grant.id.to_string() + " to RETIRED";
  return mutation;
}

MutationResult Authority::plan_tick(std::uint64_t now_ms, ArbSeq arb) {
  Mutation mutation;
  mutation.arbitration = arb;

  for (const auto& entry : sites_) {
    const SiteRecord& site = entry.second;
    if (site.state == SiteState::Fenced || site.state == SiteState::Maintenance ||
        site.state == SiteState::Draining) {
      continue;
    }
    if (site.last_heartbeat_ms == 0 || now_ms < site.last_heartbeat_ms) {
      continue;
    }
    const std::uint64_t elapsed = now_ms - site.last_heartbeat_ms;
    const std::uint64_t timeout = config_.policy.site_lease_timeout_ms;
    if (elapsed <= timeout) {
      continue;
    }
    SiteRecord updated = site;
    if (elapsed > timeout * kHeartbeatDownMultiplier) {
      updated.state = SiteState::Down;
      updated.fence_reason = bounded("heartbeat lease expired");
    } else if (site.state == SiteState::Up) {
      updated.state = SiteState::Degraded;
      updated.missed_heartbeats = site.missed_heartbeats + 1;
    } else {
      continue;
    }
    mutation.changes.push_back(change_for(updated));
    append_downgrades(mutation.changes, "site heartbeat lease expired", site.id, std::nullopt,
                      now_ms);
  }

  for (const auto& entry : grants_) {
    const GrantRecord& grant = entry.second;
    if (grant.expires_at_ms == 0 || now_ms < grant.expires_at_ms || !holds_capacity(grant.state)) {
      continue;
    }
    GrantRecord updated = grant;
    updated.state = GrantState::Expired;
    updated.updated_at_ms = now_ms;
    updated.reason = bounded("lease expired");
    mutation.changes.push_back(change_for(updated, true));
  }

  if (mutation.changes.empty()) {
    return Outcome(Status::NotFound, "nothing to expire");
  }
  mutation.summary = "expire " + std::to_string(mutation.changes.size()) + " record(s)";
  return mutation;
}

}  // namespace isf