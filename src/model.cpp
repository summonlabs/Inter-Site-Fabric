// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "isf/model.hpp"

#include <string>

namespace isf {
namespace {

constexpr std::size_t kMaxNameBytes = 128;
constexpr std::size_t kMaxReasonBytes = 512;

void encode_string_bounded(Writer& w, const std::string& v) {
  // The writer itself enforces the global byte budget; the per-field bound is
  // enforced on decode, and defensively here as well.
  w.str(v.size() > kMaxReasonBytes ? v.substr(0, kMaxReasonBytes) : v);
}

}  // namespace

const char* grant_class_name(GrantClass c) noexcept {
  switch (c) {
    case GrantClass::General:
      return "GENERAL";
    case GrantClass::Protected:
      return "PROTECTED";
  }
  return "INVALID";
}

// ---------------------------------------------------------------------------
// SiteRecord
// ---------------------------------------------------------------------------

void encode(Writer& w, const SiteRecord& v) {
  w.id128(v.id.raw());
  w.str(v.name);
  w.id128(v.incarnation.raw());
  w.generation(v.generation);
  w.epoch(v.epoch);
  w.u8(static_cast<std::uint8_t>(v.state));
  w.u64(v.advertised_capacity);
  w.u64(v.registered_at_ms);
  w.u64(v.last_heartbeat_ms);
  w.u32(v.missed_heartbeats);
  encode_string_bounded(w, v.fence_reason);
  w.u8(static_cast<std::uint8_t>(v.provenance));
}

Expected<SiteRecord> decode_site(Reader& r) {
  SiteRecord out;
  auto id = r.id128();
  if (!id.ok()) return id.status();
  out.id = SiteId::from_raw(id.value());
  auto name = r.str();
  if (!name.ok()) return name.status();
  out.name = name.value();
  auto incarnation = r.id128();
  if (!incarnation.ok()) return incarnation.status();
  out.incarnation = Incarnation::from_raw(incarnation.value());
  auto generation = r.generation();
  if (!generation.ok()) return generation.status();
  out.generation = generation.value();
  auto epoch = r.epoch();
  if (!epoch.ok()) return epoch.status();
  out.epoch = epoch.value();
  auto state = r.u8();
  if (!state.ok()) return state.status();
  if (state.value() > static_cast<std::uint8_t>(SiteState::Fenced)) {
    return Outcome(Status::Invalid, "site state out of range");
  }
  out.state = static_cast<SiteState>(state.value());
  auto advertised = r.u64();
  if (!advertised.ok()) return advertised.status();
  out.advertised_capacity = advertised.value();
  auto registered = r.u64();
  if (!registered.ok()) return registered.status();
  out.registered_at_ms = registered.value();
  auto heartbeat = r.u64();
  if (!heartbeat.ok()) return heartbeat.status();
  out.last_heartbeat_ms = heartbeat.value();
  auto missed = r.u32();
  if (!missed.ok()) return missed.status();
  out.missed_heartbeats = missed.value();
  auto reason = r.str();
  if (!reason.ok()) return reason.status();
  out.fence_reason = reason.value();
  auto provenance = r.u8();
  if (!provenance.ok()) return provenance.status();
  if (provenance.value() > static_cast<std::uint8_t>(Provenance::FencedIncarnation)) {
    return Outcome(Status::Invalid, "provenance out of range");
  }
  out.provenance = static_cast<Provenance>(provenance.value());
  return out;
}

// ---------------------------------------------------------------------------
// PathRecord
// ---------------------------------------------------------------------------

void encode(Writer& w, const PathRecord& v) {
  w.id128(v.id.raw());
  w.str(v.name);
  w.id128(v.edge.raw());
  w.id128(v.shared_risk_domain.raw());
  w.id128(v.endpoint_a.raw());
  w.id128(v.endpoint_b.raw());
  w.generation(v.generation);
  w.generation(v.capacity_generation);
  w.u8(static_cast<std::uint8_t>(v.state));
  w.u64(v.advertised);
  w.u64(v.observed);
  w.u64(v.authoritative_usable);
  w.u64(v.unavailable);
  w.u64(v.updated_at_ms);
  w.u8(static_cast<std::uint8_t>(v.provenance));
}

Expected<PathRecord> decode_path(Reader& r) {
  PathRecord out;
  auto id = r.id128();
  if (!id.ok()) return id.status();
  out.id = PathId::from_raw(id.value());
  auto name = r.str();
  if (!name.ok()) return name.status();
  out.name = name.value();
  auto edge = r.id128();
  if (!edge.ok()) return edge.status();
  out.edge = EdgeId::from_raw(edge.value());
  auto domain = r.id128();
  if (!domain.ok()) return domain.status();
  out.shared_risk_domain = DomainId::from_raw(domain.value());
  auto a = r.id128();
  if (!a.ok()) return a.status();
  out.endpoint_a = SiteId::from_raw(a.value());
  auto b = r.id128();
  if (!b.ok()) return b.status();
  out.endpoint_b = SiteId::from_raw(b.value());
  auto generation = r.generation();
  if (!generation.ok()) return generation.status();
  out.generation = generation.value();
  auto capacity_generation = r.generation();
  if (!capacity_generation.ok()) return capacity_generation.status();
  out.capacity_generation = capacity_generation.value();
  auto state = r.u8();
  if (!state.ok()) return state.status();
  if (state.value() > static_cast<std::uint8_t>(PathState::Fenced)) {
    return Outcome(Status::Invalid, "path state out of range");
  }
  out.state = static_cast<PathState>(state.value());
  auto advertised = r.u64();
  if (!advertised.ok()) return advertised.status();
  out.advertised = advertised.value();
  auto observed = r.u64();
  if (!observed.ok()) return observed.status();
  out.observed = observed.value();
  auto usable = r.u64();
  if (!usable.ok()) return usable.status();
  out.authoritative_usable = usable.value();
  auto unavailable = r.u64();
  if (!unavailable.ok()) return unavailable.status();
  out.unavailable = unavailable.value();
  if (out.unavailable > out.authoritative_usable) {
    return Outcome(Status::Conflicting, "unavailable capacity exceeds authoritative usable capacity");
  }
  auto updated = r.u64();
  if (!updated.ok()) return updated.status();
  out.updated_at_ms = updated.value();
  auto provenance = r.u8();
  if (!provenance.ok()) return provenance.status();
  if (provenance.value() > static_cast<std::uint8_t>(Provenance::FencedIncarnation)) {
    return Outcome(Status::Invalid, "provenance out of range");
  }
  out.provenance = static_cast<Provenance>(provenance.value());
  return out;
}

// ---------------------------------------------------------------------------
// SharedRiskDomain
// ---------------------------------------------------------------------------

void encode(Writer& w, const SharedRiskDomain& v) {
  w.id128(v.id.raw());
  w.str(v.name);
  w.str(v.description);
}

Expected<SharedRiskDomain> decode_domain(Reader& r) {
  SharedRiskDomain out;
  auto id = r.id128();
  if (!id.ok()) return id.status();
  out.id = DomainId::from_raw(id.value());
  auto name = r.str();
  if (!name.ok()) return name.status();
  out.name = name.value();
  auto description = r.str();
  if (!description.ok()) return description.status();
  out.description = description.value();
  return out;
}

// ---------------------------------------------------------------------------
// CapacityAttestation
// ---------------------------------------------------------------------------

void encode(Writer& w, const CapacityAttestation& v) {
  w.id128(v.id.raw());
  w.id128(v.path.raw());
  w.generation(v.path_generation);
  w.generation(v.capacity_generation);
  w.u64(v.usable);
  w.u64(v.advertised);
  w.u64(v.observed);
  w.id128(v.issuer.raw());
  w.epoch(v.epoch);
  w.id128(v.principal.raw());
  w.u64(v.observed_at_ms);
  w.digest(v.evidence);
  encode_string_bounded(w, v.source);
}

Expected<CapacityAttestation> decode_attestation(Reader& r) {
  CapacityAttestation out;
  auto id = r.id128();
  if (!id.ok()) return id.status();
  out.id = AttestationId::from_raw(id.value());
  auto path = r.id128();
  if (!path.ok()) return path.status();
  out.path = PathId::from_raw(path.value());
  auto path_generation = r.generation();
  if (!path_generation.ok()) return path_generation.status();
  out.path_generation = path_generation.value();
  auto capacity_generation = r.generation();
  if (!capacity_generation.ok()) return capacity_generation.status();
  out.capacity_generation = capacity_generation.value();
  auto usable = r.u64();
  if (!usable.ok()) return usable.status();
  out.usable = usable.value();
  auto advertised = r.u64();
  if (!advertised.ok()) return advertised.status();
  out.advertised = advertised.value();
  auto observed = r.u64();
  if (!observed.ok()) return observed.status();
  out.observed = observed.value();
  auto issuer = r.id128();
  if (!issuer.ok()) return issuer.status();
  out.issuer = Incarnation::from_raw(issuer.value());
  auto epoch = r.epoch();
  if (!epoch.ok()) return epoch.status();
  out.epoch = epoch.value();
  auto principal = r.id128();
  if (!principal.ok()) return principal.status();
  out.principal = PrincipalId::from_raw(principal.value());
  auto observed_at = r.u64();
  if (!observed_at.ok()) return observed_at.status();
  out.observed_at_ms = observed_at.value();
  auto evidence = r.digest();
  if (!evidence.ok()) return evidence.status();
  out.evidence = evidence.value();
  auto source = r.str();
  if (!source.ok()) return source.status();
  out.source = source.value();
  return out;
}

// ---------------------------------------------------------------------------
// GrantBinding
// ---------------------------------------------------------------------------

void encode(Writer& w, const GrantBinding& v) {
  w.id128(v.holder.raw());
  w.id128(v.holder_incarnation.raw());
  w.generation(v.holder_generation);
  w.id128(v.path.raw());
  w.generation(v.path_generation);
  w.generation(v.capacity_generation);
  w.generation(v.policy_generation);
  w.epoch(v.epoch);
  w.id128(v.lease.raw());
}

Expected<GrantBinding> decode_binding(Reader& r) {
  GrantBinding out;
  auto holder = r.id128();
  if (!holder.ok()) return holder.status();
  out.holder = SiteId::from_raw(holder.value());
  auto incarnation = r.id128();
  if (!incarnation.ok()) return incarnation.status();
  out.holder_incarnation = Incarnation::from_raw(incarnation.value());
  auto holder_generation = r.generation();
  if (!holder_generation.ok()) return holder_generation.status();
  out.holder_generation = holder_generation.value();
  auto path = r.id128();
  if (!path.ok()) return path.status();
  out.path = PathId::from_raw(path.value());
  auto path_generation = r.generation();
  if (!path_generation.ok()) return path_generation.status();
  out.path_generation = path_generation.value();
  auto capacity_generation = r.generation();
  if (!capacity_generation.ok()) return capacity_generation.status();
  out.capacity_generation = capacity_generation.value();
  auto policy_generation = r.generation();
  if (!policy_generation.ok()) return policy_generation.status();
  out.policy_generation = policy_generation.value();
  auto epoch = r.epoch();
  if (!epoch.ok()) return epoch.status();
  out.epoch = epoch.value();
  auto lease = r.id128();
  if (!lease.ok()) return lease.status();
  out.lease = LeaseId::from_raw(lease.value());
  return out;
}

// ---------------------------------------------------------------------------
// GrantRecord
// ---------------------------------------------------------------------------

void encode(Writer& w, const GrantRecord& v) {
  w.id128(v.id.raw());
  w.id128(v.request.raw());
  w.u64(v.arbitration.value);
  encode(w, v.binding);
  w.u8(static_cast<std::uint8_t>(v.grant_class));
  w.u64(v.amount);
  w.u8(static_cast<std::uint8_t>(v.state));
  w.u8(static_cast<std::uint8_t>(v.verification));
  w.boolean(v.acknowledged);
  w.u32(v.ack_count);
  w.u64(v.created_at_ms);
  w.u64(v.updated_at_ms);
  w.u64(v.expires_at_ms);
  encode_string_bounded(w, v.reason);
  w.u8(static_cast<std::uint8_t>(v.provenance));
  w.boolean(v.historical);
  w.boolean(v.ambiguous);
}

Expected<GrantRecord> decode_grant(Reader& r) {
  GrantRecord out;
  auto id = r.id128();
  if (!id.ok()) return id.status();
  out.id = GrantId::from_raw(id.value());
  auto request = r.id128();
  if (!request.ok()) return request.status();
  out.request = RequestId::from_raw(request.value());
  auto arbitration = r.u64();
  if (!arbitration.ok()) return arbitration.status();
  out.arbitration = ArbSeq{arbitration.value()};
  auto binding = decode_binding(r);
  if (!binding.ok()) return binding.status();
  out.binding = binding.value();
  auto grant_class = r.u8();
  if (!grant_class.ok()) return grant_class.status();
  if (grant_class.value() > static_cast<std::uint8_t>(GrantClass::Protected)) {
    return Outcome(Status::Invalid, "grant class out of range");
  }
  out.grant_class = static_cast<GrantClass>(grant_class.value());
  auto amount = r.u64();
  if (!amount.ok()) return amount.status();
  out.amount = amount.value();
  auto state = r.u8();
  if (!state.ok()) return state.status();
  if (state.value() > static_cast<std::uint8_t>(GrantState::Expired)) {
    return Outcome(Status::Invalid, "grant state out of range");
  }
  out.state = static_cast<GrantState>(state.value());
  auto verification = r.u8();
  if (!verification.ok()) return verification.status();
  if (verification.value() > static_cast<std::uint8_t>(VerificationState::Indeterminate)) {
    return Outcome(Status::Invalid, "verification state out of range");
  }
  out.verification = static_cast<VerificationState>(verification.value());
  auto ack = r.boolean();
  if (!ack.ok()) return ack.status();
  out.acknowledged = ack.value();
  auto ack_count = r.u32();
  if (!ack_count.ok()) return ack_count.status();
  out.ack_count = ack_count.value();
  auto created = r.u64();
  if (!created.ok()) return created.status();
  out.created_at_ms = created.value();
  auto updated = r.u64();
  if (!updated.ok()) return updated.status();
  out.updated_at_ms = updated.value();
  auto expires = r.u64();
  if (!expires.ok()) return expires.status();
  out.expires_at_ms = expires.value();
  auto reason = r.str();
  if (!reason.ok()) return reason.status();
  out.reason = reason.value();
  auto provenance = r.u8();
  if (!provenance.ok()) return provenance.status();
  if (provenance.value() > static_cast<std::uint8_t>(Provenance::FencedIncarnation)) {
    return Outcome(Status::Invalid, "provenance out of range");
  }
  out.provenance = static_cast<Provenance>(provenance.value());
  auto historical = r.boolean();
  if (!historical.ok()) return historical.status();
  out.historical = historical.value();
  auto ambiguous = r.boolean();
  if (!ambiguous.ok()) return ambiguous.status();
  out.ambiguous = ambiguous.value();
  return out;
}

// ---------------------------------------------------------------------------
// VerificationRecord
// ---------------------------------------------------------------------------

void encode(Writer& w, const VerificationRecord& v) {
  w.id128(v.id.raw());
  w.id128(v.grant.raw());
  encode(w, v.binding);
  w.u8(static_cast<std::uint8_t>(v.result));
  w.id128(v.verifier.raw());
  w.digest(v.evidence);
  w.u64(v.at_ms);
  encode_string_bounded(w, v.detail);
}

Expected<VerificationRecord> decode_verification(Reader& r) {
  VerificationRecord out;
  auto id = r.id128();
  if (!id.ok()) return id.status();
  out.id = VerificationId::from_raw(id.value());
  auto grant = r.id128();
  if (!grant.ok()) return grant.status();
  out.grant = GrantId::from_raw(grant.value());
  auto binding = decode_binding(r);
  if (!binding.ok()) return binding.status();
  out.binding = binding.value();
  auto result = r.u8();
  if (!result.ok()) return result.status();
  if (result.value() > static_cast<std::uint8_t>(VerificationState::Indeterminate)) {
    return Outcome(Status::Invalid, "verification result out of range");
  }
  out.result = static_cast<VerificationState>(result.value());
  auto verifier = r.id128();
  if (!verifier.ok()) return verifier.status();
  out.verifier = PrincipalId::from_raw(verifier.value());
  auto evidence = r.digest();
  if (!evidence.ok()) return evidence.status();
  out.evidence = evidence.value();
  auto at = r.u64();
  if (!at.ok()) return at.status();
  out.at_ms = at.value();
  auto detail = r.str();
  if (!detail.ok()) return detail.status();
  out.detail = detail.value();
  return out;
}

// ---------------------------------------------------------------------------
// OversubscriptionAuthority
// ---------------------------------------------------------------------------

void encode(Writer& w, const OversubscriptionAuthority& v) {
  w.id128(v.id.raw());
  w.id128(v.path.raw());
  w.generation(v.path_generation);
  w.generation(v.capacity_generation);
  w.generation(v.policy_generation);
  w.epoch(v.epoch);
  w.id128(v.issuer.raw());
  w.u32(v.ratio_bps);
  w.u64(v.issued_at_ms);
  w.u64(v.not_after_ms);
  w.id128(v.principal.raw());
}

Expected<OversubscriptionAuthority> decode_oversubscription(Reader& r) {
  OversubscriptionAuthority out;
  auto id = r.id128();
  if (!id.ok()) return id.status();
  out.id = OversubscriptionId::from_raw(id.value());
  auto path = r.id128();
  if (!path.ok()) return path.status();
  out.path = PathId::from_raw(path.value());
  auto path_generation = r.generation();
  if (!path_generation.ok()) return path_generation.status();
  out.path_generation = path_generation.value();
  auto capacity_generation = r.generation();
  if (!capacity_generation.ok()) return capacity_generation.status();
  out.capacity_generation = capacity_generation.value();
  auto policy_generation = r.generation();
  if (!policy_generation.ok()) return policy_generation.status();
  out.policy_generation = policy_generation.value();
  auto epoch = r.epoch();
  if (!epoch.ok()) return epoch.status();
  out.epoch = epoch.value();
  auto issuer = r.id128();
  if (!issuer.ok()) return issuer.status();
  out.issuer = Incarnation::from_raw(issuer.value());
  auto ratio = r.u32();
  if (!ratio.ok()) return ratio.status();
  out.ratio_bps = ratio.value();
  auto issued = r.u64();
  if (!issued.ok()) return issued.status();
  out.issued_at_ms = issued.value();
  auto not_after = r.u64();
  if (!not_after.ok()) return not_after.status();
  out.not_after_ms = not_after.value();
  auto principal = r.id128();
  if (!principal.ok()) return principal.status();
  out.principal = PrincipalId::from_raw(principal.value());
  return out;
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

void encode(Writer& w, const Policy& v) {
  w.id128(v.id.raw());
  w.generation(v.generation);
  w.u64(v.protected_floor_units);
  w.u32(v.protected_floor_bps);
  w.u64(v.min_free_units);
  w.u32(v.min_free_bps);
  w.u32(v.max_oversubscription_bps);
  w.u64(v.max_lease_duration_ms);
  w.u32(v.max_grants_per_path);
  w.u32(v.max_grants_per_site);
  w.u32(v.max_srd_concentration_bps);
  w.boolean(v.allow_degraded_activation);
  w.boolean(v.allow_partition_optimistic_recovery);
  w.boolean(v.require_verification_for_active);
  w.boolean(v.auto_reconcile_on_restart);
  w.u64(v.site_lease_timeout_ms);
}

Expected<Policy> decode_policy(Reader& r) {
  Policy out;
  auto id = r.id128();
  if (!id.ok()) return id.status();
  out.id = PolicyId::from_raw(id.value());
  auto generation = r.generation();
  if (!generation.ok()) return generation.status();
  out.generation = generation.value();
  auto protected_units = r.u64();
  if (!protected_units.ok()) return protected_units.status();
  out.protected_floor_units = protected_units.value();
  auto protected_bps = r.u32();
  if (!protected_bps.ok()) return protected_bps.status();
  out.protected_floor_bps = protected_bps.value();
  auto min_free_units = r.u64();
  if (!min_free_units.ok()) return min_free_units.status();
  out.min_free_units = min_free_units.value();
  auto min_free_bps = r.u32();
  if (!min_free_bps.ok()) return min_free_bps.status();
  out.min_free_bps = min_free_bps.value();
  auto oversub = r.u32();
  if (!oversub.ok()) return oversub.status();
  out.max_oversubscription_bps = oversub.value();
  auto lease = r.u64();
  if (!lease.ok()) return lease.status();
  out.max_lease_duration_ms = lease.value();
  auto per_path = r.u32();
  if (!per_path.ok()) return per_path.status();
  out.max_grants_per_path = per_path.value();
  auto per_site = r.u32();
  if (!per_site.ok()) return per_site.status();
  out.max_grants_per_site = per_site.value();
  auto concentration = r.u32();
  if (!concentration.ok()) return concentration.status();
  out.max_srd_concentration_bps = concentration.value();
  auto degraded = r.boolean();
  if (!degraded.ok()) return degraded.status();
  out.allow_degraded_activation = degraded.value();
  auto optimistic = r.boolean();
  if (!optimistic.ok()) return optimistic.status();
  out.allow_partition_optimistic_recovery = optimistic.value();
  auto require_verification = r.boolean();
  if (!require_verification.ok()) return require_verification.status();
  out.require_verification_for_active = require_verification.value();
  auto auto_reconcile = r.boolean();
  if (!auto_reconcile.ok()) return auto_reconcile.status();
  out.auto_reconcile_on_restart = auto_reconcile.value();
  auto site_lease = r.u64();
  if (!site_lease.ok()) return site_lease.status();
  out.site_lease_timeout_ms = site_lease.value();
  return out;
}

}  // namespace isf
