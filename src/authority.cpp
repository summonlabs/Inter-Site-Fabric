// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "isf/authority.hpp"

#include "isf/checked.hpp"

#include <algorithm>
#include <string>
#include <utility>

namespace isf {
namespace {

constexpr std::size_t kMaxReasonText = 512;

[[nodiscard]] std::string bounded(std::string text) {
  if (text.size() > kMaxReasonText) {
    text.resize(kMaxReasonText);
  }
  return text;
}

[[nodiscard]] bool is_holding_state(GrantState s) { return holds_capacity(s); }

/// States for which a grant's generation binding must still match live state.
[[nodiscard]] bool requires_current_binding(GrantState s) {
  return s == GrantState::Proposed || s == GrantState::Eligible || s == GrantState::Reserved ||
         s == GrantState::Active || s == GrantState::Degraded;
}

constexpr std::uint64_t kHeartbeatDownMultiplier = 3;

}  // namespace

const char* object_kind_name(ObjectKind k) noexcept {
  switch (k) {
    case ObjectKind::Site:
      return "SITE";
    case ObjectKind::Path:
      return "PATH";
    case ObjectKind::Domain:
      return "DOMAIN";
    case ObjectKind::Attestation:
      return "ATTESTATION";
    case ObjectKind::Grant:
      return "GRANT";
    case ObjectKind::Verification:
      return "VERIFICATION";
    case ObjectKind::Oversubscription:
      return "OVERSUBSCRIPTION";
    case ObjectKind::Policy:
      return "POLICY";
    case ObjectKind::Epoch:
      return "EPOCH";
    case ObjectKind::AuthorityMeta:
      return "AUTHORITY_META";
  }
  return "INVALID";
}

// ---------------------------------------------------------------------------
// StateChange codec
// ---------------------------------------------------------------------------

void encode(Writer& w, const StateChange& v) {
  w.u8(static_cast<std::uint8_t>(v.kind));
  w.id128(v.key);
  w.boolean(v.releases_capacity);
  w.bytes(ByteSpan(v.image.data(), v.image.size()));
}

Expected<StateChange> decode_state_change(Reader& r) {
  StateChange out;
  auto kind = r.u8();
  if (!kind.ok()) return kind.status();
  if (kind.value() < 1 || kind.value() > static_cast<std::uint8_t>(ObjectKind::AuthorityMeta)) {
    return Outcome(Status::Invalid, "unknown object kind in state change");
  }
  out.kind = static_cast<ObjectKind>(kind.value());
  auto key = r.id128();
  if (!key.ok()) return key.status();
  out.key = key.value();
  auto releases = r.boolean();
  if (!releases.ok()) return releases.status();
  out.releases_capacity = releases.value();
  auto image = r.bytes();
  if (!image.ok()) return image.status();
  out.image.assign(image.value().begin(), image.value().end());
  return out;
}

// ---------------------------------------------------------------------------
// Snapshot codec
// ---------------------------------------------------------------------------

void encode(Writer& w, const AuthoritySnapshot& v) {
  w.epoch(v.epoch);
  w.id128(v.incarnation.raw());
  encode(w, v.policy);
  w.u32(static_cast<std::uint32_t>(v.sites.size()));
  for (const auto& item : v.sites) encode(w, item);
  w.u32(static_cast<std::uint32_t>(v.paths.size()));
  for (const auto& item : v.paths) encode(w, item);
  w.u32(static_cast<std::uint32_t>(v.domains.size()));
  for (const auto& item : v.domains) encode(w, item);
  w.u32(static_cast<std::uint32_t>(v.attestations.size()));
  for (const auto& item : v.attestations) encode(w, item);
  w.u32(static_cast<std::uint32_t>(v.grants.size()));
  for (const auto& item : v.grants) encode(w, item);
  w.u32(static_cast<std::uint32_t>(v.verifications.size()));
  for (const auto& item : v.verifications) encode(w, item);
  w.u32(static_cast<std::uint32_t>(v.oversubscriptions.size()));
  for (const auto& item : v.oversubscriptions) encode(w, item);
  w.u64(v.last_arbitration.value);
}

Expected<AuthoritySnapshot> decode_snapshot(Reader& r) {
  AuthoritySnapshot out;
  auto epoch = r.epoch();
  if (!epoch.ok()) return epoch.status();
  out.epoch = epoch.value();
  auto incarnation = r.id128();
  if (!incarnation.ok()) return incarnation.status();
  out.incarnation = Incarnation::from_raw(incarnation.value());
  auto policy = decode_policy(r);
  if (!policy.ok()) return policy.status();
  out.policy = policy.value();

  auto sites = r.container_count();
  if (!sites.ok()) return sites.status();
  for (std::uint32_t i = 0; i < sites.value(); ++i) {
    auto item = decode_site(r);
    if (!item.ok()) return item.status();
    out.sites.push_back(item.value());
  }
  auto paths = r.container_count();
  if (!paths.ok()) return paths.status();
  for (std::uint32_t i = 0; i < paths.value(); ++i) {
    auto item = decode_path(r);
    if (!item.ok()) return item.status();
    out.paths.push_back(item.value());
  }
  auto domains = r.container_count();
  if (!domains.ok()) return domains.status();
  for (std::uint32_t i = 0; i < domains.value(); ++i) {
    auto item = decode_domain(r);
    if (!item.ok()) return item.status();
    out.domains.push_back(item.value());
  }
  auto attestations = r.container_count();
  if (!attestations.ok()) return attestations.status();
  for (std::uint32_t i = 0; i < attestations.value(); ++i) {
    auto item = decode_attestation(r);
    if (!item.ok()) return item.status();
    out.attestations.push_back(item.value());
  }
  auto grants = r.container_count();
  if (!grants.ok()) return grants.status();
  for (std::uint32_t i = 0; i < grants.value(); ++i) {
    auto item = decode_grant(r);
    if (!item.ok()) return item.status();
    out.grants.push_back(item.value());
  }
  auto verifications = r.container_count();
  if (!verifications.ok()) return verifications.status();
  for (std::uint32_t i = 0; i < verifications.value(); ++i) {
    auto item = decode_verification(r);
    if (!item.ok()) return item.status();
    out.verifications.push_back(item.value());
  }
  auto oversubscriptions = r.container_count();
  if (!oversubscriptions.ok()) return oversubscriptions.status();
  for (std::uint32_t i = 0; i < oversubscriptions.value(); ++i) {
    auto item = decode_oversubscription(r);
    if (!item.ok()) return item.status();
    out.oversubscriptions.push_back(item.value());
  }
  auto arb = r.u64();
  if (!arb.ok()) return arb.status();
  out.last_arbitration = ArbSeq{arb.value()};
  return out;
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

Authority::Authority(AuthorityConfig config) : config_(std::move(config)) {
  if (config_.policy.generation.is_nil()) {
    config_.policy.generation = Generation{1};
  }
  if (config_.epoch.value == 0) {
    config_.epoch = Epoch{1};
  }
  if (config_.incarnation.is_nil()) {
    config_.incarnation = Incarnation::random();
  }
  SharedRiskDomain default_domain;
  default_domain.id = DomainId::from_seed(0x15F0D0A1ULL, 0);
  default_domain.name = "default";
  default_domain.description = "shared risk domain applied to paths without an explicit domain";
  domains_.emplace(default_domain.id.raw(), default_domain);
}

Expected<Authority> Authority::from_snapshot(AuthorityConfig config,
                                             const AuthoritySnapshot& snapshot) {
  if (snapshot.policy.validate() != Status::Ok) {
    return Outcome(Status::Corrupt, "snapshot carries an invalid policy");
  }
  Authority authority(std::move(config));
  authority.config_.policy = snapshot.policy;
  authority.config_.epoch = snapshot.epoch.value == 0 ? Epoch{1} : snapshot.epoch;
  authority.last_arbitration_ = snapshot.last_arbitration;
  for (const auto& item : snapshot.domains) {
    if (item.id.is_nil()) {
      return Outcome(Status::Corrupt, "snapshot carries a shared risk domain with a nil identity");
    }
    authority.domains_[item.id.raw()] = item;
  }
  for (const auto& item : snapshot.sites) {
    if (item.id.is_nil()) {
      return Outcome(Status::Corrupt, "snapshot carries a site with a nil identity");
    }
    authority.sites_[item.id.raw()] = item;
  }
  for (const auto& item : snapshot.paths) {
    if (item.id.is_nil()) {
      return Outcome(Status::Corrupt, "snapshot carries a path with a nil identity");
    }
    authority.paths_[item.id.raw()] = item;
  }
  for (const auto& item : snapshot.attestations) {
    if (item.id.is_nil()) {
      return Outcome(Status::Corrupt, "snapshot carries an attestation with a nil identity");
    }
    authority.attestations_[item.id.raw()] = item;
  }
  for (const auto& item : snapshot.grants) {
    if (item.id.is_nil()) {
      return Outcome(Status::Corrupt, "snapshot carries a grant with a nil identity");
    }
    GrantRecord recovered = item;
    if (recovered.provenance == Provenance::Live) {
      recovered.provenance = Provenance::RecoveredFromSnapshot;
    }
    if (!is_terminal(recovered.state)) {
      // Recovered dynamic evidence is historical, never silently fresh.
      recovered.historical = true;
      recovered.verification = VerificationState::Unverified;
    }
    authority.grants_[item.id.raw()] = recovered;
    if (!item.request.is_nil()) {
      const auto existing = authority.request_index_.find(item.request.raw());
      if (existing != authority.request_index_.end() && !(existing->second == item.id.raw())) {
        return Outcome(Status::Corrupt, "snapshot contains two grants for one request identity");
      }
      authority.request_index_[item.request.raw()] = item.id.raw();
    }
  }
  for (const auto& item : snapshot.verifications) {
    if (item.id.is_nil()) {
      return Outcome(Status::Corrupt, "snapshot carries a verification with a nil identity");
    }
    authority.verifications_[item.id.raw()] = item;
  }
  for (const auto& item : snapshot.oversubscriptions) {
    if (item.id.is_nil()) {
      return Outcome(Status::Corrupt, "snapshot carries an oversubscription with a nil identity");
    }
    authority.oversubscriptions_[item.id.raw()] = item;
  }
  return authority;
}

// ---------------------------------------------------------------------------
// Introspection
// ---------------------------------------------------------------------------

std::optional<SiteRecord> Authority::find_site(SiteId id) const {
  const auto it = sites_.find(id.raw());
  if (it == sites_.end()) {
    return std::nullopt;
  }
  return it->second;
}

std::optional<PathRecord> Authority::find_path(PathId id) const {
  const auto it = paths_.find(id.raw());
  if (it == paths_.end()) {
    return std::nullopt;
  }
  return it->second;
}

std::optional<GrantRecord> Authority::find_grant(GrantId id) const {
  const auto it = grants_.find(id.raw());
  if (it == grants_.end()) {
    return std::nullopt;
  }
  return it->second;
}

std::optional<CapacityAttestation> Authority::find_attestation(AttestationId id) const {
  const auto it = attestations_.find(id.raw());
  if (it == attestations_.end()) {
    return std::nullopt;
  }
  return it->second;
}

std::optional<OversubscriptionAuthority> Authority::find_oversubscription(
    OversubscriptionId id) const {
  const auto it = oversubscriptions_.find(id.raw());
  if (it == oversubscriptions_.end()) {
    return std::nullopt;
  }
  return it->second;
}

std::vector<SiteRecord> Authority::sites() const {
  std::vector<SiteRecord> out;
  out.reserve(sites_.size());
  for (const auto& entry : sites_) out.push_back(entry.second);
  return out;
}

std::vector<PathRecord> Authority::paths() const {
  std::vector<PathRecord> out;
  out.reserve(paths_.size());
  for (const auto& entry : paths_) out.push_back(entry.second);
  return out;
}

std::vector<SharedRiskDomain> Authority::domains() const {
  std::vector<SharedRiskDomain> out;
  out.reserve(domains_.size());
  for (const auto& entry : domains_) out.push_back(entry.second);
  return out;
}

std::vector<GrantRecord> Authority::grants() const {
  std::vector<GrantRecord> out;
  out.reserve(grants_.size());
  for (const auto& entry : grants_) out.push_back(entry.second);
  return out;
}

std::vector<CapacityAttestation> Authority::attestations() const {
  std::vector<CapacityAttestation> out;
  out.reserve(attestations_.size());
  for (const auto& entry : attestations_) out.push_back(entry.second);
  return out;
}

std::vector<VerificationRecord> Authority::verifications() const {
  std::vector<VerificationRecord> out;
  out.reserve(verifications_.size());
  for (const auto& entry : verifications_) out.push_back(entry.second);
  return out;
}

std::vector<OversubscriptionAuthority> Authority::oversubscriptions() const {
  std::vector<OversubscriptionAuthority> out;
  out.reserve(oversubscriptions_.size());
  for (const auto& entry : oversubscriptions_) out.push_back(entry.second);
  return out;
}

std::vector<GrantRecord> Authority::grants_for_path(PathId path) const {
  std::vector<GrantRecord> out;
  for (const auto& entry : grants_) {
    if (entry.second.binding.path == path) {
      out.push_back(entry.second);
    }
  }
  return out;
}

std::vector<GrantRecord> Authority::grants_for_site(SiteId site) const {
  std::vector<GrantRecord> out;
  for (const auto& entry : grants_) {
    if (entry.second.binding.holder == site) {
      out.push_back(entry.second);
    }
  }
  return out;
}

Amount Authority::protected_floor(const PathRecord& path) const {
  const Amount by_ratio = fraction_bps(path.authoritative_usable, config_.policy.protected_floor_bps);
  const Amount wanted = max_amount(config_.policy.protected_floor_units, by_ratio);
  // Capacity that is unavailable cannot be protected, so the floor is capped by
  // the basis that actually exists.
  const Amount basis = path.authoritative_usable > path.unavailable
                           ? path.authoritative_usable - path.unavailable
                           : 0;
  return wanted > basis ? basis : wanted;
}

Amount Authority::minimum_free(const PathRecord& path) const {
  const Amount by_ratio = fraction_bps(path.authoritative_usable, config_.policy.min_free_bps);
  const Amount wanted = max_amount(config_.policy.min_free_units, by_ratio);
  const Amount basis = path.authoritative_usable > path.unavailable
                           ? path.authoritative_usable - path.unavailable
                           : 0;
  return wanted > basis ? basis : wanted;
}

Authority::PathTotals Authority::totals_for(PathId path) const {
  PathTotals totals;
  for (const auto& entry : grants_) {
    const GrantRecord& grant = entry.second;
    if (!(grant.binding.path == path) || !is_holding_state(grant.state)) {
      continue;
    }
    if (grant.state == GrantState::Active || grant.state == GrantState::Degraded) {
      totals.committed = saturating_add(totals.committed, grant.amount);
    } else if (grant.state == GrantState::Withdrawing) {
      totals.withdrawing = saturating_add(totals.withdrawing, grant.amount);
    } else if (grant.state == GrantState::Reserved) {
      totals.reserved = saturating_add(totals.reserved, grant.amount);
    }
    if (is_reclaimable(grant.state)) {
      totals.reclaimable = saturating_add(totals.reclaimable, grant.amount);
    }
    if (grant.grant_class == GrantClass::Protected) {
      totals.protected_held = saturating_add(totals.protected_held, grant.amount);
    }
  }
  return totals;
}

Expected<CapacityLedger> Authority::ledger(PathId path) const {
  const auto path_it = paths_.find(path.raw());
  if (path_it == paths_.end()) {
    return Outcome(Status::NotFound, "no such path");
  }
  const PathRecord& record = path_it->second;
  if (record.unavailable > record.authoritative_usable) {
    return Outcome(Status::Conflicting,
                   "path has more unavailable capacity than authoritative capacity");
  }
  const PathTotals totals = totals_for(path);

  CapacityLedger out;
  out.authoritative_usable = record.authoritative_usable;
  out.committed = totals.committed;
  out.withdrawing = totals.withdrawing;
  out.reserved = totals.reserved;
  out.reclaimable = totals.reclaimable;
  const Amount floor_amount = protected_floor(record);
  out.protected_headroom =
      totals.protected_held >= floor_amount ? 0 : floor_amount - totals.protected_held;
  out.unavailable = record.unavailable;

  auto ratio = live_oversubscription_bps(path, 0);
  const std::uint32_t permitted_bps = ratio.ok() ? ratio.value() : 0;
  out.authorized_extension = oversubscription_extension(record.authoritative_usable, permitted_bps);

  auto basis = out.basis();
  if (!basis.ok()) {
    return basis.status();
  }
  auto obligations = checked_add(out.committed, out.reserved);
  if (!obligations.ok()) {
    return obligations.status();
  }
  auto with_floor = checked_add(obligations.value(), out.protected_headroom);
  if (!with_floor.ok()) {
    return with_floor.status();
  }
  auto structural = checked_add(with_floor.value(), out.unavailable);
  if (!structural.ok()) {
    return structural.status();
  }
  if (structural.value() <= basis.value()) {
    out.free = basis.value() - structural.value();
    out.oversubscribed = 0;
  } else {
    out.free = 0;
    out.oversubscribed = structural.value() - basis.value();
  }
  auto blocked = checked_add(structural.value(), out.withdrawing);
  if (!blocked.ok()) {
    return blocked.status();
  }
  blocked = checked_add(blocked.value(), minimum_free(record));
  if (!blocked.ok()) {
    return blocked.status();
  }
  out.allocatable = blocked.value() < basis.value() ? basis.value() - blocked.value() : 0;

  const Status closure = out.verify_closure();
  if (closure != Status::Ok) {
    return Outcome(Status::Conflicting,
                   "capacity ledger for path does not close: " + out.to_string());
  }
  return out;
}

CapacityLedger Authority::aggregate_ledger() const {
  CapacityLedger out;
  Amount blocked = 0;
  Amount basis = 0;
  for (const auto& entry : paths_) {
    const PathRecord& record = entry.second;
    const PathTotals totals = totals_for(record.id);
    out.authoritative_usable = saturating_add(out.authoritative_usable, record.authoritative_usable);
    out.committed = saturating_add(out.committed, totals.committed);
    out.withdrawing = saturating_add(out.withdrawing, totals.withdrawing);
    out.reserved = saturating_add(out.reserved, totals.reserved);
    out.reclaimable = saturating_add(out.reclaimable, totals.reclaimable);
    const Amount record_floor = protected_floor(record);
    out.protected_headroom = saturating_add(
        out.protected_headroom,
        totals.protected_held >= record_floor ? 0 : record_floor - totals.protected_held);
    out.unavailable = saturating_add(out.unavailable, record.unavailable);
    auto ratio = live_oversubscription_bps(record.id, 0);
    out.authorized_extension = saturating_add(
        out.authorized_extension,
        oversubscription_extension(record.authoritative_usable, ratio.ok() ? ratio.value() : 0));
    basis = saturating_add(basis, record.authoritative_usable);
    blocked = saturating_add(blocked, totals.committed);
    blocked = saturating_add(blocked, totals.reserved);
    blocked = saturating_add(blocked, totals.withdrawing);
    blocked = saturating_add(blocked, totals.protected_held > protected_floor(record)
                                                 ? totals.protected_held
                                                 : protected_floor(record));
    blocked = saturating_add(blocked, record.unavailable);
  }
  const Amount ceiling = saturating_add(out.authoritative_usable, out.authorized_extension);
  out.free = ceiling > blocked ? ceiling - blocked : 0;
  out.allocatable = ceiling > blocked ? ceiling - blocked : 0;
  out.oversubscribed = 0;
  (void)basis;
  return out;
}

Expected<std::uint32_t> Authority::live_oversubscription_bps(PathId path,
                                                             std::uint64_t now_ms) const {
  const auto path_it = paths_.find(path.raw());
  if (path_it == paths_.end()) {
    return Status::NotFound;
  }
  if (config_.policy.max_oversubscription_bps == 0) {
    return Outcome(Status::Refused, "policy forbids oversubscription");
  }
  const PathRecord& record = path_it->second;
  std::uint32_t best = 0;
  for (const auto& entry : oversubscriptions_) {
    const OversubscriptionAuthority& authority = entry.second;
    if (!(authority.path == path)) {
      continue;
    }
    if (authority.ratio_bps <= 10000) {
      continue;
    }
    if (now_ms != 0 && !authority.is_live_at(now_ms)) {
      continue;
    }
    if (authority.epoch.value != config_.epoch.value) {
      continue;
    }
    if (authority.policy_generation != config_.policy.generation) {
      continue;
    }
    if (authority.path_generation != record.generation) {
      continue;
    }
    if (authority.capacity_generation != record.capacity_generation) {
      continue;
    }
    best = std::max(best, authority.ratio_bps);
  }
  if (best == 0) {
    return Outcome(Status::Refused, "no live oversubscription authority for this path");
  }
  return std::min(best, config_.policy.max_oversubscription_bps);
}

Expected<Amount> Authority::allocatable(PathId path, GrantClass klass, std::uint64_t now_ms) const {
  const auto path_it = paths_.find(path.raw());
  if (path_it == paths_.end()) {
    return Status::NotFound;
  }
  const PathRecord& record = path_it->second;
  if (record.unavailable > record.authoritative_usable) {
    return Outcome(Status::Conflicting,
                   "unavailable capacity exceeds authoritative usable capacity");
  }
  const PathTotals totals = totals_for(path);
  const Amount floor_amount = protected_floor(record);

  if (klass == GrantClass::Protected) {
    if (totals.protected_held > floor_amount) {
      return Outcome(Status::Conflicting,
                     "protected obligations already exceed the policy protected floor");
    }
    return floor_amount - totals.protected_held;
  }

  auto extension = live_oversubscription_bps(path, now_ms);
  const Amount ceiling =
      saturating_add(record.authoritative_usable,
                     oversubscription_extension(record.authoritative_usable,
                                                extension.ok() ? extension.value() : 0));
  if (record.unavailable >= ceiling) {
    return Amount{0};
  }
  const Amount basis = ceiling - record.unavailable;
  auto consumed = checked_add(totals.committed, totals.reserved);
  if (!consumed.ok()) {
    return consumed.status();
  }
  consumed = checked_add(consumed.value(), totals.withdrawing);
  if (!consumed.ok()) {
    return consumed.status();
  }
  consumed = checked_add(consumed.value(), floor_amount);
  if (!consumed.ok()) {
    return consumed.status();
  }
  consumed = checked_add(consumed.value(), minimum_free(record));
  if (!consumed.ok()) {
    return consumed.status();
  }
  return consumed.value() < basis ? basis - consumed.value() : 0;
}

Digest256 Authority::state_digest() const {
  Sha256 hasher;
  const Byte tag_policy = 1;
  hasher.update(ByteSpan(&tag_policy, 1));
  {
    Writer w;
    encode(w, config_.policy);
    hasher.update(w.span());
  }
  {
    // The authority epoch is authoritative state; the process incarnation is
    // not. Excluding the incarnation makes the digest a function of
    // authoritative state alone, so two daemons that recovered the same state
    // produce the same digest regardless of when they started.
    const Byte tag_epoch = 2;
    hasher.update(ByteSpan(&tag_epoch, 1));
    Writer w;
    w.u64(config_.epoch.value);
    hasher.update(w.span());
  }
  const auto hash_records = [&hasher](std::uint8_t tag, const auto& map) {
    const Byte t = tag;
    hasher.update(ByteSpan(&t, 1));
    for (const auto& entry : map) {
      Writer w;
      w.id128(entry.first);
      encode(w, entry.second);
      hasher.update(w.span());
    }
  };
  hash_records(3, sites_);
  hash_records(4, paths_);
  hash_records(5, domains_);
  hash_records(6, attestations_);
  hash_records(7, grants_);
  hash_records(8, verifications_);
  hash_records(9, oversubscriptions_);
  Writer tail;
  tail.u64(last_arbitration_.value);
  hasher.update(tail.span());
  return hasher.finish();
}

AuthoritySnapshot Authority::snapshot() const {
  AuthoritySnapshot out;
  out.epoch = config_.epoch;
  out.incarnation = config_.incarnation;
  out.policy = config_.policy;
  out.sites = sites();
  out.paths = paths();
  out.domains = domains();
  out.attestations = attestations();
  out.grants = grants();
  out.verifications = verifications();
  out.oversubscriptions = oversubscriptions();
  out.last_arbitration = last_arbitration_;
  return out;
}

// ---------------------------------------------------------------------------
// Change construction
// ---------------------------------------------------------------------------

StateChange Authority::change_for(const GrantRecord& grant, bool releases) const {
  StateChange change;
  change.kind = ObjectKind::Grant;
  change.key = grant.id.raw();
  change.releases_capacity = releases;
  Writer w;
  encode(w, grant);
  change.image.assign(w.buffer().begin(), w.buffer().end());
  return change;
}

StateChange Authority::change_for(const SiteRecord& site) const {
  StateChange change;
  change.kind = ObjectKind::Site;
  change.key = site.id.raw();
  Writer w;
  encode(w, site);
  change.image.assign(w.buffer().begin(), w.buffer().end());
  return change;
}

StateChange Authority::change_for(const PathRecord& path) const {
  StateChange change;
  change.kind = ObjectKind::Path;
  change.key = path.id.raw();
  Writer w;
  encode(w, path);
  change.image.assign(w.buffer().begin(), w.buffer().end());
  return change;
}

StateChange Authority::change_for(const Policy& policy) const {
  StateChange change;
  change.kind = ObjectKind::Policy;
  change.key = Id128{};
  Writer w;
  encode(w, policy);
  change.image.assign(w.buffer().begin(), w.buffer().end());
  return change;
}

StateChange Authority::change_for(const CapacityAttestation& attestation) const {
  StateChange change;
  change.kind = ObjectKind::Attestation;
  change.key = attestation.id.raw();
  Writer w;
  encode(w, attestation);
  change.image.assign(w.buffer().begin(), w.buffer().end());
  return change;
}

StateChange Authority::change_for(const OversubscriptionAuthority& authority) const {
  StateChange change;
  change.kind = ObjectKind::Oversubscription;
  change.key = authority.id.raw();
  Writer w;
  encode(w, authority);
  change.image.assign(w.buffer().begin(), w.buffer().end());
  return change;
}

StateChange Authority::change_for(const VerificationRecord& verification) const {
  StateChange change;
  change.kind = ObjectKind::Verification;
  change.key = verification.id.raw();
  Writer w;
  encode(w, verification);
  change.image.assign(w.buffer().begin(), w.buffer().end());
  return change;
}

StateChange Authority::change_for_epoch(Epoch target) const {
  StateChange change;
  change.kind = ObjectKind::Epoch;
  change.key = Id128{};
  Writer w;
  w.u64(target.value);
  change.image.assign(w.buffer().begin(), w.buffer().end());
  return change;
}

GrantId Authority::derive_grant_id(ArbSeq arb, const GrantProposal& proposal) const {
  if (!proposal.grant_id.is_nil()) {
    return proposal.grant_id;
  }
  return GrantId::from_seed(arb.value, proposal.request.raw().hash() ^ proposal.holder.hash());
}

void Authority::append_downgrades(std::vector<StateChange>& out, const std::string& reason,
                                  std::optional<SiteId> site, std::optional<PathId> path,
                                  std::uint64_t now_ms) const {
  for (const auto& entry : grants_) {
    const GrantRecord& grant = entry.second;
    if (site.has_value() && !(grant.binding.holder == *site)) {
      continue;
    }
    if (path.has_value() && !(grant.binding.path == *path)) {
      continue;
    }
    if (grant.state == GrantState::Active) {
      GrantRecord updated = grant;
      updated.state = GrantState::Degraded;
      updated.updated_at_ms = now_ms;
      updated.reason = bounded(reason);
      out.push_back(change_for(updated, false));
    } else if (grant.state == GrantState::Reserved) {
      GrantRecord updated = grant;
      updated.state = GrantState::Withdrawing;
      updated.updated_at_ms = now_ms;
      updated.reason = bounded(reason);
      out.push_back(change_for(updated, false));
    }
  }
}

// ---------------------------------------------------------------------------
// Invariants
// ---------------------------------------------------------------------------

Status Authority::verify_invariants(std::string* explanation) const {
  const auto fail = [explanation](Status status, const std::string& text) {
    if (explanation != nullptr) {
      *explanation = text;
    }
    return status;
  };

  // One pass over the grant table builds every path's totals, so verifying the
  // whole authority stays linear in the number of records.
  std::map<Id128, PathTotals> totals_by_path;
  for (const auto& entry : grants_) {
    const GrantRecord& grant = entry.second;
    if (!holds_capacity(grant.state)) {
      continue;
    }
    PathTotals& totals = totals_by_path[grant.binding.path.raw()];
    if (grant.state == GrantState::Active || grant.state == GrantState::Degraded) {
      totals.committed = saturating_add(totals.committed, grant.amount);
    } else if (grant.state == GrantState::Withdrawing) {
      totals.withdrawing = saturating_add(totals.withdrawing, grant.amount);
    } else if (grant.state == GrantState::Reserved) {
      totals.reserved = saturating_add(totals.reserved, grant.amount);
    }
    if (is_reclaimable(grant.state)) {
      totals.reclaimable = saturating_add(totals.reclaimable, grant.amount);
    }
    if (grant.grant_class == GrantClass::Protected) {
      totals.protected_held = saturating_add(totals.protected_held, grant.amount);
    }
  }
  for (const auto& entry : paths_) {
    const PathRecord& record = entry.second;
    if (record.unavailable > record.authoritative_usable) {
      return fail(Status::Conflicting,
                  "path " + record.id.to_string() + " has unavailable capacity above usable");
    }
    const PathTotals totals =
        totals_by_path.count(record.id.raw()) != 0 ? totals_by_path[record.id.raw()] : PathTotals{};
    CapacityLedger computed;
    computed.authoritative_usable = record.authoritative_usable;
    computed.committed = totals.committed;
    computed.withdrawing = totals.withdrawing;
    computed.reserved = totals.reserved;
    computed.reclaimable = totals.reclaimable;
    const Amount record_floor = protected_floor(record);
    computed.protected_headroom =
        totals.protected_held >= record_floor ? 0 : record_floor - totals.protected_held;
    computed.unavailable = record.unavailable;
    auto ratio = live_oversubscription_bps(record.id, 0);
    computed.authorized_extension =
        oversubscription_extension(record.authoritative_usable, ratio.ok() ? ratio.value() : 0);
    auto basis = computed.basis();
    if (!basis.ok()) {
      return fail(basis.status(), "path totals overflowed");
    }
    auto structural = checked_add(computed.committed, computed.reserved);
    if (!structural.ok()) {
      return fail(structural.status(), "path totals overflowed");
    }
    structural = checked_add(structural.value(), computed.protected_headroom);
    if (!structural.ok()) {
      return fail(structural.status(), "path totals overflowed");
    }
    structural = checked_add(structural.value(), computed.unavailable);
    if (!structural.ok()) {
      return fail(structural.status(), "path totals overflowed");
    }
    if (structural.value() <= basis.value()) {
      computed.free = basis.value() - structural.value();
      computed.oversubscribed = 0;
    } else {
      computed.free = 0;
      computed.oversubscribed = structural.value() - basis.value();
    }
    auto blocked = checked_add(structural.value(), computed.withdrawing);
    if (!blocked.ok()) {
      return fail(blocked.status(), "path totals overflowed");
    }
    blocked = checked_add(blocked.value(), minimum_free(record));
    if (!blocked.ok()) {
      return fail(blocked.status(), "path totals overflowed");
    }
    computed.allocatable = blocked.value() < basis.value() ? basis.value() - blocked.value() : 0;
    const Status closure = computed.verify_closure();
    if (closure != Status::Ok) {
      return fail(closure,
                  "path " + record.id.to_string() + " does not close: " + computed.to_string());
    }
    // Authorised obligations must fit inside the authority ceiling. A shortfall
    // here means capacity was promised that does not exist.
    if (computed.oversubscribed != 0) {
      return fail(Status::Conflicting,
                  "path " + record.id.to_string() + " is oversubscribed by " +
                      std::to_string(computed.oversubscribed) + " units without authority");
    }
    // Protected obligations are never oversubscribed, under any circumstances.
    if (totals.protected_held > record_floor) {
      return fail(Status::Conflicting,
                  "path " + record.id.to_string() +
                      " has protected obligations above the policy protected floor");
    }
  }

  std::map<Id128, GrantId> lease_owners;
  std::map<std::uint64_t, GrantId> arb_owners;
  for (const auto& entry : grants_) {
    const GrantRecord& grant = entry.second;
    if (grant.id.is_nil()) {
      return fail(Status::Corrupt, "grant with nil identity present");
    }
    if (grant.arbitration.value == 0) {
      return fail(Status::Corrupt, "grant " + grant.id.to_string() + " has no arbitration sequence");
    }
    // The grant table is ordered by identity, not by arbitration, so the only
    // ordering property that can be checked here is that no arbitration
    // sequence exceeds the highest one the authority has issued.
    if (grant.arbitration.value > last_arbitration_.value && last_arbitration_.value != 0) {
      return fail(Status::Conflicting, "grant " + grant.id.to_string() +
                                           " carries an arbitration sequence the authority "
                                           "has not issued");
    }
    const auto arb_insert = arb_owners.emplace(grant.arbitration.value, grant.id);
    if (!arb_insert.second && !(arb_insert.first->second == grant.id)) {
      return fail(Status::Conflicting, "two grants share one arbitration sequence");
    }
    if (!grant.binding.lease.is_nil()) {
      const auto lease_insert = lease_owners.emplace(grant.binding.lease.raw(), grant.id);
      if (!lease_insert.second && !(lease_insert.first->second == grant.id)) {
        return fail(Status::Conflicting, "two grants share one lease identity");
      }
    }
    const auto path_it = paths_.find(grant.binding.path.raw());
    if (path_it == paths_.end()) {
      return fail(Status::Corrupt,
                  "grant " + grant.id.to_string() + " references a path that does not exist");
    }
    const auto site_it = sites_.find(grant.binding.holder.raw());
    if (site_it == sites_.end()) {
      return fail(Status::Corrupt,
                  "grant " + grant.id.to_string() + " references a site that does not exist");
    }
    if (requires_current_binding(grant.state)) {
      const SiteRecord& site = site_it->second;
      const PathRecord& path = path_it->second;
      if (grant.binding.epoch.value != config_.epoch.value) {
        return fail(Status::Stale, "live grant bound to a superseded epoch");
      }
      if (!(grant.binding.holder_incarnation == site.incarnation)) {
        return fail(Status::Stale, "live grant bound to a superseded site incarnation");
      }
      if (grant.binding.policy_generation != config_.policy.generation) {
        return fail(Status::Stale, "live grant bound to a superseded policy generation");
      }
      if (grant.binding.path_generation != path.generation) {
        return fail(Status::Stale, "live grant bound to a superseded path generation");
      }
      if (grant.binding.capacity_generation != path.capacity_generation) {
        return fail(Status::Stale, "live grant bound to a superseded capacity generation");
      }
    }
    if (grant.state == GrantState::Active && config_.policy.require_verification_for_active &&
        grant.verification != VerificationState::Verified) {
      return fail(Status::Incomplete, "active grant has no independent verification");
    }
  }

  for (const auto& entry : paths_) {
    const PathRecord& record = entry.second;
    if (!record.shared_risk_domain.is_nil() &&
        domains_.find(record.shared_risk_domain.raw()) == domains_.end()) {
      return fail(Status::Corrupt, "path references a shared risk domain that does not exist");
    }
    if (!record.endpoint_a.is_nil() && sites_.find(record.endpoint_a.raw()) == sites_.end()) {
      return fail(Status::Incomplete, "path endpoint A is not a registered site");
    }
    if (!record.endpoint_b.is_nil() && sites_.find(record.endpoint_b.raw()) == sites_.end()) {
      return fail(Status::Incomplete, "path endpoint B is not a registered site");
    }
  }

  if (config_.policy.validate() != Status::Ok) {
    return fail(Status::Invalid, "installed policy is not structurally valid");
  }
  if (sites_.size() > config_.max_sites || paths_.size() > config_.max_paths ||
      grants_.size() > config_.max_grants || domains_.size() > config_.max_domains ||
      attestations_.size() > config_.max_attestations ||
      verifications_.size() > config_.max_verifications ||
      oversubscriptions_.size() > config_.max_oversubscriptions) {
    return fail(Status::LimitExceeded, "authority exceeded a configured container bound");
  }
  return Status::Ok;
}

// ---------------------------------------------------------------------------
// Apply
// ---------------------------------------------------------------------------

Status Authority::apply(const std::vector<StateChange>& changes, ArbSeq arb) {
  // Decode everything first: an undecodable change set must not partially apply.
  struct Decoded {
    StateChange change;
    SiteRecord site{};
    PathRecord path{};
    SharedRiskDomain domain{};
    CapacityAttestation attestation{};
    GrantRecord grant{};
    VerificationRecord verification{};
    OversubscriptionAuthority oversubscription{};
    Policy policy{};
    std::uint64_t epoch{0};
  };
  std::vector<Decoded> decoded;
  decoded.reserve(changes.size());
  const WireLimits limits{16U << 20, 4096, 65536, 8};
  for (const auto& change : changes) {
    Decoded item;
    item.change = change;
    Reader reader(ByteSpan(change.image.data(), change.image.size()), limits);
    switch (change.kind) {
      case ObjectKind::Site: {
        auto value = decode_site(reader);
        if (!value.ok()) return Status::Corrupt;
        item.site = value.value();
        if (!(item.site.id.raw() == change.key)) return Status::Conflicting;
        break;
      }
      case ObjectKind::Path: {
        auto value = decode_path(reader);
        if (!value.ok()) return Status::Corrupt;
        item.path = value.value();
        if (!(item.path.id.raw() == change.key)) return Status::Conflicting;
        break;
      }
      case ObjectKind::Domain: {
        auto value = decode_domain(reader);
        if (!value.ok()) return Status::Corrupt;
        item.domain = value.value();
        if (!(item.domain.id.raw() == change.key)) return Status::Conflicting;
        break;
      }
      case ObjectKind::Attestation: {
        auto value = decode_attestation(reader);
        if (!value.ok()) return Status::Corrupt;
        item.attestation = value.value();
        if (!(item.attestation.id.raw() == change.key)) return Status::Conflicting;
        break;
      }
      case ObjectKind::Grant: {
        auto value = decode_grant(reader);
        if (!value.ok()) return Status::Corrupt;
        item.grant = value.value();
        if (!(item.grant.id.raw() == change.key)) return Status::Conflicting;
        break;
      }
      case ObjectKind::Verification: {
        auto value = decode_verification(reader);
        if (!value.ok()) return Status::Corrupt;
        item.verification = value.value();
        if (!(item.verification.id.raw() == change.key)) return Status::Conflicting;
        break;
      }
      case ObjectKind::Oversubscription: {
        auto value = decode_oversubscription(reader);
        if (!value.ok()) return Status::Corrupt;
        item.oversubscription = value.value();
        if (!(item.oversubscription.id.raw() == change.key)) return Status::Conflicting;
        break;
      }
      case ObjectKind::Policy: {
        auto value = decode_policy(reader);
        if (!value.ok()) return Status::Corrupt;
        item.policy = value.value();
        break;
      }
      case ObjectKind::Epoch: {
        auto value = reader.u64();
        if (!value.ok()) return Status::Corrupt;
        item.epoch = value.value();
        break;
      }
      case ObjectKind::AuthorityMeta: {
        break;
      }
    }
    if (reader.require_end() != Status::Ok) {
      return Status::Corrupt;
    }
    decoded.push_back(std::move(item));
  }

  for (auto& item : decoded) {
    switch (item.change.kind) {
      case ObjectKind::Site: {
        if (sites_.size() >= config_.max_sites &&
            sites_.find(item.change.key) == sites_.end()) {
          return Status::LimitExceeded;
        }
        sites_[item.change.key] = item.site;
        break;
      }
      case ObjectKind::Path: {
        if (paths_.size() >= config_.max_paths && paths_.find(item.change.key) == paths_.end()) {
          return Status::LimitExceeded;
        }
        paths_[item.change.key] = item.path;
        break;
      }
      case ObjectKind::Domain: {
        if (domains_.size() >= config_.max_domains &&
            domains_.find(item.change.key) == domains_.end()) {
          return Status::LimitExceeded;
        }
        domains_[item.change.key] = item.domain;
        break;
      }
      case ObjectKind::Attestation: {
        if (attestations_.size() >= config_.max_attestations &&
            attestations_.find(item.change.key) == attestations_.end()) {
          return Status::LimitExceeded;
        }
        attestations_[item.change.key] = item.attestation;
        break;
      }
      case ObjectKind::Grant: {
        if (grants_.size() >= config_.max_grants && grants_.find(item.change.key) == grants_.end()) {
          return Status::LimitExceeded;
        }
        if (!item.grant.request.is_nil()) {
          const auto existing = request_index_.find(item.grant.request.raw());
          if (existing != request_index_.end() && !(existing->second == item.change.key)) {
            return Status::Duplicate;
          }
          request_index_[item.grant.request.raw()] = item.change.key;
        }
        grants_[item.change.key] = item.grant;
        break;
      }
      case ObjectKind::Verification: {
        if (verifications_.size() >= config_.max_verifications &&
            verifications_.find(item.change.key) == verifications_.end()) {
          return Status::LimitExceeded;
        }
        verifications_[item.change.key] = item.verification;
        break;
      }
      case ObjectKind::Oversubscription: {
        if (oversubscriptions_.size() >= config_.max_oversubscriptions &&
            oversubscriptions_.find(item.change.key) == oversubscriptions_.end()) {
          return Status::LimitExceeded;
        }
        oversubscriptions_[item.change.key] = item.oversubscription;
        break;
      }
      case ObjectKind::Policy: {
        if (item.policy.validate() != Status::Ok) {
          return Status::Invalid;
        }
        config_.policy = item.policy;
        break;
      }
      case ObjectKind::Epoch: {
        if (item.epoch == 0) {
          return Status::Invalid;
        }
        config_.epoch = Epoch{item.epoch};
        break;
      }
      case ObjectKind::AuthorityMeta: {
        break;
      }
    }
  }
  if (arb.value > last_arbitration_.value) {
    last_arbitration_ = arb;
  }
  return Status::Ok;
}

void Authority::note_recovered_arbitration(ArbSeq arb) {
  if (arb.value > last_arbitration_.value) {
    last_arbitration_ = arb;
  }
}

Status Authority::mark_recovered(GrantId grant, Provenance provenance, bool ambiguous,
                                 const std::string& reason) {
  const auto it = grants_.find(grant.raw());
  if (it == grants_.end()) {
    return Status::NotFound;
  }
  GrantRecord& record = it->second;
  record.provenance = provenance;
  record.historical = true;
  record.ambiguous = ambiguous;
  if (!reason.empty()) {
    record.reason = bounded(reason);
  }
  // Recovered dynamic evidence is never silently fresh.
  record.verification = VerificationState::Unverified;
  return Status::Ok;
}

Status Authority::mark_all_historical() {
  for (auto& entry : grants_) {
    GrantRecord& record = entry.second;
    if (is_terminal(record.state)) {
      continue;
    }
    record.historical = true;
  }
  return Status::Ok;
}

// ---------------------------------------------------------------------------
// Binding validation
// ---------------------------------------------------------------------------

Status Authority::check_binding(const GrantRecord& grant, const GrantOperation& op) const {
  if (!op.actor.is_nil() && !(op.actor == grant.binding.holder)) {
    return Status::Denied;
  }
  if (!op.lease.is_nil() && !(op.lease == grant.binding.lease)) {
    return Status::Stale;
  }
  const auto site_it = sites_.find(grant.binding.holder.raw());
  if (site_it == sites_.end()) {
    return Status::NotFound;
  }
  const auto path_it = paths_.find(grant.binding.path.raw());
  if (path_it == paths_.end()) {
    return Status::NotFound;
  }
  const SiteRecord& site = site_it->second;
  const PathRecord& path = path_it->second;

  if (!op.actor_incarnation.is_nil() && !(op.actor_incarnation == site.incarnation)) {
    return Status::Fenced;
  }
  if (op.epoch.value != 0 && op.epoch.value != config_.epoch.value) {
    return Status::Stale;
  }
  if (!op.path_generation.is_nil() && !(op.path_generation == path.generation)) {
    return Status::Stale;
  }
  if (!op.capacity_generation.is_nil() && !(op.capacity_generation == path.capacity_generation)) {
    return Status::Stale;
  }
  if (!op.policy_generation.is_nil() && !(op.policy_generation == config_.policy.generation)) {
    return Status::Stale;
  }

  // Dependency invalidation: a live grant whose recorded dependencies no longer
  // match current state cannot be advanced.
  if (requires_current_binding(grant.state)) {
    if (grant.binding.epoch.value != config_.epoch.value) {
      return Status::Stale;
    }
    if (!(grant.binding.holder_incarnation == site.incarnation)) {
      return Status::Fenced;
    }
    if (grant.binding.policy_generation != config_.policy.generation) {
      return Status::Stale;
    }
    if (grant.binding.path_generation != path.generation) {
      return Status::Stale;
    }
    if (grant.binding.capacity_generation != path.capacity_generation) {
      return Status::Stale;
    }
  }
  if (grant.ambiguous && grant.state != GrantState::Withdrawing &&
      !(op.reason == "reconcile")) {
    return Status::Indeterminate;
  }
  return Status::Ok;
}

Expected<GrantRecord> Authority::require_grant(GrantId id) const {
  const auto it = grants_.find(id.raw());
  if (it == grants_.end()) {
    return Outcome(Status::NotFound, "no such grant");
  }
  return it->second;
}

Expected<SiteRecord> Authority::require_site(SiteId id) const {
  const auto it = sites_.find(id.raw());
  if (it == sites_.end()) {
    return Outcome(Status::NotFound, "no such site");
  }
  return it->second;
}

Expected<PathRecord> Authority::require_path(PathId id) const {
  const auto it = paths_.find(id.raw());
  if (it == paths_.end()) {
    return Outcome(Status::NotFound, "no such path");
  }
  return it->second;
}

std::string describe_grant(const GrantRecord& grant) {
  std::string out = grant.id.to_string();
  out += " ";
  out += grant_state_name(grant.state);
  out += " amount=";
  out += std::to_string(grant.amount);
  out += " class=";
  out += grant_class_name(grant.grant_class);
  out += " arb=";
  out += grant.arbitration.to_string();
  if (grant.ambiguous) {
    out += " AMBIGUOUS";
  }
  if (grant.historical) {
    out += " HISTORICAL";
  }
  return out;
}

}  // namespace isf