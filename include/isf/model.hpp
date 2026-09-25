// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// The authoritative record types: sites, inter-site paths, shared risk domains,
// capacity attestations, grants, leases, verifications, and oversubscription
// authorities. Every record carries the generations it was created against so
// that dependency invalidation is an explicit comparison rather than a guess.

#ifndef ISF_MODEL_HPP
#define ISF_MODEL_HPP

#include "isf/capacity.hpp"
#include "isf/digest.hpp"
#include "isf/ids.hpp"
#include "isf/lifecycle.hpp"
#include "isf/policy.hpp"
#include "isf/status.hpp"
#include "isf/wire.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace isf {

/// Static description of a physical site, as registered by the site agent.
struct SiteDescriptor {
  SiteId id{};
  std::string name{};
  Amount advertised_capacity{0};
};

/// A site as the authority currently understands it.
struct SiteRecord {
  SiteId id{};
  std::string name{};
  Incarnation incarnation{};
  Generation generation{};
  Epoch epoch{};
  SiteState state{SiteState::Unknown};
  Amount advertised_capacity{0};
  std::uint64_t registered_at_ms{0};
  std::uint64_t last_heartbeat_ms{0};
  std::uint32_t missed_heartbeats{0};
  std::string fence_reason{};
  Provenance provenance{Provenance::Live};
};

/// Static description of an inter-site path.
struct PathDescriptor {
  PathId id{};
  std::string name{};
  EdgeId edge{};
  DomainId shared_risk_domain{};
  SiteId endpoint_a{};
  SiteId endpoint_b{};
};

/// An inter-site path as the authority currently understands it.
struct PathRecord {
  PathId id{};
  std::string name{};
  EdgeId edge{};
  DomainId shared_risk_domain{};
  SiteId endpoint_a{};
  SiteId endpoint_b{};
  Generation generation{};
  Generation capacity_generation{};
  PathState state{PathState::Unknown};
  Amount advertised{0};
  Amount observed{0};
  Amount authoritative_usable{0};
  Amount unavailable{0};
  std::uint64_t updated_at_ms{0};
  Provenance provenance{Provenance::Live};
};

/// A shared risk domain: a set of paths that can fail together.
struct SharedRiskDomain {
  DomainId id{};
  std::string name{};
  std::string description{};
};

/// Evidence that a path really has the capacity the authority will commit
/// against. Advertised and observed numbers alone never become authoritative.
struct CapacityAttestation {
  AttestationId id{};
  PathId path{};
  Generation path_generation{};
  Generation capacity_generation{};
  Amount usable{0};
  Amount advertised{0};
  Amount observed{0};
  Incarnation issuer{};
  Epoch epoch{};
  PrincipalId principal{};
  std::uint64_t observed_at_ms{0};
  Digest256 evidence{};
  std::string source{};
};

/// The exact generations, epoch, incarnation and lease a grant is bound to.
struct GrantBinding {
  SiteId holder{};
  Incarnation holder_incarnation{};
  Generation holder_generation{};
  PathId path{};
  Generation path_generation{};
  Generation capacity_generation{};
  Generation policy_generation{};
  Epoch epoch{};
  LeaseId lease{};

  friend bool operator==(const GrantBinding&, const GrantBinding&) = default;
};

/// What a grant's capacity is for. Protected capacity is never oversubscribed
/// and is released last.
enum class GrantClass : std::uint8_t {
  General = 0,
  Protected,
};

[[nodiscard]] const char* grant_class_name(GrantClass c) noexcept;

/// A capacity grant: the authoritative answer to "may this site use this much
/// capacity on this path, right now".
struct GrantRecord {
  GrantId id{};
  RequestId request{};
  ArbSeq arbitration{};
  GrantBinding binding{};
  GrantClass grant_class{GrantClass::General};
  Amount amount{0};
  GrantState state{GrantState::Proposed};
  VerificationState verification{VerificationState::Unverified};
  bool acknowledged{false};
  std::uint32_t ack_count{0};
  std::uint64_t created_at_ms{0};
  std::uint64_t updated_at_ms{0};
  std::uint64_t expires_at_ms{0};
  std::string reason{};
  Provenance provenance{Provenance::Live};
  bool historical{false};
  bool ambiguous{false};
};

/// An independent verification that connectivity actually works. Verification
/// is a separate act from acknowledgement; a holder acknowledging a grant
/// proves nothing about the path.
struct VerificationRecord {
  VerificationId id{};
  GrantId grant{};
  GrantBinding binding{};
  VerificationState result{VerificationState::Unverified};
  PrincipalId verifier{};
  Digest256 evidence{};
  std::uint64_t at_ms{0};
  std::string detail{};
};

/// Explicit, generation bound permission to overbook a path beyond its
/// authoritative usable capacity. Absent this record, the authority refuses any
/// allocation that would push allocation past usable capacity.
struct OversubscriptionAuthority {
  OversubscriptionId id{};
  PathId path{};
  Generation path_generation{};
  Generation capacity_generation{};
  Generation policy_generation{};
  Epoch epoch{};
  Incarnation issuer{};
  std::uint32_t ratio_bps{0};
  std::uint64_t issued_at_ms{0};
  std::uint64_t not_after_ms{0};
  PrincipalId principal{};

  [[nodiscard]] bool is_live_at(std::uint64_t now_ms) const noexcept {
    return not_after_ms == 0 || now_ms <= not_after_ms;
  }
};

/// Canonical encoders / decoders. The same encoding feeds the store, the wire
/// protocol, and the ledger digest, so there is exactly one byte image of any
/// record.
void encode(Writer& w, const SiteRecord& v);
[[nodiscard]] Expected<SiteRecord> decode_site(Reader& r);

void encode(Writer& w, const PathRecord& v);
[[nodiscard]] Expected<PathRecord> decode_path(Reader& r);

void encode(Writer& w, const SharedRiskDomain& v);
[[nodiscard]] Expected<SharedRiskDomain> decode_domain(Reader& r);

void encode(Writer& w, const CapacityAttestation& v);
[[nodiscard]] Expected<CapacityAttestation> decode_attestation(Reader& r);

void encode(Writer& w, const GrantBinding& v);
[[nodiscard]] Expected<GrantBinding> decode_binding(Reader& r);

void encode(Writer& w, const GrantRecord& v);
[[nodiscard]] Expected<GrantRecord> decode_grant(Reader& r);

void encode(Writer& w, const VerificationRecord& v);
[[nodiscard]] Expected<VerificationRecord> decode_verification(Reader& r);

void encode(Writer& w, const OversubscriptionAuthority& v);
[[nodiscard]] Expected<OversubscriptionAuthority> decode_oversubscription(Reader& r);

void encode(Writer& w, const Policy& v);
[[nodiscard]] Expected<Policy> decode_policy(Reader& r);

}  // namespace isf

#endif  // ISF_MODEL_HPP
