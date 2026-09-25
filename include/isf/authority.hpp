// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// The capacity authority: the deterministic state machine that decides which
// site-to-site connectivity is legal now, how much capacity is authoritative,
// and when it must be reduced, fenced, or refused.
//
// The authority performs no I/O, takes no locks, and reads no clock. Time is a
// parameter. Every mutation is a two-stage "plan then apply" pair so that a
// caller can durably record the intended post-images (write-ahead) before they
// take effect in memory. Applying a plan is a pure insertion of encoded record
// post-images, which makes replay and recovery share one code path with the
// live mutation path.

#ifndef ISF_AUTHORITY_HPP
#define ISF_AUTHORITY_HPP

#include "isf/capacity.hpp"
#include "isf/digest.hpp"
#include "isf/ids.hpp"
#include "isf/model.hpp"
#include "isf/policy.hpp"
#include "isf/status.hpp"

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace isf {

/// Kinds of object that can appear in a state change.
enum class ObjectKind : std::uint8_t {
  Site = 1,
  Path = 2,
  Domain = 3,
  Attestation = 4,
  Grant = 5,
  Verification = 6,
  Oversubscription = 7,
  Policy = 8,
  Epoch = 9,
  AuthorityMeta = 10,
};

[[nodiscard]] const char* object_kind_name(ObjectKind k) noexcept;

/// A single object post-image. During replay a change is applied by decoding the
/// image and inserting it into the map named by kind.
struct StateChange {
  ObjectKind kind{ObjectKind::Grant};
  Id128 key{};
  std::vector<Byte> image{};
  /// True when applying this change strictly reduces held capacity. A durable
  /// intent carrying a releasing change is *not* applied when its completion
  /// record is missing: capacity is only ever released by a provably complete
  /// transaction.
  bool releases_capacity{false};
};

/// Encoders/decoders for a raw state change payload.
void encode(Writer& w, const StateChange& v);
[[nodiscard]] Expected<StateChange> decode_state_change(Reader& r);

/// One authority mutation, as a set of object post-images.
struct Mutation {
  std::vector<StateChange> changes{};
  std::string summary{};
  /// Arbitration sequence assigned to this mutation. Assigned by the caller's
  /// commit pipeline; the authority stores it in the resulting grant records.
  ArbSeq arbitration{};
};

using MutationResult = Expected<Mutation>;

/// Static configuration of one authority instance.
struct AuthorityConfig {
  Policy policy{Policy::conservative_default()};
  Epoch epoch{1};
  Incarnation incarnation{Incarnation::random()};
  std::size_t max_sites{4096};
  std::size_t max_paths{65536};
  std::size_t max_domains{4096};
  std::size_t max_grants{1U << 20};
  std::size_t max_attestations{1U << 16};
  std::size_t max_verifications{1U << 20};
  std::size_t max_oversubscriptions{4096};
};

/// Registration of a site by its agent.
struct SiteRegistration {
  SiteDescriptor descriptor{};
  Incarnation incarnation{};
  Epoch epoch{};
  std::uint64_t now_ms{0};
};

/// A periodic liveness signal from a site agent.
struct SiteHeartbeat {
  SiteId id{};
  Incarnation incarnation{};
  Generation generation{};
  Epoch epoch{};
  Amount advertised_capacity{0};
  std::uint64_t now_ms{0};
};

/// Registration of an inter-site path.
struct PathRegistration {
  PathDescriptor descriptor{};
  Generation path_generation{};
  PathState state{PathState::Up};
  Amount advertised{0};
  Amount observed{0};
  std::uint64_t now_ms{0};
};

/// A request to consider a new grant.
struct GrantProposal {
  RequestId request{};
  SiteId holder{};
  Incarnation holder_incarnation{};
  Generation holder_generation{};
  PathId path{};
  Amount amount{0};
  GrantClass grant_class{GrantClass::General};
  std::uint64_t duration_ms{0};
  std::uint64_t now_ms{0};
  std::string reason{};
  /// Optional caller supplied grant identity. When nil the authority derives one
  /// deterministically from the arbitration sequence.
  GrantId grant_id{};
  LeaseId lease{};
};

/// A reference to an existing grant plus the caller's claimed binding.
struct GrantOperation {
  GrantId grant{};
  RequestId request{};
  SiteId actor{};
  Incarnation actor_incarnation{};
  Generation actor_generation{};
  Epoch epoch{};
  Generation path_generation{};
  Generation capacity_generation{};
  Generation policy_generation{};
  LeaseId lease{};
  std::uint64_t now_ms{0};
  std::string reason{};
};

/// Acknowledgement that a holder has received a grant. Acknowledgement is a
/// claim by the holder; it is not evidence that connectivity works.
struct GrantAcknowledgement {
  GrantId grant{};
  SiteId actor{};
  Incarnation actor_incarnation{};
  Epoch epoch{};
  std::uint64_t now_ms{0};
};

/// Independent verification of a grant's connectivity.
struct GrantVerification {
  VerificationId id{};
  GrantId grant{};
  PrincipalId verifier{};
  VerificationState result{VerificationState::Unverified};
  Digest256 evidence{};
  std::uint64_t now_ms{0};
  std::string detail{};
};

/// A complete dump of authoritative state, used for snapshots and for
/// differential comparison against an independent reference model.
struct AuthoritySnapshot {
  Epoch epoch{};
  Incarnation incarnation{};
  Policy policy{};
  std::vector<SiteRecord> sites{};
  std::vector<PathRecord> paths{};
  std::vector<SharedRiskDomain> domains{};
  std::vector<CapacityAttestation> attestations{};
  std::vector<GrantRecord> grants{};
  std::vector<VerificationRecord> verifications{};
  std::vector<OversubscriptionAuthority> oversubscriptions{};
  ArbSeq last_arbitration{};
};

void encode(Writer& w, const AuthoritySnapshot& v);
[[nodiscard]] Expected<AuthoritySnapshot> decode_snapshot(Reader& r);

/// The deterministic capacity authority.
class Authority {
 public:
  explicit Authority(AuthorityConfig config);

  // ---- introspection -----------------------------------------------------

  [[nodiscard]] const Policy& policy() const noexcept { return config_.policy; }
  [[nodiscard]] Epoch epoch() const noexcept { return config_.epoch; }
  [[nodiscard]] Incarnation incarnation() const noexcept { return config_.incarnation; }
  [[nodiscard]] ArbSeq last_arbitration() const noexcept { return last_arbitration_; }
  [[nodiscard]] const AuthorityConfig& config() const noexcept { return config_; }

  [[nodiscard]] std::optional<SiteRecord> find_site(SiteId id) const;
  [[nodiscard]] std::optional<PathRecord> find_path(PathId id) const;
  [[nodiscard]] std::optional<GrantRecord> find_grant(GrantId id) const;
  [[nodiscard]] std::optional<CapacityAttestation> find_attestation(AttestationId id) const;
  [[nodiscard]] std::optional<OversubscriptionAuthority> find_oversubscription(
      OversubscriptionId id) const;

  [[nodiscard]] std::vector<SiteRecord> sites() const;
  [[nodiscard]] std::vector<PathRecord> paths() const;
  [[nodiscard]] std::vector<SharedRiskDomain> domains() const;
  [[nodiscard]] std::vector<GrantRecord> grants() const;
  [[nodiscard]] std::vector<CapacityAttestation> attestations() const;
  [[nodiscard]] std::vector<VerificationRecord> verifications() const;
  [[nodiscard]] std::vector<OversubscriptionAuthority> oversubscriptions() const;
  [[nodiscard]] std::vector<GrantRecord> grants_for_path(PathId path) const;
  [[nodiscard]] std::vector<GrantRecord> grants_for_site(SiteId site) const;

  /// Derived ledger for one path.
  [[nodiscard]] Expected<CapacityLedger> ledger(PathId path) const;

  /// Aggregate ledger across every path.
  [[nodiscard]] CapacityLedger aggregate_ledger() const;

  /// Canonical digest of all authoritative state. Two authorities that have
  /// applied the same changes in the same order have the same digest.
  [[nodiscard]] Digest256 state_digest() const;

  /// Full state image.
  [[nodiscard]] AuthoritySnapshot snapshot() const;

  /// Rebuild an authority from a snapshot. The config supplies incarnation,
  /// epoch, and limits; recovered records keep their recorded provenance and are
  /// marked historical unless they are already terminal.
  static Expected<Authority> from_snapshot(AuthorityConfig config, const AuthoritySnapshot& snapshot);

  /// Verify every structural invariant. Returns Status::Ok, or the first
  /// violation with an explanation.
  [[nodiscard]] Status verify_invariants(std::string* explanation) const;

  /// Validate a caller supplied binding against live state for an existing
  /// grant, without planning any mutation. Exposed so operators and tests can
  /// ask whether an operation would be accepted, without side effects.
  [[nodiscard]] Status check_binding(const GrantRecord& grant, const GrantOperation& op) const;

  // ---- mutation planning -------------------------------------------------
  //
  // Each plan_* method computes post-images from the current state without
  // modifying it. The caller persists the plan, then calls apply().

  [[nodiscard]] MutationResult plan_install_policy(const Policy& policy, PrincipalId principal,
                                                   ArbSeq arb);
  [[nodiscard]] MutationResult plan_bump_epoch(Epoch epoch, PrincipalId principal, ArbSeq arb);
  [[nodiscard]] MutationResult plan_register_site(const SiteRegistration& registration, ArbSeq arb);
  [[nodiscard]] MutationResult plan_heartbeat(const SiteHeartbeat& heartbeat, ArbSeq arb);
  [[nodiscard]] MutationResult plan_set_site_state(SiteId site, SiteState state,
                                                   const std::string& reason, std::uint64_t now_ms,
                                                   ArbSeq arb);
  [[nodiscard]] MutationResult plan_register_path(const PathRegistration& registration, ArbSeq arb);
  [[nodiscard]] MutationResult plan_set_path_state(PathId path, PathState state,
                                                   const std::string& reason, std::uint64_t now_ms,
                                                   ArbSeq arb);
  [[nodiscard]] MutationResult plan_attest_capacity(const CapacityAttestation& attestation,
                                                    ArbSeq arb);
  [[nodiscard]] MutationResult plan_issue_oversubscription(const OversubscriptionAuthority& authority,
                                                           ArbSeq arb);
  [[nodiscard]] MutationResult plan_propose_grant(const GrantProposal& proposal, ArbSeq arb);
  [[nodiscard]] MutationResult plan_evaluate_grant(const GrantOperation& op, ArbSeq arb);
  [[nodiscard]] MutationResult plan_reserve_grant(const GrantOperation& op, ArbSeq arb);
  [[nodiscard]] MutationResult plan_activate_grant(const GrantOperation& op, ArbSeq arb);
  [[nodiscard]] MutationResult plan_degrade_grant(const GrantOperation& op, ArbSeq arb);
  [[nodiscard]] MutationResult plan_withdraw_grant(const GrantOperation& op, ArbSeq arb);
  [[nodiscard]] MutationResult plan_retire_grant(const GrantOperation& op, ArbSeq arb);
  [[nodiscard]] MutationResult plan_cancel_grant(const GrantOperation& op, ArbSeq arb);
  [[nodiscard]] MutationResult plan_acknowledge_grant(const GrantAcknowledgement& ack, ArbSeq arb);
  [[nodiscard]] MutationResult plan_verify_grant(const GrantVerification& verification, ArbSeq arb);
  [[nodiscard]] MutationResult plan_reconcile_grant(const GrantOperation& op, GrantState target,
                                                    PrincipalId principal, ArbSeq arb);
  [[nodiscard]] MutationResult plan_tick(std::uint64_t now_ms, ArbSeq arb);

  /// Apply a change set to authoritative state. Decoding is expected to succeed;
  /// a failure means the caller passed a change set it did not obtain from a
  /// plan_* method and yields Status::Corrupt without partially applying.
  [[nodiscard]] Status apply(const std::vector<StateChange>& changes, ArbSeq arb);

  /// Reconcile a change set's effect on arbitration bookkeeping during replay.
  void note_recovered_arbitration(ArbSeq arb);

  /// Mark an applied grant as conservatively recovered.
  [[nodiscard]] Status mark_recovered(GrantId grant, Provenance provenance, bool ambiguous,
                                      const std::string& reason);

  /// Mark every non-terminal grant whose binding does not match the current
  /// incarnation as historical. Called once at start-up.
  [[nodiscard]] Status mark_all_historical();

 private:
  [[nodiscard]] Expected<GrantRecord> require_grant(GrantId id) const;
  [[nodiscard]] Expected<SiteRecord> require_site(SiteId id) const;
  [[nodiscard]] Expected<PathRecord> require_path(PathId id) const;

  /// Build the post-image change for a grant.
  [[nodiscard]] StateChange change_for(const GrantRecord& grant, bool releases) const;
  [[nodiscard]] StateChange change_for(const SiteRecord& site) const;
  [[nodiscard]] StateChange change_for(const PathRecord& path) const;
  [[nodiscard]] StateChange change_for(const Policy& policy) const;
  [[nodiscard]] StateChange change_for(const CapacityAttestation& attestation) const;
  [[nodiscard]] StateChange change_for(const OversubscriptionAuthority& authority) const;
  [[nodiscard]] StateChange change_for(const VerificationRecord& verification) const;
  [[nodiscard]] StateChange change_for_epoch(Epoch target) const;

  /// Bucket totals used to derive a ledger.
  struct PathTotals {
    Amount committed{0};     ///< grants in ACTIVE or DEGRADED
    Amount withdrawing{0};   ///< grants in WITHDRAWING
    Amount reserved{0};      ///< grants in RESERVED
    Amount reclaimable{0};
    Amount protected_held{0};
  };
  [[nodiscard]] PathTotals totals_for(PathId path) const;

  /// Capacity available for a new allocation of the given class.
  [[nodiscard]] Expected<Amount> allocatable(PathId path, GrantClass klass, std::uint64_t now_ms) const;

  /// Effective protected floor for a path under the current policy, capped by
  /// the capacity that actually exists on the path. Capacity that is
  /// unavailable cannot be protected.
  [[nodiscard]] Amount protected_floor(const PathRecord& path) const;

  /// Effective minimum free headroom for a path, capped the same way.
  [[nodiscard]] Amount minimum_free(const PathRecord& path) const;

  /// True when a live oversubscription authority permits this path to overbook.
  [[nodiscard]] Expected<std::uint32_t> live_oversubscription_bps(PathId path,
                                                                  std::uint64_t now_ms) const;

  /// Emit conservative downgrades for every live grant of a site or path.
  void append_downgrades(std::vector<StateChange>& out, const std::string& reason,
                         std::optional<SiteId> site, std::optional<PathId> path,
                         std::uint64_t now_ms) const;

  [[nodiscard]] GrantId derive_grant_id(ArbSeq arb, const GrantProposal& proposal) const;

  /// Re-bind or withdraw the grants of a path after a policy, capacity, or path
  /// generation change. Grants are withdrawn in descending arbitration order so
  /// the outcome is a deterministic function of the request order, and
  /// protected obligations are released last.
  void rebalance_path(std::vector<StateChange>& out, const PathRecord& path, const Policy& policy,
                      std::uint64_t now_ms, const std::string& reason, bool rebind_policy,
                      bool rebind_path_capacity) const;

  AuthorityConfig config_{};
  ArbSeq last_arbitration_{};

  std::map<Id128, SiteRecord> sites_{};
  std::map<Id128, PathRecord> paths_{};
  std::map<Id128, SharedRiskDomain> domains_{};
  std::map<Id128, CapacityAttestation> attestations_{};
  std::map<Id128, GrantRecord> grants_{};
  std::map<Id128, VerificationRecord> verifications_{};
  std::map<Id128, OversubscriptionAuthority> oversubscriptions_{};
  /// Request identity -> grant identity, so a replayed or duplicated proposal
  /// is detected instead of creating a second grant for one request.
  std::map<Id128, Id128> request_index_{};
};

/// Encode a snapshot's policy generation for human readable diagnostics.
[[nodiscard]] std::string describe_grant(const GrantRecord& grant);

}  // namespace isf

#endif  // ISF_AUTHORITY_HPP
