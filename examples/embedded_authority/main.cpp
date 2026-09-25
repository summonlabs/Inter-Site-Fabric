// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Embedded authority example.
//
// This program links only against the library and drives the capacity authority
// entirely in process. There is no daemon, no socket, and no persistence: it
// shows the deterministic core in isolation.

#include "isf/authority.hpp"
#include "isf/clock.hpp"
#include "isf/digest.hpp"

#include <cstdio>
#include <string>

namespace {

using namespace isf;

int fail(const char* what, const Status status) {
  std::fprintf(stderr, "%s: %s\n", what, status_name(status));
  return 1;
}

}  // namespace

int main() {
  const std::uint64_t now = now_ms();

  AuthorityConfig config;
  config.incarnation = Incarnation::from_seed(0x15F0, 1);
  config.policy = Policy::conservative_default();
  config.policy.protected_floor_bps = 1000;  // keep 10% out of general allocation
  Authority authority(config);

  const SiteId site_a = SiteId::from_seed(1, 1);
  const SiteId site_b = SiteId::from_seed(2, 2);
  const Incarnation incarnation_a = Incarnation::from_seed(3, 3);
  const PathId path = PathId::from_seed(4, 4);

  std::uint64_t arbitration = 0;
  const auto apply = [&](MutationResult result) -> Status {
    if (!result.ok()) {
      return result.status();
    }
    return authority.apply(result.value().changes, ArbSeq{arbitration});
  };

  SiteRegistration registration;
  registration.descriptor.id = site_a;
  registration.descriptor.name = "site-a";
  registration.incarnation = incarnation_a;
  registration.epoch = authority.epoch();
  registration.now_ms = now;
  ++arbitration;
  if (apply(authority.plan_register_site(registration, ArbSeq{arbitration})) != Status::Ok) {
    return fail("site A registration failed", Status::Corrupt);
  }
  registration.descriptor.id = site_b;
  registration.descriptor.name = "site-b";
  registration.incarnation = Incarnation::from_seed(5, 5);
  ++arbitration;
  if (apply(authority.plan_register_site(registration, ArbSeq{arbitration})) != Status::Ok) {
    return fail("site B registration failed", Status::Corrupt);
  }

  PathRegistration path_registration;
  path_registration.descriptor.id = path;
  path_registration.descriptor.name = "a-to-b";
  path_registration.descriptor.endpoint_a = site_a;
  path_registration.descriptor.endpoint_b = site_b;
  path_registration.path_generation = Generation{1};
  path_registration.state = PathState::Up;
  path_registration.advertised = 10000;
  path_registration.now_ms = now;
  ++arbitration;
  if (apply(authority.plan_register_path(path_registration, ArbSeq{arbitration})) != Status::Ok) {
    return fail("path registration failed", Status::Corrupt);
  }
  const auto registered_path = authority.find_path(path);
  if (!registered_path.has_value()) {
    return fail("registered path is missing", Status::Corrupt);
  }

  // Advertised capacity is not authoritative capacity. Until an attestation
  // arrives, nothing can be committed against this path.
  std::printf("after registration: usable=%llu (advertised=%llu)\n",
              static_cast<unsigned long long>(registered_path->authoritative_usable),
              static_cast<unsigned long long>(registered_path->advertised));

  CapacityAttestation attestation;
  attestation.id = AttestationId::from_seed(6, 6);
  attestation.path = path;
  attestation.path_generation = registered_path->generation;
  attestation.capacity_generation = Generation{1};
  attestation.usable = 10000;
  attestation.advertised = 10000;
  attestation.observed = 9800;
  attestation.issuer = authority.incarnation();
  attestation.epoch = authority.epoch();
  attestation.principal = PrincipalId::from_seed(7, 7);
  attestation.observed_at_ms = now;
  attestation.evidence = Digest256::of(ByteSpan{});
  attestation.source = "embedded-example";
  ++arbitration;
  if (apply(authority.plan_attest_capacity(attestation, ArbSeq{arbitration})) != Status::Ok) {
    return fail("capacity attestation failed", Status::Corrupt);
  }

  const auto print_ledger = [&](const char* label) {
    auto ledger = authority.ledger(path);
    if (!ledger.ok()) {
      std::printf("%-22s ledger unavailable: %s\n", label, ledger.detail().c_str());
      return;
    }
    std::printf("%-22s %s closure=%s\n", label, ledger.value().to_string().c_str(),
                status_name(ledger.value().verify_closure()));
  };
  print_ledger("attested:");

  GrantProposal proposal;
  proposal.request = RequestId::from_seed(8, 8);
  proposal.holder = site_a;
  proposal.holder_incarnation = incarnation_a;
  proposal.path = path;
  proposal.amount = 6000;
  proposal.duration_ms = 3600000;
  proposal.now_ms = now;

  ++arbitration;
  auto proposed = authority.plan_propose_grant(proposal, ArbSeq{arbitration});
  if (!proposed.ok()) {
    return fail("proposal failed", proposed.status());
  }
  const GrantId grant_id = GrantId::from_raw(proposed.value().changes.front().key);
  if (apply(std::move(proposed)) != Status::Ok) {
    return fail("proposal could not be applied", Status::Corrupt);
  }

  GrantOperation op;
  op.grant = grant_id;
  op.actor = site_a;
  op.actor_incarnation = incarnation_a;
  op.epoch = authority.epoch();
  op.now_ms = now;

  ++arbitration;
  if (apply(authority.plan_evaluate_grant(op, ArbSeq{arbitration})) != Status::Ok) {
    return fail("evaluation failed", Status::Corrupt);
  }
  ++arbitration;
  if (apply(authority.plan_reserve_grant(op, ArbSeq{arbitration})) != Status::Ok) {
    return fail("reservation failed", Status::Corrupt);
  }
  print_ledger("reserved:");
  ++arbitration;
  if (apply(authority.plan_activate_grant(op, ArbSeq{arbitration})) != Status::Ok) {
    return fail("activation failed", Status::Corrupt);
  }
  std::printf("grant %s state=%s\n", grant_id.to_string().c_str(),
              grant_state_name(authority.find_grant(grant_id)->state));
  print_ledger("active:");

  // A second request beyond the remaining headroom is refused, not accepted
  // with a wrapped total.
  GrantProposal oversize = proposal;
  oversize.request = RequestId::from_seed(9, 9);
  oversize.amount = 100000;
  ++arbitration;
  auto second = authority.plan_propose_grant(oversize, ArbSeq{arbitration});
  if (!second.ok()) {
    return fail("second proposal failed", second.status());
  }
  const GrantId second_id = GrantId::from_raw(second.value().changes.front().key);
  if (apply(std::move(second)) != Status::Ok) {
    return fail("second proposal could not be applied", Status::Corrupt);
  }
  GrantOperation second_op = op;
  second_op.grant = second_id;
  ++arbitration;
  if (apply(authority.plan_evaluate_grant(second_op, ArbSeq{arbitration})) != Status::Ok) {
    return fail("second evaluation failed", Status::Corrupt);
  }
  ++arbitration;
  auto refused = authority.plan_reserve_grant(second_op, ArbSeq{arbitration});
  std::printf("oversized request: %s\n",
              refused.ok() ? "accepted (unexpected)" : status_name(refused.status()));

  std::string why;
  const Status invariants = authority.verify_invariants(&why);
  std::printf("invariants: %s %s\n", status_name(invariants), why.c_str());
  std::printf("state digest: %s\n", authority.state_digest().to_string().c_str());
  return invariants == Status::Ok ? 0 : 1;
}
