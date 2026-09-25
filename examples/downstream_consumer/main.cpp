// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Independent downstream consumer.
//
// This program is compiled against an installed Inter-Site Fabric prefix and
// exercises the public API only. It deliberately touches every layer of the
// exported interface: the pure authority, the durable store, the framed
// transport, and the client, so that a break in any exported header is caught
// here as well as in the project's own suites.
//
// It exits non-zero on the first failed expectation.

#include "isf/authority.hpp"
#include "isf/client.hpp"
#include "isf/clock.hpp"
#include "isf/daemon.hpp"
#include "isf/digest.hpp"
#include "isf/server.hpp"
#include "isf/store.hpp"

#include <cstdio>
#include <filesystem>
#include <string>

namespace {

using namespace isf;

int g_failures = 0;

void expect(bool condition, const std::string& what) {
  if (!condition) {
    std::printf("FAIL %s\n", what.c_str());
    ++g_failures;
  } else {
    std::printf("ok   %s\n", what.c_str());
  }
}

/// The pure authority, exercised without any I/O.
void exercise_authority() {
  AuthorityConfig config;
  config.incarnation = Incarnation::from_seed(0xC0, 1);
  config.policy = Policy::conservative_default();
  Authority authority(config);

  const SiteId site_a = SiteId::from_seed(1, 1);
  const SiteId site_b = SiteId::from_seed(2, 2);
  const Incarnation incarnation = Incarnation::from_seed(3, 3);
  const PathId path = PathId::from_seed(4, 4);
  const std::uint64_t now = now_ms();
  std::uint64_t arbitration = 0;
  const auto apply = [&](MutationResult result) {
    if (!result.ok()) {
      return false;
    }
    return authority.apply(result.value().changes, ArbSeq{arbitration}) == Status::Ok;
  };

  SiteRegistration registration;
  registration.descriptor.id = site_a;
  registration.descriptor.name = "consumer-a";
  registration.incarnation = incarnation;
  registration.epoch = authority.epoch();
  registration.now_ms = now;
  expect(apply(authority.plan_register_site(registration, ArbSeq{++arbitration})),
         "register site A");
  registration.descriptor.id = site_b;
  registration.descriptor.name = "consumer-b";
  registration.incarnation = Incarnation::from_seed(5, 5);
  expect(apply(authority.plan_register_site(registration, ArbSeq{++arbitration})),
         "register site B");

  PathRegistration path_registration;
  path_registration.descriptor.id = path;
  path_registration.descriptor.name = "consumer-path";
  path_registration.descriptor.endpoint_a = site_a;
  path_registration.descriptor.endpoint_b = site_b;
  path_registration.path_generation = Generation{1};
  path_registration.state = PathState::Up;
  path_registration.now_ms = now;
  expect(apply(authority.plan_register_path(path_registration, ArbSeq{++arbitration})),
         "register path");

  const auto registered = authority.find_path(path);
  expect(registered.has_value(), "path is present after registration");
  if (registered.has_value()) {
    expect(registered->authoritative_usable == 0,
           "a freshly registered path has no authoritative capacity");
  }

  CapacityAttestation attestation;
  attestation.id = AttestationId::from_seed(6, 6);
  attestation.path = path;
  attestation.path_generation = Generation{1};
  attestation.capacity_generation = Generation{1};
  attestation.usable = 1000;
  attestation.advertised = 1000;
  attestation.observed = 1000;
  attestation.issuer = authority.incarnation();
  attestation.epoch = authority.epoch();
  attestation.principal = PrincipalId::from_seed(7, 7);
  attestation.observed_at_ms = now;
  attestation.evidence = Digest256::of(ByteSpan{});
  attestation.source = "downstream-consumer";
  expect(apply(authority.plan_attest_capacity(attestation, ArbSeq{++arbitration})),
         "attest authoritative capacity");

  const auto ledger = authority.ledger(path);
  expect(ledger.ok(), "ledger is derivable");
  if (ledger.ok()) {
    expect(ledger.value().verify_closure() == Status::Ok, "ledger closes");
    expect(ledger.value().authoritative_usable == 1000, "authoritative capacity is 1000");
    expect(ledger.value().protected_headroom == 100, "the default floor keeps 10% back");
    expect(ledger.value().allocatable == 900, "900 units are allocatable");
  }

  GrantProposal proposal;
  proposal.request = RequestId::from_seed(8, 8);
  proposal.holder = site_a;
  proposal.holder_incarnation = incarnation;
  proposal.path = path;
  proposal.amount = 950;
  proposal.duration_ms = 60000;
  proposal.now_ms = now;
  auto proposed = authority.plan_propose_grant(proposal, ArbSeq{++arbitration});
  expect(proposed.ok(), "proposal is planned");
  if (!proposed.ok()) {
    return;
  }
  const GrantId grant = GrantId::from_raw(proposed.value().changes.front().key);
  if (!apply(std::move(proposed))) {
    expect(false, "proposal could not be applied");
    return;
  }
  GrantOperation op;
  op.grant = grant;
  op.actor = site_a;
  op.actor_incarnation = incarnation;
  op.epoch = authority.epoch();
  op.now_ms = now;
  expect(authority.apply(authority.plan_evaluate_grant(op, ArbSeq{++arbitration}).value().changes,
                         ArbSeq{arbitration}) == Status::Ok,
         "grant becomes eligible");
  auto reserved = authority.plan_reserve_grant(op, ArbSeq{++arbitration});
  expect(!reserved.ok() && reserved.status() == Status::Exhausted,
         "a request larger than the allocatable headroom is refused");

  std::string why;
  expect(authority.verify_invariants(&why) == Status::Ok, "invariants hold: " + why);
}

/// The durable store, exercised through a real close and reopen.
void exercise_store(const std::string& directory) {
  const std::string path = directory + "/consumer.isfstore";
  StoreOptions options = StoreOptions::for_tests();
  SiteRecord site;
  site.id = SiteId::from_seed(9, 9);
  site.name = "consumer-site";
  site.incarnation = Incarnation::from_seed(10, 10);
  site.generation = Generation{1};
  site.epoch = Epoch{1};
  site.state = SiteState::Up;
  Writer writer;
  encode(writer, site);
  StateChange change;
  change.kind = ObjectKind::Site;
  change.key = site.id.raw();
  change.image.assign(writer.buffer().begin(), writer.buffer().end());

  {
    Store store;
    auto opened = store.open(path, options);
    expect(opened.ok(), "store opens");
    if (!opened.ok()) {
      return;
    }
    expect(store.append_intent(1, ArbSeq{1}, {change}, 1000, site.incarnation) == Status::Ok,
           "intent is appended");
    expect(store.append_commit(1, 1000) == Status::Ok, "completion is appended");
    expect(store.flush() == Status::Ok, "store is flushed");
    store.close();
  }
  Store reopened;
  auto replay = reopened.open(path, options);
  expect(replay.ok(), "store reopens");
  if (replay.ok()) {
    expect(replay.value().report.servable(), "recovered store is servable");
    expect(replay.value().report.records_read == 2, "both records were replayed");
    expect(replay.value().report.fidelity == RecoveryFidelity::Exact, "recovery is exact");
  }
  reopened.close();
}

/// The full stack: daemon, store, framed loopback transport, client.
void exercise_transport(const std::string& directory) {
  DaemonOptions daemon_options;
  daemon_options.state_path = directory + "/consumer-daemon.isfstore";
  daemon_options.enable_ticker = false;
  auto daemon = Daemon::start(daemon_options);
  expect(daemon.ok(), "daemon starts");
  if (!daemon.ok()) {
    return;
  }
  ServerOptions server_options;
  server_options.bind_endpoint = Endpoint{"127.0.0.1", 0};
  FabricServer server(**daemon, server_options);
  expect(server.start() == Status::Ok, "server listens");
  {
    ClientOptions client_options;
    client_options.endpoint = server.local_endpoint();
    client_options.client_kind = "downstream-consumer";
    auto client = FabricClient::connect(client_options);
    expect(client.ok(), "client completes the handshake");
    if (client.ok()) {
      auto status = client.value().status();
      expect(status.ok(), "status request succeeds");
      if (status.ok()) {
        expect(status.value().store_servable, "the daemon reports a servable store");
        expect(status.value().state_digest == (**daemon).state_digest(),
               "the digest reported over the wire matches the in-process authority");
      }
      (void)client.value().request_shutdown();
      client.value().close();
    }
  }
  server.stop();
  (**daemon).stop();
}

}  // namespace

int main() {
  namespace fs = std::filesystem;
  const fs::path directory = fs::temp_directory_path() / "isf-downstream-consumer";
  std::error_code ec;
  fs::remove_all(directory, ec);
  fs::create_directories(directory, ec);

  std::printf("Inter-Site Fabric %s downstream consumer\n", runtime_version_string());
  exercise_authority();
  exercise_store(directory.string());
  exercise_transport(directory.string());

  fs::remove_all(directory, ec);
  if (g_failures != 0) {
    std::printf("%d expectation(s) failed\n", g_failures);
    return 1;
  }
  std::printf("all expectations held\n");
  return 0;
}
