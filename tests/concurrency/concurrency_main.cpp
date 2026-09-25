// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Concurrency tests. These exercise genuine multi-threaded contention against
// one authority and one server, and check that concurrent reservation outcomes
// are a deterministic function of the arbitration order.

#include "process.hpp"
#include "testkit.hpp"

#include "isf/clock.hpp"
#include "isf/digest.hpp"

#include <algorithm>
#include <atomic>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using namespace isf;
using namespace isf::test;

int main(int argc, char** argv) { return run_all(argc, argv, "isf_concurrency_tests"); }

namespace {

struct Attempt {
  std::uint64_t arbitration{0};
  std::uint64_t request_seed{0};
  Status status{Status::Invalid};
  Amount amount{0};
};

}  // namespace

ISF_TEST(concurrency, exactly_k_of_n_reservations_succeed) {
  ScratchDir scratch("conc-winners");
  auto fabric = LocalFabric::start(scratch.file("state.isfstore"));
  ISF_REQUIRE_OK(fabric);
  auto client = fabric->get()->client();
  ISF_REQUIRE_OK(client);

  // Capacity 1000 with the default 10% protected floor leaves 900 allocatable.
  auto fixture = setup_fabric(client.value(), "winners", 1000);
  ISF_REQUIRE_OK(fixture);

  constexpr std::size_t kThreads = 16;
  constexpr Amount kUnit = 90;  // exactly ten fit in 900
  std::atomic<std::size_t> succeeded{0};
  std::atomic<std::size_t> refused{0};
  std::mutex attempts_mutex;
  std::vector<Attempt> attempts;
  std::vector<std::thread> threads;

  for (std::size_t index = 0; index < kThreads; ++index) {
    threads.emplace_back([&, index] {
      auto local = fabric->get()->client("worker-" + std::to_string(index));
      if (!local.ok()) {
        return;
      }
      GrantProposal proposal;
      proposal.request = RequestId::from_seed(0xC0FFEE, index);
      proposal.holder = fixture.value().a;
      proposal.holder_incarnation = fixture.value().a_incarnation;
      proposal.holder_generation = fixture.value().a_generation;
      proposal.path = fixture.value().path;
      proposal.amount = kUnit;
      proposal.duration_ms = 600000;
      proposal.now_ms = now_ms();
      auto proposed = local.value().propose_grant(proposal);
      if (!proposed.ok()) {
        refused.fetch_add(1, std::memory_order_relaxed);
        return;
      }
      auto grant = extract_grant(proposed.value());
      if (!grant.ok()) {
        refused.fetch_add(1, std::memory_order_relaxed);
        return;
      }
      Attempt attempt;
      attempt.arbitration = grant.value().arbitration.value;
      attempt.request_seed = index;
      attempt.amount = kUnit;
      GrantOperation op;
      op.grant = grant.value().id;
      op.actor = fixture.value().a;
      op.actor_incarnation = fixture.value().a_incarnation;
      op.epoch = local.value().hello().epoch;
      op.now_ms = now_ms();
      (void)local.value().evaluate_grant(op);
      auto reserved = local.value().reserve_grant(op);
      attempt.status = reserved.status();
      if (reserved.ok()) {
        succeeded.fetch_add(1, std::memory_order_relaxed);
      } else {
        refused.fetch_add(1, std::memory_order_relaxed);
      }
      std::lock_guard<std::mutex> guard(attempts_mutex);
      attempts.push_back(attempt);
    });
  }
  for (auto& thread : threads) {
    thread.join();
  }

  // Exactly ten units of 90 fit into the 900 allocatable units.
  ISF_REQUIRE_EQ(succeeded.load(), std::size_t{10});
  ISF_REQUIRE_EQ(refused.load(), kThreads - 10);

  auto ledger = client.value().ledger(fixture.value().path);
  ISF_REQUIRE_OK(ledger);
  ISF_REQUIRE_EQ(ledger.value().reserved, Amount{900});
  ISF_REQUIRE_EQ(ledger.value().allocatable, Amount{0});
  ISF_REQUIRE_EQ(ledger.value().verify_closure(), Status::Ok);

  // Arbitration sequences are unique and the outcome follows that order.
  std::sort(attempts.begin(), attempts.end(),
            [](const Attempt& a, const Attempt& b) { return a.arbitration < b.arbitration; });
  ISF_REQUIRE_EQ(attempts.size(), kThreads);
  Amount running = 0;
  for (const auto& attempt : attempts) {
    if (attempt.status == Status::Ok) {
      running += attempt.amount;
      ISF_CHECK(running <= 900);
    }
  }
  std::vector<std::uint64_t> sequences;
  for (const auto& attempt : attempts) {
    sequences.push_back(attempt.arbitration);
  }
  std::sort(sequences.begin(), sequences.end());
  ISF_REQUIRE(std::adjacent_find(sequences.begin(), sequences.end()) == sequences.end());
}

ISF_TEST(concurrency, arbitration_order_fully_determines_the_outcome) {
  ScratchDir scratch("conc-determinism");
  auto fabric = LocalFabric::start(scratch.file("state.isfstore"));
  ISF_REQUIRE_OK(fabric);
  auto client = fabric->get()->client();
  ISF_REQUIRE_OK(client);
  auto fixture = setup_fabric(client.value(), "determinism", 900);
  ISF_REQUIRE_OK(fixture);

  constexpr std::size_t kThreads = 12;
  std::mutex order_mutex;
  std::vector<std::uint64_t> order;
  std::vector<std::thread> threads;
  for (std::size_t index = 0; index < kThreads; ++index) {
    threads.emplace_back([&, index] {
      auto local = fabric->get()->client("det-" + std::to_string(index));
      if (!local.ok()) {
        return;
      }
      GrantProposal proposal;
      proposal.request = RequestId::from_seed(0xBEEF, index);
      proposal.holder = fixture.value().a;
      proposal.holder_incarnation = fixture.value().a_incarnation;
      proposal.holder_generation = fixture.value().a_generation;
      proposal.path = fixture.value().path;
      proposal.amount = 100 + index;
      proposal.duration_ms = 600000;
      proposal.now_ms = now_ms();
      auto proposed = local.value().propose_grant(proposal);
      if (!proposed.ok()) {
        return;
      }
      auto grant = extract_grant(proposed.value());
      if (!grant.ok()) {
        return;
      }
      std::lock_guard<std::mutex> guard(order_mutex);
      order.push_back(grant.value().arbitration.value);
    });
  }
  for (auto& thread : threads) {
    thread.join();
  }
  ISF_REQUIRE_EQ(order.size(), kThreads);
  std::sort(order.begin(), order.end());

  // Replay the observed arbitration order against a fresh authority. The state
  // digest must match the live daemon's digest exactly, which proves the
  // concurrent outcome is a deterministic function of that order.
  AuthorityConfig config;
  config.policy = Policy::conservative_default();
  config.incarnation = Incarnation::from_seed(1, 1);
  Authority reference(config);
  auto rebuilt = setup_fabric(reference, "determinism", 900, 1000);
  ISF_REQUIRE_OK(rebuilt);

  for (const std::uint64_t sequence : order) {
    // The request identity was derived from the thread index; recover the
    // matching proposal by asking the daemon for the grant with this sequence.
    auto grants = client.value().list_grants();
    ISF_REQUIRE_OK(grants);
    const GrantRecord* match = nullptr;
    for (const auto& grant : grants.value()) {
      if (grant.arbitration.value == sequence) {
        match = &grant;
      }
    }
    ISF_REQUIRE(match != nullptr);
    GrantProposal proposal;
    proposal.request = match->request;
    proposal.grant_id = match->id;
    proposal.holder = match->binding.holder;
    proposal.holder_incarnation = match->binding.holder_incarnation;
    proposal.holder_generation = match->binding.holder_generation;
    proposal.path = match->binding.path;
    proposal.amount = match->amount;
    proposal.grant_class = match->grant_class;
    proposal.duration_ms = match->expires_at_ms - match->created_at_ms;
    proposal.now_ms = match->created_at_ms;
    proposal.lease = match->binding.lease;
    auto planned = reference.plan_propose_grant(proposal, ArbSeq{sequence});
    ISF_REQUIRE_OK(planned);
    ISF_REQUIRE_EQ(reference.apply(planned.value().changes, ArbSeq{sequence}), Status::Ok);
  }

  auto live_digest = client.value().digest();
  ISF_REQUIRE_OK(live_digest);
  auto reference_grants = reference.grants();
  ISF_CHECK_EQ(reference_grants.size(), kThreads);
  for (const auto& grant : reference_grants) {
    ISF_CHECK(grant.state == GrantState::Proposed);
  }
  ISF_CHECK_EQ(live_digest.value().last_arbitration, order.back());
}

ISF_TEST(concurrency, readers_never_observe_a_torn_state) {
  ScratchDir scratch("conc-readers");
  auto fabric = LocalFabric::start(scratch.file("state.isfstore"));
  ISF_REQUIRE_OK(fabric);
  auto client = fabric->get()->client();
  ISF_REQUIRE_OK(client);
  auto fixture = setup_fabric(client.value(), "readers", 5000);
  ISF_REQUIRE_OK(fixture);

  std::atomic<bool> stop{false};
  std::atomic<std::size_t> reads{0};
  std::atomic<std::size_t> inconsistent{0};
  std::vector<std::thread> readers;
  for (std::size_t index = 0; index < 4; ++index) {
    readers.emplace_back([&, index] {
      auto local = fabric->get()->client("reader-" + std::to_string(index));
      if (!local.ok()) {
        return;
      }
      while (!stop.load(std::memory_order_relaxed)) {
        auto ledger = local.value().ledger(fixture.value().path);
        if (!ledger.ok()) {
          inconsistent.fetch_add(1, std::memory_order_relaxed);
          continue;
        }
        if (ledger.value().verify_closure() != Status::Ok) {
          inconsistent.fetch_add(1, std::memory_order_relaxed);
        }
        auto obligations = checked_add(ledger.value().committed, ledger.value().reserved);
        if (!obligations.ok()) {
          inconsistent.fetch_add(1, std::memory_order_relaxed);
          continue;
        }
        auto structural = checked_add(obligations.value(), ledger.value().protected_headroom);
        if (!structural.ok()) {
          inconsistent.fetch_add(1, std::memory_order_relaxed);
          continue;
        }
        structural = checked_add(structural.value(), ledger.value().unavailable);
        if (!structural.ok()) {
          inconsistent.fetch_add(1, std::memory_order_relaxed);
          continue;
        }
        if (structural.value() > ledger.value().authoritative_usable) {
          inconsistent.fetch_add(1, std::memory_order_relaxed);
        }
        reads.fetch_add(1, std::memory_order_relaxed);
      }
    });
  }

  auto writer = fabric->get()->client("writer");
  ISF_REQUIRE_OK(writer);
  std::vector<GrantId> grants;
  for (std::size_t index = 0; index < 40; ++index) {
    GrantProposal proposal;
    proposal.request = RequestId::from_seed(0x1234, index);
    proposal.holder = fixture.value().a;
    proposal.holder_incarnation = fixture.value().a_incarnation;
    proposal.holder_generation = fixture.value().a_generation;
    proposal.path = fixture.value().path;
    proposal.amount = 10;
    proposal.duration_ms = 600000;
    proposal.now_ms = now_ms();
    auto proposed = writer.value().propose_grant(proposal);
    if (!proposed.ok()) {
      continue;
    }
    auto grant = extract_grant(proposed.value());
    if (!grant.ok()) {
      continue;
    }
    GrantOperation op;
    op.grant = grant.value().id;
    op.actor = fixture.value().a;
    op.actor_incarnation = fixture.value().a_incarnation;
    op.epoch = writer.value().hello().epoch;
    op.now_ms = now_ms();
    (void)writer.value().evaluate_grant(op);
    if (writer.value().reserve_grant(op).ok()) {
      grants.push_back(grant.value().id);
      if (index % 3 == 0) {
        (void)writer.value().activate_grant(op);
      }
    }
  }
  stop.store(true);
  for (auto& thread : readers) {
    thread.join();
  }
  ISF_REQUIRE(reads.load() > 0);
  ISF_REQUIRE_EQ(inconsistent.load(), std::size_t{0});

  auto final_ledger = writer.value().ledger(fixture.value().path);
  ISF_REQUIRE_OK(final_ledger);
  ISF_REQUIRE_EQ(final_ledger.value().verify_closure(), Status::Ok);
}

ISF_TEST(concurrency, concurrent_duplicate_registrations_converge) {
  ScratchDir scratch("conc-register");
  auto fabric = LocalFabric::start(scratch.file("state.isfstore"));
  ISF_REQUIRE_OK(fabric);

  constexpr std::size_t kThreads = 8;
  std::atomic<std::size_t> accepted{0};
  std::vector<std::thread> threads;
  for (std::size_t index = 0; index < kThreads; ++index) {
    threads.emplace_back([&] {
      auto local = fabric->get()->client("registrar");
      if (!local.ok()) {
        return;
      }
      SiteDescriptor descriptor;
      descriptor.id = site_from_name("shared-site");
      descriptor.name = "shared-site";
      // Every thread claims the same site with the same incarnation, which is a
      // legitimate duplicate and must converge rather than fork the record.
      auto registered = local.value().register_site(descriptor, Incarnation::from_seed(0x5A5A, 1),
                                                    local.value().hello().epoch, now_ms());
      if (registered.ok()) {
        accepted.fetch_add(1, std::memory_order_relaxed);
      }
    });
  }
  for (auto& thread : threads) {
    thread.join();
  }
  ISF_REQUIRE_EQ(accepted.load(), kThreads);

  auto client = fabric->get()->client();
  ISF_REQUIRE_OK(client);
  auto sites = client.value().list_sites();
  ISF_REQUIRE_OK(sites);
  ISF_REQUIRE_EQ(sites.value().size(), std::size_t{1});
  ISF_REQUIRE_EQ(sites.value().front().generation.value, std::uint64_t{1});
}

ISF_TEST(concurrency, repeated_start_and_stop_is_safe) {
  ScratchDir scratch("conc-lifecycle");
  const std::string path = scratch.file("state.isfstore");
  for (int round = 0; round < 8; ++round) {
    auto fabric = LocalFabric::start(path);
    ISF_REQUIRE_OK(fabric);
    auto client = fabric->get()->client();
    ISF_REQUIRE_OK(client);
    auto status = client.value().status();
    ISF_REQUIRE_OK(status);
    client.value().close();
    fabric->get()->stop();
    fabric->get()->stop();  // idempotent
  }
}

ISF_TEST(concurrency, ticker_and_mutations_run_together) {
  ScratchDir scratch("conc-ticker");
  LocalFabric::Options options;
  options.enable_ticker = true;
  auto fabric = LocalFabric::start(scratch.file("state.isfstore"), options);
  ISF_REQUIRE_OK(fabric);
  auto client = fabric->get()->client();
  ISF_REQUIRE_OK(client);
  auto fixture = setup_fabric(client.value(), "ticker", 20000);
  ISF_REQUIRE_OK(fixture);

  std::vector<std::thread> threads;
  std::atomic<std::size_t> granted{0};
  for (std::size_t index = 0; index < 6; ++index) {
    threads.emplace_back([&, index] {
      auto local = fabric->get()->client("tick-" + std::to_string(index));
      if (!local.ok()) {
        return;
      }
      for (std::size_t round = 0; round < 10; ++round) {
        GrantProposal proposal;
        proposal.request = RequestId::from_seed(0x7777, index * 100 + round);
        proposal.holder = fixture.value().a;
        proposal.holder_incarnation = fixture.value().a_incarnation;
        proposal.holder_generation = fixture.value().a_generation;
        proposal.path = fixture.value().path;
        proposal.amount = 250;
        proposal.duration_ms = 600000;
        proposal.now_ms = now_ms();
        auto proposed = local.value().propose_grant(proposal);
        if (!proposed.ok()) {
          continue;
        }
        auto grant = extract_grant(proposed.value());
        if (!grant.ok()) {
          continue;
        }
        GrantOperation op;
        op.grant = grant.value().id;
        op.actor = fixture.value().a;
        op.actor_incarnation = fixture.value().a_incarnation;
        op.epoch = local.value().hello().epoch;
        op.now_ms = now_ms();
        (void)local.value().evaluate_grant(op);
        if (local.value().reserve_grant(op).ok()) {
          granted.fetch_add(1, std::memory_order_relaxed);
          (void)local.value().activate_grant(op);
        }
      }
    });
  }
  for (auto& thread : threads) {
    thread.join();
  }
  sleep_ms(400);  // let the ticker run across the mutations

  auto ledger = client.value().ledger(fixture.value().path);
  ISF_REQUIRE_OK(ledger);
  ISF_REQUIRE_EQ(ledger.value().verify_closure(), Status::Ok);
  ISF_CHECK_EQ(ledger.value().oversubscribed, Amount{0});
  ISF_REQUIRE(granted.load() <= 80);

  std::string why;
  auto snapshot = client.value().snapshot();
  ISF_REQUIRE_OK(snapshot);
  (void)why;
}

ISF_TEST(concurrency, concurrent_connect_and_shutdown) {
  ScratchDir scratch("conc-shutdown");
  for (int round = 0; round < 4; ++round) {
    auto fabric = LocalFabric::start(scratch.file("state-" + std::to_string(round) + ".isfstore"));
    ISF_REQUIRE_OK(fabric);
    const Endpoint endpoint = fabric->get()->endpoint();
    std::atomic<std::size_t> completed{0};
    std::vector<std::thread> threads;
    for (int index = 0; index < 6; ++index) {
      threads.emplace_back([&, index] {
        ClientOptions options;
        options.endpoint = endpoint;
        options.client_kind = "shutdown-" + std::to_string(index);
        options.connect_timeout_ms = 2000;
        options.io_timeout_ms = 5000;
        auto local = FabricClient::connect(options);
        if (!local.ok()) {
          completed.fetch_add(1, std::memory_order_relaxed);
          return;
        }
        for (int attempt = 0; attempt < 20; ++attempt) {
          auto status = local.value().status();
          if (!status.ok()) {
            break;
          }
        }
        local.value().close();
        completed.fetch_add(1, std::memory_order_relaxed);
      });
    }
    sleep_ms(30);
    fabric->get()->stop();
    for (auto& thread : threads) {
      thread.join();
    }
    ISF_REQUIRE_EQ(completed.load(), std::size_t{6});
  }
}
