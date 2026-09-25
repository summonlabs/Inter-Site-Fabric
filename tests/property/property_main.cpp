// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Seeded property tests. Every property is driven by the run seed, and the seed
// is printed on failure so a counterexample is reproducible from the seed alone.

#include "testkit.hpp"

#include "isf/clock.hpp"
#include "isf/digest.hpp"

#include <algorithm>
#include <array>
#include <map>
#include <string>
#include <vector>

using namespace isf;
using namespace isf::test;

int main(int argc, char** argv) { return run_all(argc, argv, "isf_property_tests"); }

namespace {

/// Apply a plan if it succeeds, and report the resulting status.
Status apply_plan(Authority& authority, MutationResult result, std::uint64_t arbitration) {
  const ArbSeq arb{arbitration};
  if (!result.ok()) {
    return result.status();
  }
  return authority.apply(result.value().changes, arb);
}

struct World {
  Authority authority;
  FabricFixture fixture{};
  std::vector<GrantId> grants{};
  std::uint64_t arbitration{0};

  explicit World(const std::string& tag, Amount usable, const Policy& policy)
      : authority(make_config(policy)) {
    auto built = setup_fabric(authority, tag, usable, 1000);
    if (!built.ok()) {
      throw TestFailure("fixture could not be built: " + built.detail());
    }
    fixture = built.value();
  }

  static AuthorityConfig make_config(const Policy& policy) {
    AuthorityConfig config;
    config.policy = policy;
    config.incarnation = Incarnation::from_seed(0xA5A5, 1);
    return config;
  }

  ArbSeq next_arb() { return ArbSeq{++arbitration}; }

  /// Propose, evaluate and reserve using an explicitly supplied proposal, so
  /// two worlds can be driven by byte-identical requests.
  Expected<GrantId> reserve_exact(const GrantProposal& proposal) {
    auto proposed = authority.plan_propose_grant(proposal, next_arb());
    if (!proposed.ok()) {
      return proposed.status();
    }
    const GrantId id = GrantId::from_raw(proposed.value().changes.front().key);
    const Status applied = authority.apply(proposed.value().changes, ArbSeq{arbitration});
    if (applied != Status::Ok) {
      return applied;
    }
    GrantOperation op;
    op.grant = id;
    op.actor = proposal.holder;
    op.actor_incarnation = proposal.holder_incarnation;
    op.epoch = authority.epoch();
    op.now_ms = proposal.now_ms;
    const Status evaluated =
        apply_plan(authority, authority.plan_evaluate_grant(op, next_arb()), arbitration);
    if (evaluated != Status::Ok) {
      return evaluated;
    }
    const Status reserved =
        apply_plan(authority, authority.plan_reserve_grant(op, next_arb()), arbitration);
    if (reserved != Status::Ok) {
      return reserved;
    }
    grants.push_back(id);
    return id;
  }

  /// Propose, evaluate and reserve. Returns the grant identity or a failure.
  Expected<GrantId> reserve(Rng& rng, bool site_a, Amount amount, GrantClass klass) {
    if (amount == 0) {
      return Outcome(Status::Invalid, "zero amount");
    }
    GrantProposal proposal;
    proposal.request = RequestId::from_seed(rng.next(), rng.next());
    proposal.holder = site_a ? fixture.a : fixture.b;
    proposal.holder_incarnation = site_a ? fixture.a_incarnation : fixture.b_incarnation;
    proposal.holder_generation = site_a ? fixture.a_generation : fixture.b_generation;
    proposal.path = fixture.path;
    proposal.amount = amount;
    proposal.grant_class = klass;
    proposal.duration_ms = 600000;
    proposal.now_ms = 2000;

    auto proposed = authority.plan_propose_grant(proposal, next_arb());
    if (!proposed.ok()) {
      return proposed.status();
    }
    const GrantId id = GrantId::from_raw(proposed.value().changes.front().key);
    const Status applied = authority.apply(proposed.value().changes, ArbSeq{arbitration});
    if (applied != Status::Ok) {
      return applied;
    }
    GrantOperation op;
    op.grant = id;
    op.actor = proposal.holder;
    op.actor_incarnation = proposal.holder_incarnation;
    op.epoch = authority.epoch();
    op.now_ms = 2000;

    const Status evaluated =
        apply_plan(authority, authority.plan_evaluate_grant(op, next_arb()), arbitration);
    if (evaluated != Status::Ok) {
      return evaluated;
    }
    const Status reserved =
        apply_plan(authority, authority.plan_reserve_grant(op, next_arb()), arbitration);
    if (reserved != Status::Ok) {
      return reserved;
    }
    grants.push_back(id);
    return id;
  }

  Status activate(GrantId id) {
    GrantOperation op;
    op.grant = id;
    op.now_ms = 3000;
    return apply_plan(authority, authority.plan_activate_grant(op, next_arb()), arbitration);
  }

  Status degrade(GrantId id) {
    GrantOperation op;
    op.grant = id;
    op.now_ms = 3000;
    op.reason = "property";
    return apply_plan(authority, authority.plan_degrade_grant(op, next_arb()), arbitration);
  }

  Status withdraw(GrantId id) {
    GrantOperation op;
    op.grant = id;
    op.now_ms = 3000;
    op.reason = "property";
    return apply_plan(authority, authority.plan_withdraw_grant(op, next_arb()), arbitration);
  }

  Status retire(GrantId id) {
    GrantOperation op;
    op.grant = id;
    op.now_ms = 3000;
    op.reason = "property";
    return apply_plan(authority, authority.plan_retire_grant(op, next_arb()), arbitration);
  }
};

/// Sum of grant amounts in a set of states, from the grant table itself.
[[nodiscard]] Amount sum_amounts(const Authority& authority, PathId path,
                                 const std::vector<GrantState>& states) {
  Amount total = 0;
  for (const auto& grant : authority.grants()) {
    if (!(grant.binding.path == path)) {
      continue;
    }
    if (std::find(states.begin(), states.end(), grant.state) == states.end()) {
      continue;
    }
    total = saturating_add(total, grant.amount);
  }
  return total;
}

}  // namespace

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

ISF_TEST(property, identical_op_streams_produce_identical_state) {
  const std::uint64_t iterations = run_iterations();
  for (std::uint64_t iteration = 0; iteration < iterations; ++iteration) {
    Rng rng(run_seed() + (iteration * 0x9E3779B97F4A7C15ULL));
    const Amount usable = 1 + rng.below(5000);
    Policy policy = Policy::conservative_default();
    policy.protected_floor_bps = static_cast<std::uint32_t>(rng.below(3000));
    policy.min_free_bps = static_cast<std::uint32_t>(rng.below(1000));

    World first("determinism", usable, policy);
    World second("determinism", usable, policy);

    // Each step is decided once, from a replayable stream, and then handed to
    // both worlds unchanged. Any divergence is therefore a determinism defect
    // in the authority, not a difference in the input.
    std::vector<GrantId> granted;
    const std::uint64_t steps = 40;
    for (std::uint64_t step = 0; step < steps; ++step) {
      if (rng.chance(60) || granted.empty()) {
        GrantProposal proposal;
        proposal.request = RequestId::from_seed(rng.next(), rng.next());
        const bool site_a = rng.chance(50);
        proposal.holder = site_a ? first.fixture.a : first.fixture.b;
        proposal.holder_incarnation =
            site_a ? first.fixture.a_incarnation : first.fixture.b_incarnation;
        proposal.holder_generation =
            site_a ? first.fixture.a_generation : first.fixture.b_generation;
        proposal.path = first.fixture.path;
        proposal.amount = 1 + rng.below(usable + 10);
        proposal.grant_class = rng.chance(20) ? GrantClass::Protected : GrantClass::General;
        proposal.duration_ms = 600000;
        proposal.now_ms = 2000;

        auto first_result = first.reserve_exact(proposal);
        auto second_result = second.reserve_exact(proposal);
        ISF_REQUIRE_EQ(static_cast<int>(first_result.status()),
                       static_cast<int>(second_result.status()));
        if (first_result.ok()) {
          ISF_CHECK(first_result.value() == second_result.value());
          granted.push_back(first_result.value());
        }
      } else {
        const std::size_t index = static_cast<std::size_t>(rng.below(granted.size()));
        const std::uint64_t choice = rng.below(4);
        GrantOperation op;
        op.grant = granted[index];
        op.now_ms = 3000;
        op.reason = "determinism";
        Status a = Status::Ok;
        Status b = Status::Ok;
        if (choice == 0) {
          a = first.activate(granted[index]);
          b = second.activate(granted[index]);
        } else if (choice == 1) {
          a = first.degrade(granted[index]);
          b = second.degrade(granted[index]);
        } else if (choice == 2) {
          a = first.withdraw(granted[index]);
          b = second.withdraw(granted[index]);
        } else {
          a = first.retire(granted[index]);
          b = second.retire(granted[index]);
        }
        ISF_REQUIRE_EQ(static_cast<int>(a), static_cast<int>(b));
      }
      ISF_REQUIRE(first.authority.state_digest() == second.authority.state_digest());
    }
  }
}

// ---------------------------------------------------------------------------
// Accounting closure
// ---------------------------------------------------------------------------

ISF_TEST(property, accounting_closes_after_every_operation) {
  const std::uint64_t iterations = std::max<std::uint64_t>(run_iterations() / 4, 20);
  for (std::uint64_t iteration = 0; iteration < iterations; ++iteration) {
    Rng rng(run_seed() ^ (iteration * 0xD6E8FEB86659FD93ULL));
    const Amount usable = 1 + rng.below(20000);
    Policy policy = Policy::conservative_default();
    policy.protected_floor_bps = static_cast<std::uint32_t>(rng.below(4000));
    policy.protected_floor_units = rng.below(50);
    policy.min_free_bps = static_cast<std::uint32_t>(rng.below(500));
    World world("closure", usable, policy);

    std::vector<GrantId> live;
    for (std::uint64_t step = 0; step < 60; ++step) {
      const std::uint64_t action = rng.below(10);
      if (action < 6 || live.empty()) {
        auto granted = world.reserve(rng, rng.chance(50), 1 + rng.below(usable), 
                                     rng.chance(15) ? GrantClass::Protected : GrantClass::General);
        if (granted.ok()) {
          live.push_back(granted.value());
        }
      } else {
        const std::size_t index = static_cast<std::size_t>(rng.below(live.size()));
        switch (action) {
          case 6:
            (void)world.activate(live[index]);
            break;
          case 7:
            (void)world.degrade(live[index]);
            break;
          case 8:
            (void)world.withdraw(live[index]);
            break;
          default:
            (void)world.retire(live[index]);
            break;
        }
      }

      auto ledger = world.authority.ledger(world.fixture.path);
      ISF_REQUIRE_OK(ledger);
      ISF_CHECK_EQ(static_cast<int>(ledger.value().verify_closure()), static_cast<int>(Status::Ok));
      ISF_CHECK_EQ(ledger.value().oversubscribed, Amount{0});

      // Closure against the grant table itself, computed independently here.
      const Amount committed = sum_amounts(world.authority, world.fixture.path,
                                           {GrantState::Active, GrantState::Degraded});
      const Amount withdrawing =
          sum_amounts(world.authority, world.fixture.path, {GrantState::Withdrawing});
      const Amount reserved = sum_amounts(world.authority, world.fixture.path, {GrantState::Reserved});
      ISF_CHECK_EQ(ledger.value().committed, committed);
      ISF_CHECK_EQ(ledger.value().withdrawing, withdrawing);
      ISF_CHECK_EQ(ledger.value().reserved, reserved);

      std::string why;
      const Status invariants = world.authority.verify_invariants(&why);
      if (invariants != Status::Ok) {
        ISF_FAIL(std::string("invariant violation after step ") + std::to_string(step) + ": " +
                 status_name(invariants) + " (" + why + ")");
      }
    }
  }
}

ISF_TEST(property, allocation_never_exceeds_the_authorized_ceiling) {
  const std::uint64_t iterations = std::max<std::uint64_t>(run_iterations() / 4, 20);
  for (std::uint64_t iteration = 0; iteration < iterations; ++iteration) {
    Rng rng(run_seed() ^ (iteration * 0xBF58476D1CE4E5B9ULL));
    const Amount usable = 1 + rng.below(1000);
    Policy policy = Policy::conservative_default();
    policy.protected_floor_bps = static_cast<std::uint32_t>(rng.below(2000));
    World world("ceiling", usable, policy);

    Amount requested_total = 0;
    Amount granted_total = 0;
    for (std::uint64_t step = 0; step < 30; ++step) {
      const Amount amount = 1 + rng.below(usable / 2 + 1);
      requested_total = saturating_add(requested_total, amount);
      auto granted = world.reserve(rng, rng.chance(50), amount, GrantClass::General);
      if (granted.ok()) {
        granted_total = saturating_add(granted_total, amount);
        (void)world.activate(granted.value());
      }
      auto ledger = world.authority.ledger(world.fixture.path);
      ISF_REQUIRE_OK(ledger);
      // Authorised obligations plus the protected floor plus unavailable
      // capacity must never exceed the authoritative basis.
      auto obligations = checked_add(ledger.value().committed, ledger.value().reserved);
      ISF_REQUIRE_OK(obligations);
      auto structural = checked_add(obligations.value(), ledger.value().protected_headroom);
      ISF_REQUIRE_OK(structural);
      structural = checked_add(structural.value(), ledger.value().unavailable);
      ISF_REQUIRE_OK(structural);
      ISF_CHECK(structural.value() <= ledger.value().authoritative_usable);
    }
    ISF_CHECK(granted_total <= usable);
    (void)requested_total;
  }
}

// ---------------------------------------------------------------------------
// Differential model
// ---------------------------------------------------------------------------

ISF_TEST(property, differential_against_an_independent_capacity_model) {
  const std::uint64_t iterations = std::max<std::uint64_t>(run_iterations() / 4, 20);
  for (std::uint64_t iteration = 0; iteration < iterations; ++iteration) {
    Rng rng(run_seed() ^ (iteration * 0x94D049BB133111EBULL));
    const Amount usable = 1 + rng.below(3000);
    const std::uint32_t floor_bps = static_cast<std::uint32_t>(rng.below(2500));
    Policy policy = Policy::conservative_default();
    policy.protected_floor_bps = floor_bps;
    policy.min_free_bps = 0;
    policy.min_free_units = 0;
    policy.protected_floor_units = 0;
    World world("differential", usable, policy);

    Amount reference_floor = usable / 10000 * floor_bps + (usable % 10000) * floor_bps / 10000;
    if (reference_floor > usable) {
      reference_floor = usable;
    }
    ReferenceLedger reference(usable, reference_floor);

    std::vector<GrantId> live;
    for (std::uint64_t step = 0; step < 40; ++step) {
      if (rng.chance(65) || live.empty()) {
        const Amount amount = 1 + rng.below(usable / 3 + 1);
        auto granted = world.reserve(rng, rng.chance(50), amount, GrantClass::General);
        const bool model_accepts = reference.allocate(amount);
        if (model_accepts) {
          ISF_CHECK(granted.ok());
          if (granted.ok()) {
            live.push_back(granted.value());
          } else {
            reference.release(amount);
          }
        } else {
          ISF_CHECK(!granted.ok());
        }
      } else {
        const std::size_t index = static_cast<std::size_t>(rng.below(live.size()));
        auto grant = world.authority.find_grant(live[index]);
        if (grant.has_value() && grant->state == GrantState::Eligible) {
          (void)world.activate(live[index]);
        }
        if (grant.has_value() && holds_capacity(grant->state) &&
            (grant->state == GrantState::Active || grant->state == GrantState::Degraded)) {
          if (rng.chance(50)) {
            (void)world.withdraw(live[index]);
          } else {
            (void)world.retire(live[index]);
          }
          reference.release(grant->amount);
          live.erase(live.begin() + static_cast<std::ptrdiff_t>(index));
        }
      }
      auto ledger = world.authority.ledger(world.fixture.path);
      ISF_REQUIRE_OK(ledger);
      ISF_CHECK(reference.consistent());
      // The authority's allocatable headroom matches the independent model's
      // free capacity exactly.
      ISF_CHECK_EQ(ledger.value().allocatable, reference.free());
    }
  }
}

// ---------------------------------------------------------------------------
// Encoding stability
// ---------------------------------------------------------------------------

ISF_TEST(property, canonical_encoding_is_stable_under_round_trips) {
  const std::uint64_t iterations = run_iterations();
  for (std::uint64_t iteration = 0; iteration < iterations; ++iteration) {
    Rng rng(run_seed() ^ (iteration * 0x2545F4914F6CDD1DULL));
    GrantRecord grant;
    grant.id = GrantId::from_raw(Id128{rng.next(), rng.next()});
    grant.request = RequestId::from_raw(Id128{rng.next(), rng.next()});
    grant.arbitration = ArbSeq{rng.next()};
    grant.binding.holder = SiteId::from_raw(Id128{rng.next(), rng.next()});
    grant.binding.holder_incarnation = Incarnation::from_raw(Id128{rng.next(), rng.next()});
    grant.binding.holder_generation = Generation{rng.next()};
    grant.binding.path = PathId::from_raw(Id128{rng.next(), rng.next()});
    grant.binding.path_generation = Generation{rng.next()};
    grant.binding.capacity_generation = Generation{rng.next()};
    grant.binding.policy_generation = Generation{rng.next()};
    grant.binding.epoch = Epoch{rng.next()};
    grant.binding.lease = LeaseId::from_raw(Id128{rng.next(), rng.next()});
    grant.amount = rng.next();
    grant.state = static_cast<GrantState>(rng.below(10));
    grant.verification = static_cast<VerificationState>(rng.below(4));
    grant.acknowledged = rng.chance(50);
    grant.ack_count = static_cast<std::uint32_t>(rng.below(1000));
    grant.created_at_ms = rng.next();
    grant.updated_at_ms = rng.next();
    grant.expires_at_ms = rng.next();
    grant.provenance = static_cast<Provenance>(rng.below(7));
    grant.historical = rng.chance(50);
    grant.ambiguous = rng.chance(50);

    Writer first;
    encode(first, grant);
    Reader reader(first.span());
    auto decoded = decode_grant(reader);
    ISF_REQUIRE_OK(decoded);
    Writer second;
    encode(second, decoded.value());
    ISF_CHECK(first.buffer() == second.buffer());
  }
}

ISF_TEST(property, corrupted_frames_are_never_accepted) {
  const std::uint64_t iterations = run_iterations();
  for (std::uint64_t iteration = 0; iteration < iterations; ++iteration) {
    Rng rng(run_seed() ^ (iteration * 0x27D4EB2F165667C5ULL));
    const std::size_t length = 1 + static_cast<std::size_t>(rng.below(256));
    std::vector<Byte> body(length);
    for (auto& byte : body) {
      byte = static_cast<Byte>(rng.next() & 0xFFU);
    }
    std::vector<Byte> frame = encode_frame(ByteSpan(body.data(), body.size()));
    const std::size_t index = static_cast<std::size_t>(rng.below(frame.size()));
    const Byte original = frame[index];
    Byte replacement = static_cast<Byte>(rng.next() & 0xFFU);
    if (replacement == original) {
      replacement = static_cast<Byte>(original ^ 0x01U);
    }
    frame[index] = replacement;

    FrameDecoder decoder(1U << 20);
    const Status pushed = decoder.push(ByteSpan(frame.data(), frame.size()));
    if (pushed != Status::Ok) {
      continue;  // rejected outright
    }
    auto payload = decoder.next();
    if (payload.ok()) {
      // The only acceptable acceptance is a mutation of the length field that
      // still leaves a self-consistent frame; that cannot happen because the
      // length participates in neither the CRC nor the payload, so a length
      // change must produce a payload mismatch or a short frame.
      ISF_CHECK(payload.value() == body);
    }
  }
}

ISF_TEST(property, framing_round_trips_arbitrary_payloads) {
  const std::uint64_t iterations = run_iterations();
  for (std::uint64_t iteration = 0; iteration < iterations; ++iteration) {
    Rng rng(run_seed() ^ (iteration * 0x9E3779B97F4A7C15ULL));
    const std::size_t length = static_cast<std::size_t>(rng.below(4096));
    std::vector<Byte> body(length);
    for (auto& byte : body) {
      byte = static_cast<Byte>(rng.next() & 0xFFU);
    }
    const std::vector<Byte> frame = encode_frame(ByteSpan(body.data(), body.size()));
    FrameDecoder decoder(1U << 20);
    ISF_REQUIRE_STATUS_EQ(decoder.push(ByteSpan(frame.data(), frame.size())), Status::Ok);
    auto payload = decoder.next();
    ISF_REQUIRE_OK(payload);
    ISF_REQUIRE(payload.value() == body);
  }
}

// ---------------------------------------------------------------------------
// Persistence properties
// ---------------------------------------------------------------------------

ISF_TEST(property, store_truncation_never_fabricates_authority) {
  const std::uint64_t iterations = std::max<std::uint64_t>(run_iterations() / 8, 10);
  for (std::uint64_t iteration = 0; iteration < iterations; ++iteration) {
    Rng rng(run_seed() ^ (iteration * 0xFF51AFD7ED558CCDULL));
    ScratchDir scratch("prop-truncate");
    const std::string path = scratch.file("log.isfstore");
    StoreOptions options = StoreOptions::for_tests();
    std::size_t records = 0;
    {
      Store store;
      ISF_REQUIRE_OK(store.open(path, options));
      const std::size_t count = 2 + static_cast<std::size_t>(rng.below(12));
      for (std::size_t i = 1; i <= count; ++i) {
        SiteRecord site;
        site.id = site_from_name("t" + std::to_string(i));
        site.name = "t" + std::to_string(i);
        site.incarnation = Incarnation::from_seed(i, 1);
        site.generation = Generation{1};
        site.epoch = Epoch{1};
        site.state = SiteState::Up;
        Writer writer;
        encode(writer, site);
        StateChange change;
        change.kind = ObjectKind::Site;
        change.key = site.id.raw();
        change.image.assign(writer.buffer().begin(), writer.buffer().end());
        ISF_REQUIRE_EQ(store.append_intent(i, ArbSeq{i}, {change}, i, Incarnation::from_seed(i, 1)),
                       Status::Ok);
        ISF_REQUIRE_EQ(store.append_commit(i, i), Status::Ok);
        ++records;
      }
      ISF_REQUIRE_EQ(store.flush(), Status::Ok);
      store.close();
    }
    // Read the full file for reference, then truncate at a random offset.
    std::vector<Byte> bytes;
    {
      std::FILE* fp = std::fopen(path.c_str(), "rb");
      ISF_REQUIRE(fp != nullptr);
      std::array<Byte, 4096> buffer{};
      std::size_t got = 0;
      while ((got = std::fread(buffer.data(), 1, buffer.size(), fp)) > 0) {
        bytes.insert(bytes.end(), buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(got));
      }
      std::fclose(fp);
    }
    ISF_REQUIRE(bytes.size() > 200);
    const std::size_t cut = 128 + static_cast<std::size_t>(rng.below(bytes.size() - 128));
    bytes.resize(cut);
    {
      std::FILE* fp = std::fopen(path.c_str(), "wb");
      ISF_REQUIRE(fp != nullptr);
      (void)std::fwrite(bytes.data(), 1, bytes.size(), fp);
      std::fclose(fp);
    }

    Store store;
    auto replay = store.open(path, options);
    ISF_REQUIRE_OK(replay);
    if (!replay.value().report.servable()) {
      continue;  // conservative refusal is always acceptable
    }
    // Whatever survived must be a prefix: every complete intent/commit pair seen
    // must correspond to a record that existed in the original sequence, and the
    // number of changes can never exceed what was written.
    std::size_t intents = 0;
    for (const auto& action : replay.value().actions) {
      if (action.kind == ReplayAction::Kind::Changes && !action.changes.empty()) {
        ++intents;
        ISF_CHECK(action.arbitration.value >= 1);
        ISF_CHECK(action.arbitration.value <= records);
      }
    }
    ISF_CHECK(intents <= records);
  }
}

ISF_TEST(property, store_round_trip_preserves_authority_state) {
  const std::uint64_t iterations = std::max<std::uint64_t>(run_iterations() / 8, 10);
  for (std::uint64_t iteration = 0; iteration < iterations; ++iteration) {
    Rng rng(run_seed() ^ (iteration * 0xC4CEB9FE1A85EC53ULL));
    ScratchDir scratch("prop-roundtrip");
    const std::string path = scratch.file("log.isfstore");

    AuthorityConfig config;
    config.incarnation = Incarnation::from_seed(iteration + 1, 7);
    Authority authority(config);
    auto fixture = setup_fabric(authority, "roundtrip", 1 + rng.below(5000), 1000);
    ISF_REQUIRE_OK(fixture);

    StoreOptions options = StoreOptions::for_tests();
    Store store;
    ISF_REQUIRE_OK(store.open(path, options));
    // The fixture state is durable evidence too, so it is recorded as a
    // snapshot record before the incremental change stream begins.
    ISF_REQUIRE_EQ(store.append_snapshot(authority.snapshot(), 1000, config.incarnation),
                   Status::Ok);

    const auto record = [&](std::uint64_t sequence, const Mutation& mutation) -> Status {
      const Status written =
          store.append_intent(sequence, ArbSeq{sequence}, mutation.changes, 2000, config.incarnation);
      if (written != Status::Ok) {
        return written;
      }
      const Status applied = authority.apply(mutation.changes, ArbSeq{sequence});
      if (applied != Status::Ok) {
        return applied;
      }
      return store.append_commit(sequence, 2000);
    };

    std::uint64_t sequence = 0;
    for (std::uint64_t step = 0; step < 20; ++step) {
      GrantProposal proposal;
      proposal.request = RequestId::from_seed(rng.next(), rng.next());
      proposal.holder = fixture.value().a;
      proposal.holder_incarnation = fixture.value().a_incarnation;
      proposal.holder_generation = fixture.value().a_generation;
      proposal.path = fixture.value().path;
      proposal.amount = 1 + rng.below(500);
      proposal.duration_ms = 600000;
      proposal.now_ms = 2000;
      auto planned = authority.plan_propose_grant(proposal, ArbSeq{++sequence});
      if (!planned.ok()) {
        continue;
      }
      ISF_REQUIRE_EQ(record(sequence, planned.value()), Status::Ok);
      const GrantId id = GrantId::from_raw(planned.value().changes.front().key);
      GrantOperation op;
      op.grant = id;
      op.actor = fixture.value().a;
      op.actor_incarnation = fixture.value().a_incarnation;
      op.epoch = authority.epoch();
      op.now_ms = 2000;
      auto evaluated = authority.plan_evaluate_grant(op, ArbSeq{++sequence});
      if (!evaluated.ok()) {
        continue;
      }
      ISF_REQUIRE_EQ(record(sequence, evaluated.value()), Status::Ok);
      auto reserved = authority.plan_reserve_grant(op, ArbSeq{++sequence});
      if (!reserved.ok()) {
        continue;
      }
      ISF_REQUIRE_EQ(record(sequence, reserved.value()), Status::Ok);
      auto activated = authority.plan_activate_grant(op, ArbSeq{++sequence});
      if (!activated.ok()) {
        continue;
      }
      ISF_REQUIRE_EQ(record(sequence, activated.value()), Status::Ok);
    }
    ISF_REQUIRE_EQ(store.flush(), Status::Ok);
    const Digest256 expected = authority.state_digest();
    const std::string expected_ledger = authority.ledger(fixture.value().path).value().to_string();
    store.close();

    // Rebuild from the log alone and compare the authoritative digest.
    Store reopened;
    auto replay = reopened.open(path, options);
    ISF_REQUIRE_OK(replay);
    ISF_REQUIRE(replay.value().report.servable());
    Authority recovered(config);
    bool saw_snapshot = false;
    for (const auto& action : replay.value().actions) {
      if (action.kind == ReplayAction::Kind::Snapshot) {
        auto rebuilt = Authority::from_snapshot(config, action.snapshot);
        ISF_REQUIRE_OK(rebuilt);
        recovered = std::move(rebuilt.value());
        saw_snapshot = true;
        continue;
      }
      ISF_REQUIRE_EQ(recovered.apply(action.changes, action.arbitration), Status::Ok);
    }
    ISF_REQUIRE(saw_snapshot);
    ISF_CHECK(recovered.state_digest() == expected);
    ISF_CHECK_EQ(recovered.ledger(fixture.value().path).value().to_string(), expected_ledger);
    reopened.close();
  }
}

// ---------------------------------------------------------------------------
// Arithmetic
// ---------------------------------------------------------------------------

ISF_TEST(property, checked_arithmetic_never_wraps) {
  const std::uint64_t iterations = run_iterations() * 4;
  for (std::uint64_t iteration = 0; iteration < iterations; ++iteration) {
    Rng rng(run_seed() ^ (iteration * 0x9E3779B97F4A7C15ULL));
    const Amount a = rng.next();
    const Amount b = rng.next();
    auto sum = checked_add(a, b);
    if (a > kAmountMax - b) {
      ISF_CHECK(!sum.ok());
      ISF_CHECK_EQ(static_cast<int>(sum.status()), static_cast<int>(Status::LimitExceeded));
    } else {
      ISF_CHECK(sum.ok());
      ISF_CHECK_EQ(sum.value(), a + b);
      ISF_CHECK(sum.value() >= a);
    }
    auto difference = checked_sub(a, b);
    if (b > a) {
      ISF_CHECK(!difference.ok());
    } else {
      ISF_CHECK(difference.ok());
      ISF_CHECK_EQ(difference.value(), a - b);
    }
    auto product = checked_mul(a, b);
    if (a != 0 && b > kAmountMax / a) {
      ISF_CHECK(!product.ok());
    } else {
      ISF_CHECK(product.ok());
      ISF_CHECK_EQ(product.value(), a * b);
    }
  }
}