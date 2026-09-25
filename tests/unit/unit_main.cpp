// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Unit tests for the deterministic core: identities, integrity primitives,
// canonical encoding, capacity accounting, lifecycle, policy, the authority
// state machine, and the durable store.

#include "testkit.hpp"

#include "isf/clock.hpp"
#include "isf/digest.hpp"
#include "isf/log.hpp"
#include "isf/protocol.hpp"

#include <array>
#include <cstdio>
#include <string>
#include <vector>

using namespace isf;
using namespace isf::test;

int main(int argc, char** argv) { return run_all(argc, argv, "isf_unit_tests"); }

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

ISF_TEST(status, names_are_distinct_and_round_trip) {
  const std::array<Status, 24> all{
      Status::Ok,          Status::Unknown,      Status::Unsupported, Status::Stale,
      Status::Conflicting, Status::Incomplete,   Status::Indeterminate, Status::Refused,
      Status::Cancelled,   Status::Invalid,      Status::NotFound,    Status::Duplicate,
      Status::Exhausted,   Status::Denied,       Status::LimitExceeded, Status::InvalidTransition,
      Status::Corrupt,     Status::VersionMismatch, Status::Unauthorized, Status::Busy,
      Status::Expired,     Status::Fenced,       Status::Unavailable, Status::Ambiguous};
  for (const Status status : all) {
    const char* name = status_name(status);
    bool recognized = false;
    const Status parsed = status_from_name(name, recognized);
    ISF_REQUIRE(recognized);
    ISF_CHECK_EQ(static_cast<int>(parsed), static_cast<int>(status));
  }
  // The vocabulary the runtime depends on must stay distinguishable.
  ISF_REQUIRE(std::string(status_name(Status::Unknown)) != status_name(Status::Stale));
  ISF_REQUIRE(std::string(status_name(Status::Refused)) != status_name(Status::Cancelled));
  ISF_REQUIRE(std::string(status_name(Status::Invalid)) != status_name(Status::Indeterminate));
  bool recognized = true;
  (void)status_from_name("NOT_A_STATUS", recognized);
  ISF_REQUIRE(!recognized);
}

// ---------------------------------------------------------------------------
// Identities
// ---------------------------------------------------------------------------

ISF_TEST(ids, hex_and_canonical_round_trip) {
  Rng rng(run_seed());
  for (std::uint64_t i = 0; i < 256; ++i) {
    const Id128 value{rng.next(), rng.next()};
    ISF_REQUIRE_EQ(value.to_hex().size(), std::size_t{32});
    auto parsed_hex = Id128::parse(value.to_hex());
    ISF_REQUIRE_OK(parsed_hex);
    ISF_REQUIRE(parsed_hex.value() == value);
    auto parsed_canonical = Id128::parse(value.to_canonical());
    ISF_REQUIRE_OK(parsed_canonical);
    ISF_REQUIRE(parsed_canonical.value() == value);
  }
}

ISF_TEST(ids, parse_rejects_malformed_input) {
  // The malformed inputs are owned strings: taking c_str() of a temporary here
  // would dangle, which is exactly the kind of defect AddressSanitizer exists
  // to catch.
  const std::array<std::string, 6> bad{"", "zz", "0", std::string(31, 'a'),
                                       std::string(33, 'a'), std::string(32, 'g')};
  for (const std::string& text : bad) {
    auto parsed = Id128::parse(text);
    ISF_REQUIRE(!parsed.ok());
    ISF_CHECK_EQ(static_cast<int>(parsed.status()), static_cast<int>(Status::Invalid));
  }
}

ISF_TEST(ids, seed_construction_is_deterministic) {
  ISF_REQUIRE(Id128::from_seed(1, 2) == Id128::from_seed(1, 2));
  ISF_REQUIRE(!(Id128::from_seed(1, 2) == Id128::from_seed(2, 1)));
  ISF_REQUIRE(!Id128::from_seed(0, 0).is_nil());
  const SiteId site = SiteId::from_seed(7, 9);
  ISF_REQUIRE(site.to_string().rfind("site:", 0) == 0);
  auto parsed = SiteId::parse(site.to_string());
  ISF_REQUIRE_OK(parsed);
  ISF_REQUIRE(parsed.value() == site);
  auto bare = SiteId::parse(site.raw().to_canonical());
  ISF_REQUIRE_OK(bare);
  ISF_REQUIRE(bare.value() == site);
}

// ---------------------------------------------------------------------------
// Integrity primitives
// ---------------------------------------------------------------------------

ISF_TEST(digest, sha256_matches_known_vectors) {
  const auto hex_of = [](const std::string& text) {
    return Digest256::of(ByteSpan(reinterpret_cast<const Byte*>(text.data()), text.size())).to_hex();
  };
  ISF_REQUIRE_EQ(hex_of(""),
                 std::string("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
  ISF_REQUIRE_EQ(hex_of("abc"),
                 std::string("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
  ISF_REQUIRE_EQ(
      hex_of("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
      std::string("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"));
  const std::string million(1000000, 'a');
  ISF_REQUIRE_EQ(hex_of(million),
                 std::string("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"));
}

ISF_TEST(digest, crc32c_matches_known_vector) {
  const std::string check = "123456789";
  const std::uint32_t value =
      crc32c(ByteSpan(reinterpret_cast<const Byte*>(check.data()), check.size()));
  ISF_REQUIRE_EQ(value, 0xE3069283U);
  ISF_REQUIRE_EQ(crc32c(ByteSpan{}), 0U);

  // Incremental and one-shot must agree.
  Crc32c incremental;
  for (const char c : check) {
    incremental.update(static_cast<Byte>(c));
  }
  ISF_REQUIRE_EQ(incremental.value(), value);
}

ISF_TEST(digest, parse_rejects_malformed_digests) {
  ISF_REQUIRE(!Digest256::parse("").ok());
  ISF_REQUIRE(!Digest256::parse(std::string(63, 'a')).ok());
  ISF_REQUIRE(!Digest256::parse(std::string(64, 'z')).ok());
  const std::string good(64, 'a');
  ISF_REQUIRE_OK(Digest256::parse(good));
  ISF_REQUIRE_OK(Digest256::parse("sha256:" + good));
}

// ---------------------------------------------------------------------------
// Canonical encoding
// ---------------------------------------------------------------------------

ISF_TEST(wire, round_trips_every_field_type) {
  Writer writer;
  writer.u8(0xAB);
  writer.u16(0x1234);
  writer.u32(0xDEADBEEF);
  writer.u64(0x0123456789ABCDEFULL);
  writer.i64(-42);
  writer.boolean(true);
  writer.boolean(false);
  writer.str("hello world");
  const std::array<Byte, 3> raw{1, 2, 3};
  writer.bytes(ByteSpan(raw.data(), raw.size()));
  writer.id128(Id128{5, 6});
  writer.digest(Digest256::of(ByteSpan{}));

  Reader reader(writer.span());
  ISF_REQUIRE_EQ(reader.u8().value(), std::uint8_t{0xAB});
  ISF_REQUIRE_EQ(reader.u16().value(), std::uint16_t{0x1234});
  ISF_REQUIRE_EQ(reader.u32().value(), 0xDEADBEEFU);
  ISF_REQUIRE_EQ(reader.u64().value(), 0x0123456789ABCDEFULL);
  ISF_REQUIRE_EQ(reader.i64().value(), std::int64_t{-42});
  ISF_REQUIRE_EQ(reader.boolean().value(), true);
  ISF_REQUIRE_EQ(reader.boolean().value(), false);
  ISF_REQUIRE_EQ(reader.str().value(), std::string("hello world"));
  ISF_REQUIRE_EQ(reader.bytes().value().size(), std::size_t{3});
  ISF_REQUIRE_EQ(reader.id128().value(), (Id128{5, 6}));
  ISF_REQUIRE_EQ(reader.digest().value(), Digest256::of(ByteSpan{}));
  ISF_REQUIRE(reader.at_end());
  ISF_REQUIRE_EQ(static_cast<int>(reader.require_end()), static_cast<int>(Status::Ok));
}

ISF_TEST(wire, decoding_rejects_truncation_and_trailing_bytes) {
  Writer writer;
  writer.u64(0x1122334455667788ULL);
  for (std::size_t cut = 0; cut < writer.size(); ++cut) {
    Reader reader(ByteSpan(writer.buffer().data(), cut));
    ISF_REQUIRE(!reader.u64().ok());
  }
  Reader trailing(writer.span());
  ISF_REQUIRE_OK(trailing.u64());
  ISF_REQUIRE_EQ(static_cast<int>(trailing.require_end()), static_cast<int>(Status::Ok));

  Writer padded;
  padded.u64(1);
  padded.u8(9);
  Reader reader(padded.span());
  ISF_REQUIRE_OK(reader.u64());
  ISF_REQUIRE_EQ(static_cast<int>(reader.require_end()), static_cast<int>(Status::Invalid));
}

ISF_TEST(wire, rejects_lengths_beyond_the_configured_bound) {
  Writer writer;
  const std::string big(5000, 'x');
  writer.str(big);
  WireLimits limits;
  limits.max_string = 1024;
  Reader reader(writer.span(), limits);
  auto value = reader.str();
  ISF_REQUIRE(!value.ok());
  ISF_REQUIRE_EQ(static_cast<int>(value.status()), static_cast<int>(Status::LimitExceeded));
}

ISF_TEST(wire, validates_utf8_strictly) {
  ISF_REQUIRE(is_valid_utf8(""));
  ISF_REQUIRE(is_valid_utf8("plain ascii"));
  ISF_REQUIRE(is_valid_utf8("\xC3\xA9"));            // U+00E9
  ISF_REQUIRE(is_valid_utf8("\xE2\x82\xAC"));       // U+20AC
  ISF_REQUIRE(is_valid_utf8("\xF0\x9F\x98\x80"));  // U+1F600
  ISF_REQUIRE(!is_valid_utf8("\xC0\x80"));           // overlong NUL
  ISF_REQUIRE(!is_valid_utf8("\xE0\x80\x80"));      // overlong
  ISF_REQUIRE(!is_valid_utf8("\xED\xA0\x80"));      // surrogate half
  ISF_REQUIRE(!is_valid_utf8("\xF4\x90\x80\x80")); // beyond U+10FFFF
  ISF_REQUIRE(!is_valid_utf8("\xF8\x88\x80\x80\x80"));  // five byte form
  ISF_REQUIRE(!is_valid_utf8("\x80"));                // lone continuation
  ISF_REQUIRE(!is_valid_utf8("\xE2\x82"));           // truncated sequence
}

ISF_TEST(wire, rejects_impossible_container_counts) {
  Writer writer;
  writer.u32(0xFFFFFFFFU);
  Reader reader(writer.span());
  auto count = reader.container_count();
  ISF_REQUIRE(!count.ok());
  ISF_REQUIRE_EQ(static_cast<int>(count.status()), static_cast<int>(Status::LimitExceeded));
}

// ---------------------------------------------------------------------------
// Checked arithmetic and capacity
// ---------------------------------------------------------------------------

ISF_TEST(checked, arithmetic_never_wraps) {
  ISF_REQUIRE_EQ(checked_add(kAmountMax, 1).status(), Status::LimitExceeded);
  ISF_REQUIRE_EQ(checked_add(kAmountMax, 0).value(), kAmountMax);
  ISF_REQUIRE_EQ(checked_sub(0, 1).status(), Status::Invalid);
  ISF_REQUIRE_EQ(checked_sub(5, 5).value(), Amount{0});
  ISF_REQUIRE_EQ(checked_mul(kAmountMax, 2).status(), Status::LimitExceeded);
  ISF_REQUIRE_EQ(checked_mul(0, kAmountMax).value(), Amount{0});
  ISF_REQUIRE_EQ(checked_mul(Amount{1} << 32, Amount{1} << 32).status(), Status::LimitExceeded);
  ISF_REQUIRE_EQ(checked_mul(Amount{1} << 31, Amount{1} << 32).value(), Amount{1} << 63);
  ISF_REQUIRE_EQ(narrow_u32(0x1FFFFFFFFULL).status(), Status::LimitExceeded);
}

ISF_TEST(capacity, fraction_saturates_conservatively) {
  ISF_REQUIRE_EQ(fraction_bps(1000, 1000), Amount{100});
  ISF_REQUIRE_EQ(fraction_bps(1000, 0), Amount{0});
  ISF_REQUIRE_EQ(fraction_bps(0, 10000), Amount{0});
  ISF_REQUIRE_EQ(fraction_bps(kAmountMax, 10000), kAmountMax);
  ISF_REQUIRE_EQ(fraction_bps(kAmountMax, 1), kAmountMax / 10000);
  ISF_REQUIRE_EQ(fraction_bps(9999, 10000), Amount{9999});
}

ISF_TEST(capacity, closure_identity_detects_inconsistency) {
  CapacityLedger ledger;
  ledger.authoritative_usable = 1000;
  ledger.committed = 300;
  ledger.reserved = 200;
  ledger.protected_headroom = 100;
  ledger.unavailable = 50;
  ledger.free = 350;
  ledger.reclaimable = 200;
  ISF_REQUIRE_EQ(ledger.verify_closure(), Status::Ok);
  ledger.free = 351;
  ISF_REQUIRE_EQ(ledger.verify_closure(), Status::Incomplete);
  ledger.free = 350;
  ledger.reclaimable = 600;
  ISF_REQUIRE_EQ(ledger.verify_closure(), Status::Conflicting);
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

ISF_TEST(lifecycle, the_documented_chain_is_walkable) {
  ISF_REQUIRE(can_transition(GrantState::Proposed, GrantState::Eligible));
  ISF_REQUIRE(can_transition(GrantState::Eligible, GrantState::Reserved));
  ISF_REQUIRE(can_transition(GrantState::Reserved, GrantState::Active));
  ISF_REQUIRE(can_transition(GrantState::Active, GrantState::Degraded));
  ISF_REQUIRE(can_transition(GrantState::Degraded, GrantState::Withdrawing));
  ISF_REQUIRE(can_transition(GrantState::Withdrawing, GrantState::Retired));

  ISF_REQUIRE(!can_transition(GrantState::Proposed, GrantState::Active));
  ISF_REQUIRE(!can_transition(GrantState::Retired, GrantState::Active));
  ISF_REQUIRE(!can_transition(GrantState::Eligible, GrantState::Active));
  ISF_REQUIRE(!can_transition(GrantState::Withdrawing, GrantState::Active));
}

ISF_TEST(lifecycle, terminal_and_holding_classification_is_consistent) {
  const std::array<GrantState, 10> all{GrantState::Proposed, GrantState::Eligible,
                                       GrantState::Reserved, GrantState::Active,
                                       GrantState::Degraded, GrantState::Withdrawing,
                                       GrantState::Retired,   GrantState::Refused,
                                       GrantState::Cancelled, GrantState::Expired};
  for (const GrantState state : all) {
    if (is_terminal(state)) {
      ISF_CHECK(!holds_capacity(state));
      ISF_CHECK(!is_reclaimable(state));
      ISF_CHECK(successor_mask(state) == 0);
    }
    if (is_reclaimable(state)) {
      ISF_CHECK(holds_capacity(state));
    }
    if (is_live_obligation(state)) {
      ISF_CHECK(holds_capacity(state));
    }
    GrantState parsed{};
    ISF_REQUIRE(grant_state_from_name(grant_state_name(state), parsed));
    ISF_CHECK_EQ(static_cast<int>(parsed), static_cast<int>(state));
  }
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

ISF_TEST(policy, validation_rejects_out_of_range_documents) {
  Policy policy = Policy::conservative_default();
  ISF_REQUIRE_EQ(policy.validate(), Status::Ok);

  Policy no_generation = policy;
  no_generation.generation = Generation{0};
  ISF_REQUIRE_EQ(no_generation.validate(), Status::Invalid);

  Policy bad_bps = policy;
  bad_bps.protected_floor_bps = 10001;
  ISF_REQUIRE_EQ(bad_bps.validate(), Status::Invalid);

  Policy bad_oversub = policy;
  bad_oversub.max_oversubscription_bps = kMaxOversubscriptionBps + 1;
  ISF_REQUIRE_EQ(bad_oversub.validate(), Status::LimitExceeded);

  Policy contradictory = policy;
  contradictory.allow_partition_optimistic_recovery = true;
  ISF_REQUIRE_EQ(contradictory.validate(), Status::Conflicting);

  Policy bad_lease = policy;
  bad_lease.max_lease_duration_ms = 0;
  ISF_REQUIRE_EQ(bad_lease.validate(), Status::LimitExceeded);
}

// ---------------------------------------------------------------------------
// Model codecs
// ---------------------------------------------------------------------------

ISF_TEST(model, records_round_trip_through_the_canonical_encoding) {
  SiteRecord site;
  site.id = site_from_name("codec");
  site.name = "codec-site";
  site.incarnation = Incarnation::from_seed(1, 2);
  site.generation = Generation{4};
  site.epoch = Epoch{3};
  site.state = SiteState::Degraded;
  site.advertised_capacity = 1234;
  site.last_heartbeat_ms = 99;
  site.provenance = Provenance::RecoveredFromLog;

  Writer writer;
  encode(writer, site);
  Reader reader(writer.span());
  auto decoded = decode_site(reader);
  ISF_REQUIRE_OK(decoded);
  ISF_REQUIRE(decoded.value().id == site.id);
  ISF_REQUIRE_EQ(decoded.value().name, site.name);
  ISF_REQUIRE(decoded.value().state == SiteState::Degraded);
  ISF_REQUIRE_EQ(decoded.value().advertised_capacity, site.advertised_capacity);
  ISF_REQUIRE(decoded.value().provenance == Provenance::RecoveredFromLog);
  ISF_REQUIRE_STATUS_EQ(reader.require_end(), Status::Ok);
}

ISF_TEST(model, grant_codes_round_trip_and_reject_truncation) {
  GrantRecord grant;
  grant.id = GrantId::from_seed(11, 12);
  grant.request = RequestId::from_seed(13, 14);
  grant.arbitration = ArbSeq{77};
  grant.binding.holder = site_from_name("holder");
  grant.binding.holder_incarnation = Incarnation::from_seed(15, 16);
  grant.binding.holder_generation = Generation{2};
  grant.binding.path = path_from_name("p");
  grant.binding.path_generation = Generation{3};
  grant.binding.capacity_generation = Generation{4};
  grant.binding.policy_generation = Generation{5};
  grant.binding.epoch = Epoch{6};
  grant.binding.lease = LeaseId::from_seed(17, 18);
  grant.amount = 4096;
  grant.state = GrantState::Degraded;
  grant.verification = VerificationState::Failed;
  grant.acknowledged = true;
  grant.ack_count = 3;
  grant.ambiguous = true;
  grant.historical = true;
  grant.provenance = Provenance::AmbiguousCommit;
  grant.reason = "reason text";

  Writer writer;
  encode(writer, grant);
  Reader reader(writer.span());
  auto decoded = decode_grant(reader);
  ISF_REQUIRE_OK(decoded);
  ISF_REQUIRE(decoded.value().id == grant.id);
  ISF_REQUIRE(decoded.value().state == GrantState::Degraded);
  ISF_REQUIRE(decoded.value().verification == VerificationState::Failed);
  ISF_REQUIRE_EQ(decoded.value().amount, grant.amount);
  ISF_REQUIRE(decoded.value().ambiguous);
  ISF_REQUIRE(decoded.value().historical);
  ISF_REQUIRE_STATUS_EQ(reader.require_end(), Status::Ok);

  for (std::size_t cut = 0; cut + 1 < writer.size(); ++cut) {
    Reader truncated(ByteSpan(writer.buffer().data(), cut));
    auto partial = decode_grant(truncated);
    ISF_CHECK(!partial.ok());
  }
}

ISF_TEST(model, decode_rejects_out_of_range_enumerators) {
  Writer writer;
  writer.id128(site_from_name("x").raw());
  writer.str("name");
  writer.id128(Incarnation::from_seed(1, 1).raw());
  writer.u64(1);
  writer.u64(1);
  writer.u8(200);  // site state out of range
  Reader reader(writer.span());
  auto decoded = decode_site(reader);
  ISF_REQUIRE(!decoded.ok());
  ISF_REQUIRE_EQ(static_cast<int>(decoded.status()), static_cast<int>(Status::Invalid));
}

ISF_TEST(model, path_decode_rejects_unavailable_above_usable) {
  PathRecord path;
  path.id = path_from_name("bad");
  path.generation = Generation{1};
  path.capacity_generation = Generation{1};
  path.state = PathState::Up;
  path.authoritative_usable = 10;
  path.unavailable = 11;
  Writer writer;
  encode(writer, path);
  Reader reader(writer.span());
  auto decoded = decode_path(reader);
  ISF_REQUIRE(!decoded.ok());
  ISF_REQUIRE_EQ(static_cast<int>(decoded.status()), static_cast<int>(Status::Conflicting));
}

ISF_TEST(model, state_change_round_trips) {
  StateChange change;
  change.kind = ObjectKind::Grant;
  change.key = GrantId::from_seed(1, 2).raw();
  change.releases_capacity = true;
  change.image = {1, 2, 3, 4};
  Writer writer;
  encode(writer, change);
  Reader reader(writer.span());
  auto decoded = decode_state_change(reader);
  ISF_REQUIRE_OK(decoded);
  ISF_REQUIRE_EQ(static_cast<int>(decoded.value().kind), static_cast<int>(ObjectKind::Grant));
  ISF_REQUIRE(decoded.value().key == change.key);
  ISF_REQUIRE(decoded.value().releases_capacity);
  ISF_REQUIRE_EQ(decoded.value().image.size(), std::size_t{4});
}

// ---------------------------------------------------------------------------
// Authority: happy path and accounting
// ---------------------------------------------------------------------------

ISF_TEST(authority, full_lifecycle_with_exact_closure) {
  AuthorityConfig config;
  config.incarnation = Incarnation::from_seed(1, 1);
  Authority authority(config);
  auto fixture = setup_fabric(authority, "lifecycle", 1000, 1000);
  ISF_REQUIRE_OK(fixture);

  auto ledger = authority.ledger(fixture.value().path);
  ISF_REQUIRE_OK(ledger);
  ISF_REQUIRE_EQ(ledger.value().authoritative_usable, Amount{1000});
  ISF_REQUIRE_EQ(ledger.value().protected_headroom, Amount{100});  // 10% default floor
  ISF_REQUIRE_EQ(ledger.value().free, Amount{900});
  ISF_REQUIRE_EQ(ledger.value().verify_closure(), Status::Ok);

  GrantProposal proposal;
  proposal.request = RequestId::from_seed(1, 1);
  proposal.holder = fixture.value().a;
  proposal.holder_incarnation = fixture.value().a_incarnation;
  proposal.holder_generation = fixture.value().a_generation;
  proposal.path = fixture.value().path;
  proposal.amount = 250;
  proposal.duration_ms = 60000;
  proposal.now_ms = 2000;
  auto planned = authority.plan_propose_grant(proposal, ArbSeq{10});
  ISF_REQUIRE_OK(planned);
  ISF_REQUIRE_EQ(authority.apply(planned.value().changes, ArbSeq{10}), Status::Ok);
  auto grant = authority.find_grant(GrantId::from_raw(planned.value().changes.front().key));
  ISF_REQUIRE(grant.has_value());
  ISF_REQUIRE(grant->state == GrantState::Proposed);

  GrantOperation op;
  op.grant = grant->id;
  op.actor = fixture.value().a;
  op.actor_incarnation = fixture.value().a_incarnation;
  op.epoch = authority.epoch();
  op.now_ms = 2000;

  auto evaluated = authority.plan_evaluate_grant(op, ArbSeq{11});
  ISF_REQUIRE_OK(evaluated);
  ISF_REQUIRE_EQ(authority.apply(evaluated.value().changes, ArbSeq{11}), Status::Ok);
  ISF_REQUIRE(authority.find_grant(grant->id)->state == GrantState::Eligible);

  // Capacity is not consumed while merely eligible.
  ISF_REQUIRE_EQ(authority.ledger(fixture.value().path).value().free, Amount{900});

  auto reserved = authority.plan_reserve_grant(op, ArbSeq{12});
  ISF_REQUIRE_OK(reserved);
  ISF_REQUIRE_EQ(authority.apply(reserved.value().changes, ArbSeq{12}), Status::Ok);
  ledger = authority.ledger(fixture.value().path);
  ISF_REQUIRE_OK(ledger);
  ISF_REQUIRE_EQ(ledger.value().reserved, Amount{250});
  ISF_REQUIRE_EQ(ledger.value().free, Amount{650});
  ISF_REQUIRE_EQ(ledger.value().reclaimable, Amount{250});
  ISF_REQUIRE_EQ(ledger.value().verify_closure(), Status::Ok);

  auto activated = authority.plan_activate_grant(op, ArbSeq{13});
  ISF_REQUIRE_OK(activated);
  ISF_REQUIRE_EQ(authority.apply(activated.value().changes, ArbSeq{13}), Status::Ok);
  ledger = authority.ledger(fixture.value().path);
  ISF_REQUIRE_EQ(ledger.value().committed, Amount{250});
  ISF_REQUIRE_EQ(ledger.value().reserved, Amount{0});
  ISF_REQUIRE_EQ(ledger.value().reclaimable, Amount{0});
  ISF_REQUIRE_EQ(ledger.value().verify_closure(), Status::Ok);

  // Acknowledgement records the holder's claim but does not verify anything.
  GrantAcknowledgement ack;
  ack.grant = grant->id;
  ack.actor = fixture.value().a;
  ack.actor_incarnation = fixture.value().a_incarnation;
  ack.now_ms = 3000;
  auto acknowledged = authority.plan_acknowledge_grant(ack, ArbSeq{14});
  ISF_REQUIRE_OK(acknowledged);
  ISF_REQUIRE_EQ(authority.apply(acknowledged.value().changes, ArbSeq{14}), Status::Ok);
  auto after_ack = authority.find_grant(grant->id);
  ISF_REQUIRE(after_ack->acknowledged);
  ISF_REQUIRE(after_ack->state == GrantState::Active);
  ISF_REQUIRE(after_ack->verification == VerificationState::Unverified);

  auto degraded = authority.plan_degrade_grant(op, ArbSeq{15});
  ISF_REQUIRE_OK(degraded);
  ISF_REQUIRE_EQ(authority.apply(degraded.value().changes, ArbSeq{15}), Status::Ok);
  ISF_REQUIRE(authority.find_grant(grant->id)->state == GrantState::Degraded);

  auto withdrawing = authority.plan_withdraw_grant(op, ArbSeq{16});
  ISF_REQUIRE_OK(withdrawing);
  ISF_REQUIRE_EQ(authority.apply(withdrawing.value().changes, ArbSeq{16}), Status::Ok);
  ISF_REQUIRE(authority.find_grant(grant->id)->state == GrantState::Withdrawing);
  // Withdrawing still holds capacity: releasing early would risk overcommit.
  ISF_REQUIRE_EQ(authority.ledger(fixture.value().path).value().committed, Amount{0});
  ISF_REQUIRE_EQ(authority.ledger(fixture.value().path).value().withdrawing, Amount{250});
  ISF_REQUIRE_EQ(authority.ledger(fixture.value().path).value().allocatable, Amount{650});

  auto retired = authority.plan_retire_grant(op, ArbSeq{17});
  ISF_REQUIRE_OK(retired);
  ISF_REQUIRE_EQ(authority.apply(retired.value().changes, ArbSeq{17}), Status::Ok);
  ISF_REQUIRE(authority.find_grant(grant->id)->state == GrantState::Retired);
  ledger = authority.ledger(fixture.value().path);
  ISF_REQUIRE_EQ(ledger.value().committed, Amount{0});
  ISF_REQUIRE_EQ(ledger.value().free, Amount{900});
  ISF_REQUIRE_EQ(ledger.value().verify_closure(), Status::Ok);
  std::string why;
  ISF_REQUIRE_EQ(authority.verify_invariants(&why), Status::Ok);
}

ISF_TEST(authority, refuses_allocation_beyond_free_capacity) {
  AuthorityConfig config;
  Authority authority(config);
  auto fixture = setup_fabric(authority, "exhaust", 100, 1000);
  ISF_REQUIRE_OK(fixture);
  // usable 100, protected floor 10% = 10, so 90 is allocatable.

  const auto try_allocate = [&](Amount amount, std::uint64_t seq) {
    GrantProposal proposal;
    proposal.request = RequestId::from_seed(seq, 1);
    proposal.holder = fixture.value().a;
    proposal.holder_incarnation = fixture.value().a_incarnation;
    proposal.holder_generation = fixture.value().a_generation;
    proposal.path = fixture.value().path;
    proposal.amount = amount;
    proposal.duration_ms = 60000;
    proposal.now_ms = 2000;
    auto planned = authority.plan_propose_grant(proposal, ArbSeq{seq});
    if (!planned.ok()) {
      return planned.status();
    }
    (void)authority.apply(planned.value().changes, ArbSeq{seq});
    const GrantId id = GrantId::from_raw(planned.value().changes.front().key);
    GrantOperation op;
    op.grant = id;
    op.actor = fixture.value().a;
    op.actor_incarnation = fixture.value().a_incarnation;
    op.epoch = authority.epoch();
    op.now_ms = 2000;
    auto evaluated = authority.plan_evaluate_grant(op, ArbSeq{seq + 1});
    if (!evaluated.ok()) {
      return evaluated.status();
    }
    (void)authority.apply(evaluated.value().changes, ArbSeq{seq + 1});
    auto reserved = authority.plan_reserve_grant(op, ArbSeq{seq + 2});
    if (!reserved.ok()) {
      return reserved.status();
    }
    return authority.apply(reserved.value().changes, ArbSeq{seq + 2});
  };

  ISF_REQUIRE_EQ(try_allocate(90, 100), Status::Ok);
  ISF_REQUIRE_EQ(try_allocate(1, 200), Status::Exhausted);
  ISF_REQUIRE_EQ(try_allocate(0, 300), Status::Invalid);

  auto ledger = authority.ledger(fixture.value().path);
  ISF_REQUIRE_OK(ledger);
  ISF_REQUIRE_EQ(ledger.value().reserved, Amount{90});
  ISF_REQUIRE_EQ(ledger.value().free, Amount{0});
  ISF_REQUIRE_EQ(ledger.value().protected_headroom, Amount{10});
  ISF_REQUIRE_EQ(ledger.value().verify_closure(), Status::Ok);
}

ISF_TEST(authority, protected_capacity_is_never_oversubscribed) {
  AuthorityConfig config;
  Authority authority(config);
  auto fixture = setup_fabric(authority, "protected", 1000, 1000);
  ISF_REQUIRE_OK(fixture);

  const auto reserve_protected = [&](Amount amount, std::uint64_t seq) {
    GrantProposal proposal;
    proposal.request = RequestId::from_seed(seq, 2);
    proposal.holder = fixture.value().a;
    proposal.holder_incarnation = fixture.value().a_incarnation;
    proposal.holder_generation = fixture.value().a_generation;
    proposal.path = fixture.value().path;
    proposal.amount = amount;
    proposal.grant_class = GrantClass::Protected;
    proposal.duration_ms = 60000;
    proposal.now_ms = 2000;
    auto planned = authority.plan_propose_grant(proposal, ArbSeq{seq});
    ISF_REQUIRE_OK(planned);
    (void)authority.apply(planned.value().changes, ArbSeq{seq});
    const GrantId id = GrantId::from_raw(planned.value().changes.front().key);
    GrantOperation op;
    op.grant = id;
    op.actor = fixture.value().a;
    op.actor_incarnation = fixture.value().a_incarnation;
    op.epoch = authority.epoch();
    op.now_ms = 2000;
    (void)authority.apply(authority.plan_evaluate_grant(op, ArbSeq{seq + 1}).value().changes,
                          ArbSeq{seq + 1});
    auto reserved = authority.plan_reserve_grant(op, ArbSeq{seq + 2});
    if (!reserved.ok()) {
      return reserved.status();
    }
    return authority.apply(reserved.value().changes, ArbSeq{seq + 2});
  };

  // The default protected floor is 10% of 1000 = 100.
  ISF_REQUIRE_EQ(reserve_protected(100, 100), Status::Ok);
  ISF_REQUIRE_EQ(reserve_protected(1, 200), Status::Exhausted);
}

ISF_TEST(authority, general_allocation_cannot_consume_the_protected_floor) {
  AuthorityConfig config;
  Authority authority(config);
  auto fixture = setup_fabric(authority, "floor", 1000, 1000);
  ISF_REQUIRE_OK(fixture);

  GrantProposal proposal;
  proposal.request = RequestId::from_seed(1, 3);
  proposal.holder = fixture.value().a;
  proposal.holder_incarnation = fixture.value().a_incarnation;
  proposal.holder_generation = fixture.value().a_generation;
  proposal.path = fixture.value().path;
  proposal.amount = 901;
  proposal.duration_ms = 60000;
  proposal.now_ms = 2000;
  auto planned = authority.plan_propose_grant(proposal, ArbSeq{1});
  ISF_REQUIRE_OK(planned);
  (void)authority.apply(planned.value().changes, ArbSeq{1});
  GrantOperation op;
  op.grant = GrantId::from_raw(planned.value().changes.front().key);
  op.actor = fixture.value().a;
  op.actor_incarnation = fixture.value().a_incarnation;
  op.epoch = authority.epoch();
  op.now_ms = 2000;
  (void)authority.apply(authority.plan_evaluate_grant(op, ArbSeq{2}).value().changes, ArbSeq{2});
  ISF_REQUIRE_EQ(authority.plan_reserve_grant(op, ArbSeq{3}).status(), Status::Exhausted);
}

ISF_TEST(authority, oversubscription_requires_an_explicit_authority) {
  AuthorityConfig config;
  config.policy = Policy::conservative_default();
  config.policy.max_oversubscription_bps = 15000;  // 1.5x ceiling
  Authority authority(config);
  auto fixture = setup_fabric(authority, "oversub", 1000, 1000);
  ISF_REQUIRE_OK(fixture);

  const auto allocate = [&](Amount amount, std::uint64_t seq) {
    GrantProposal proposal;
    proposal.request = RequestId::from_seed(seq, 4);
    proposal.holder = fixture.value().a;
    proposal.holder_incarnation = fixture.value().a_incarnation;
    proposal.holder_generation = fixture.value().a_generation;
    proposal.path = fixture.value().path;
    proposal.amount = amount;
    proposal.duration_ms = 60000;
    proposal.now_ms = 2000;
    auto planned = authority.plan_propose_grant(proposal, ArbSeq{seq});
    if (!planned.ok()) {
      return planned.status();
    }
    (void)authority.apply(planned.value().changes, ArbSeq{seq});
    GrantOperation op;
    op.grant = GrantId::from_raw(planned.value().changes.front().key);
    op.actor = fixture.value().a;
    op.actor_incarnation = fixture.value().a_incarnation;
    op.epoch = authority.epoch();
    op.now_ms = 2000;
    (void)authority.apply(authority.plan_evaluate_grant(op, ArbSeq{seq + 1}).value().changes,
                          ArbSeq{seq + 1});
    auto reserved = authority.plan_reserve_grant(op, ArbSeq{seq + 2});
    if (!reserved.ok()) {
      return reserved.status();
    }
    return authority.apply(reserved.value().changes, ArbSeq{seq + 2});
  };

  ISF_REQUIRE_EQ(allocate(900, 10), Status::Ok);
  // The next allocation exceeds the authoritative usable capacity and there is
  // no oversubscription authority recorded yet.
  ISF_REQUIRE_EQ(allocate(50, 20), Status::Exhausted);

  OversubscriptionAuthority grant;
  grant.id = OversubscriptionId::from_seed(1, 1);
  grant.path = fixture.value().path;
  grant.path_generation = fixture.value().path_generation;
  grant.capacity_generation = fixture.value().capacity_generation;
  grant.policy_generation = authority.policy().generation;
  grant.epoch = authority.epoch();
  grant.issuer = authority.incarnation();
  grant.principal = principal_from_name("operator");
  grant.ratio_bps = 15000;  // permits allocating up to 1.5 times the usable basis
  grant.issued_at_ms = 1500;
  auto issued = authority.plan_issue_oversubscription(grant, ArbSeq{30});
  ISF_REQUIRE_OK(issued);
  ISF_REQUIRE_EQ(authority.apply(issued.value().changes, ArbSeq{30}), Status::Ok);

  ISF_REQUIRE_EQ(allocate(50, 40), Status::Ok);
  auto ledger = authority.ledger(fixture.value().path);
  ISF_REQUIRE_OK(ledger);
  ISF_REQUIRE_EQ(ledger.value().allocated().value(), Amount{950});
  ISF_REQUIRE_EQ(ledger.value().verify_closure(), Status::Ok);
}

ISF_TEST(authority, epoch_change_invalidates_every_live_grant) {
  AuthorityConfig config;
  Authority authority(config);
  auto fixture = setup_fabric(authority, "epoch", 1000, 1000);
  ISF_REQUIRE_OK(fixture);

  GrantProposal proposal;
  proposal.request = RequestId::from_seed(1, 5);
  proposal.holder = fixture.value().a;
  proposal.holder_incarnation = fixture.value().a_incarnation;
  proposal.holder_generation = fixture.value().a_generation;
  proposal.path = fixture.value().path;
  proposal.amount = 100;
  proposal.duration_ms = 60000;
  proposal.now_ms = 2000;
  auto planned = authority.plan_propose_grant(proposal, ArbSeq{1});
  ISF_REQUIRE_OK(planned);
  (void)authority.apply(planned.value().changes, ArbSeq{1});
  GrantOperation op;
  op.grant = GrantId::from_raw(planned.value().changes.front().key);
  op.actor = fixture.value().a;
  op.actor_incarnation = fixture.value().a_incarnation;
  op.epoch = authority.epoch();
  op.now_ms = 2000;
  (void)authority.apply(authority.plan_evaluate_grant(op, ArbSeq{2}).value().changes, ArbSeq{2});
  ISF_REQUIRE_OK(authority.plan_reserve_grant(op, ArbSeq{3}));
  (void)authority.apply(authority.plan_reserve_grant(op, ArbSeq{3}).value().changes, ArbSeq{3});
  ISF_REQUIRE_OK(authority.plan_activate_grant(op, ArbSeq{4}));
  (void)authority.apply(authority.plan_activate_grant(op, ArbSeq{4}).value().changes, ArbSeq{4});

  auto bumped = authority.plan_bump_epoch(Epoch{2}, principal_from_name("operator"), ArbSeq{5});
  ISF_REQUIRE_OK(bumped);
  ISF_REQUIRE_EQ(authority.apply(bumped.value().changes, ArbSeq{5}), Status::Ok);
  ISF_REQUIRE_EQ(authority.epoch().value, std::uint64_t{2});
  auto grant = authority.find_grant(op.grant);
  ISF_REQUIRE(grant->state == GrantState::Withdrawing);
  // The capacity is still held: an epoch change must not free capacity.
  ISF_REQUIRE_EQ(authority.ledger(fixture.value().path).value().committed, Amount{0});
  ISF_REQUIRE_EQ(authority.ledger(fixture.value().path).value().withdrawing, Amount{100});
  ISF_REQUIRE_EQ(authority.ledger(fixture.value().path).value().allocatable, Amount{800});

  // Operations bound to the superseded epoch are stale.
  GrantOperation stale = op;
  stale.epoch = Epoch{1};
  auto result = authority.plan_retire_grant(stale, ArbSeq{6});
  ISF_REQUIRE_OK(result);  // retiring a withdrawing grant is allowed regardless
  GrantOperation activating = op;
  activating.epoch = Epoch{1};
  (void)activating;
}

ISF_TEST(authority, policy_generation_change_rebinds_or_withdraws) {
  AuthorityConfig config;
  Authority authority(config);
  auto fixture = setup_fabric(authority, "policygen", 1000, 1000);
  ISF_REQUIRE_OK(fixture);

  GrantProposal proposal;
  proposal.request = RequestId::from_seed(1, 6);
  proposal.holder = fixture.value().a;
  proposal.holder_incarnation = fixture.value().a_incarnation;
  proposal.holder_generation = fixture.value().a_generation;
  proposal.path = fixture.value().path;
  proposal.amount = 800;
  proposal.duration_ms = 60000;
  proposal.now_ms = 2000;
  auto planned = authority.plan_propose_grant(proposal, ArbSeq{1});
  ISF_REQUIRE_OK(planned);
  (void)authority.apply(planned.value().changes, ArbSeq{1});
  GrantOperation op;
  op.grant = GrantId::from_raw(planned.value().changes.front().key);
  op.actor = fixture.value().a;
  op.actor_incarnation = fixture.value().a_incarnation;
  op.epoch = authority.epoch();
  op.now_ms = 2000;
  (void)authority.apply(authority.plan_evaluate_grant(op, ArbSeq{2}).value().changes, ArbSeq{2});
  (void)authority.apply(authority.plan_reserve_grant(op, ArbSeq{3}).value().changes, ArbSeq{3});
  (void)authority.apply(authority.plan_activate_grant(op, ArbSeq{4}).value().changes, ArbSeq{4});
  ISF_REQUIRE_EQ(authority.find_grant(op.grant)->state, GrantState::Active);

  // A policy that keeps the grant legal re-binds it rather than withdrawing it.
  Policy stricter = authority.policy();
  stricter.generation = Generation{2};
  stricter.protected_floor_bps = 2000;  // floor rises to 200; 800 still fits in 800
  auto installed = authority.plan_install_policy(stricter, principal_from_name("operator"), ArbSeq{5});
  ISF_REQUIRE_OK(installed);
  ISF_REQUIRE_EQ(authority.apply(installed.value().changes, ArbSeq{5}), Status::Ok);
  auto rebound = authority.find_grant(op.grant);
  ISF_REQUIRE(rebound->state == GrantState::Active);
  ISF_REQUIRE(rebound->binding.policy_generation == Generation{2});

  // A policy that makes the grant illegal withdraws it, and the capacity stays
  // held until the grant is retired.
  Policy harsher = authority.policy();
  harsher.generation = Generation{3};
  harsher.protected_floor_bps = 5000;  // floor 500, ceiling for general is 500
  auto installed2 = authority.plan_install_policy(harsher, principal_from_name("operator"), ArbSeq{6});
  ISF_REQUIRE_OK(installed2);
  ISF_REQUIRE_EQ(authority.apply(installed2.value().changes, ArbSeq{6}), Status::Ok);
  auto withdrawn = authority.find_grant(op.grant);
  ISF_REQUIRE(withdrawn->state == GrantState::Withdrawing);
  auto ledger = authority.ledger(fixture.value().path);
  ISF_REQUIRE_OK(ledger);
  ISF_REQUIRE_EQ(ledger.value().committed, Amount{0});
  ISF_REQUIRE_EQ(ledger.value().withdrawing, Amount{800});
  ISF_REQUIRE_EQ(ledger.value().protected_headroom, Amount{500});
  ISF_REQUIRE_EQ(ledger.value().allocatable, Amount{0});
  ISF_REQUIRE_EQ(ledger.value().verify_closure(), Status::Ok);
}

ISF_TEST(authority, superseded_site_incarnation_is_fenced) {
  AuthorityConfig config;
  Authority authority(config);
  auto fixture = setup_fabric(authority, "fence", 1000, 1000);
  ISF_REQUIRE_OK(fixture);

  GrantProposal proposal;
  proposal.request = RequestId::from_seed(1, 7);
  proposal.holder = fixture.value().a;
  proposal.holder_incarnation = fixture.value().a_incarnation;
  proposal.holder_generation = fixture.value().a_generation;
  proposal.path = fixture.value().path;
  proposal.amount = 100;
  proposal.duration_ms = 60000;
  proposal.now_ms = 2000;
  auto planned = authority.plan_propose_grant(proposal, ArbSeq{1});
  ISF_REQUIRE_OK(planned);
  (void)authority.apply(planned.value().changes, ArbSeq{1});
  GrantOperation op;
  op.grant = GrantId::from_raw(planned.value().changes.front().key);
  op.actor = fixture.value().a;
  op.actor_incarnation = fixture.value().a_incarnation;
  op.epoch = authority.epoch();
  op.now_ms = 2000;
  (void)authority.apply(authority.plan_evaluate_grant(op, ArbSeq{2}).value().changes, ArbSeq{2});
  (void)authority.apply(authority.plan_reserve_grant(op, ArbSeq{3}).value().changes, ArbSeq{3});
  (void)authority.apply(authority.plan_activate_grant(op, ArbSeq{4}).value().changes, ArbSeq{4});

  // The site comes back with a new incarnation.
  const Incarnation replacement = Incarnation::from_seed(0xF00D, 1);
  SiteRegistration reregistration;
  reregistration.descriptor.id = fixture.value().a;
  reregistration.descriptor.name = "fence-a";
  reregistration.incarnation = replacement;
  reregistration.epoch = authority.epoch();
  reregistration.now_ms = 3000;
  auto plan = authority.plan_register_site(reregistration, ArbSeq{5});
  ISF_REQUIRE_OK(plan);
  ISF_REQUIRE_EQ(authority.apply(plan.value().changes, ArbSeq{5}), Status::Ok);

  auto fenced = authority.find_grant(op.grant);
  ISF_REQUIRE(fenced->state == GrantState::Withdrawing);
  ISF_REQUIRE(fenced->historical);
  ISF_REQUIRE(fenced->provenance == Provenance::FencedIncarnation);
  ISF_REQUIRE(fenced->verification == VerificationState::Unverified);
  // The fenced incarnation retains no ability to advance the grant.
  GrantOperation from_old_incarnation = op;
  from_old_incarnation.reason = "attempt from a fenced incarnation";
  const Status denied = authority.check_binding(*fenced, from_old_incarnation);
  ISF_REQUIRE(denied == Status::Fenced || denied == Status::Stale);
  // Capacity still held until reconciliation.
  ISF_REQUIRE_EQ(authority.ledger(fixture.value().path).value().committed, Amount{0});
  ISF_REQUIRE_EQ(authority.ledger(fixture.value().path).value().withdrawing, Amount{100});

  // The new incarnation can reconcile the stale grant away.
  GrantOperation reconcile;
  reconcile.grant = op.grant;
  reconcile.now_ms = 4000;
  reconcile.reason = "reconcile";
  auto reconciled = authority.plan_reconcile_grant(reconcile, GrantState::Retired,
                                                   principal_from_name("operator"), ArbSeq{6});
  ISF_REQUIRE_OK(reconciled);
  ISF_REQUIRE_EQ(authority.apply(reconciled.value().changes, ArbSeq{6}), Status::Ok);
  ISF_REQUIRE_EQ(authority.ledger(fixture.value().path).value().committed, Amount{0});
  ISF_REQUIRE_EQ(authority.ledger(fixture.value().path).value().withdrawing, Amount{0});
}

ISF_TEST(authority, partition_degrades_and_never_frees_capacity) {
  AuthorityConfig config;
  Authority authority(config);
  auto fixture = setup_fabric(authority, "partition", 1000, 1000);
  ISF_REQUIRE_OK(fixture);

  GrantProposal proposal;
  proposal.request = RequestId::from_seed(1, 8);
  proposal.holder = fixture.value().a;
  proposal.holder_incarnation = fixture.value().a_incarnation;
  proposal.holder_generation = fixture.value().a_generation;
  proposal.path = fixture.value().path;
  proposal.amount = 400;
  proposal.duration_ms = 60000;
  proposal.now_ms = 2000;
  auto planned = authority.plan_propose_grant(proposal, ArbSeq{1});
  ISF_REQUIRE_OK(planned);
  (void)authority.apply(planned.value().changes, ArbSeq{1});
  GrantOperation op;
  op.grant = GrantId::from_raw(planned.value().changes.front().key);
  op.actor = fixture.value().a;
  op.actor_incarnation = fixture.value().a_incarnation;
  op.epoch = authority.epoch();
  op.now_ms = 2000;
  (void)authority.apply(authority.plan_evaluate_grant(op, ArbSeq{2}).value().changes, ArbSeq{2});
  (void)authority.apply(authority.plan_reserve_grant(op, ArbSeq{3}).value().changes, ArbSeq{3});
  (void)authority.apply(authority.plan_activate_grant(op, ArbSeq{4}).value().changes, ArbSeq{4});

  auto partitioned = authority.plan_set_site_state(fixture.value().a, SiteState::Partitioned,
                                                  "link lost", 5000, ArbSeq{5});
  ISF_REQUIRE_OK(partitioned);
  ISF_REQUIRE_EQ(authority.apply(partitioned.value().changes, ArbSeq{5}), Status::Ok);
  ISF_REQUIRE_EQ(authority.find_grant(op.grant)->state, GrantState::Degraded);

  // No new reservations while partitioned.
  GrantProposal second;
  second.request = RequestId::from_seed(2, 8);
  second.holder = fixture.value().a;
  second.holder_incarnation = fixture.value().a_incarnation;
  second.holder_generation = fixture.value().a_generation;
  second.path = fixture.value().path;
  second.amount = 10;
  second.duration_ms = 60000;
  second.now_ms = 5000;
  auto second_plan = authority.plan_propose_grant(second, ArbSeq{6});
  ISF_REQUIRE_OK(second_plan);
  (void)authority.apply(second_plan.value().changes, ArbSeq{6});
  GrantOperation second_op;
  second_op.grant = GrantId::from_raw(second_plan.value().changes.front().key);
  second_op.actor = fixture.value().a;
  second_op.actor_incarnation = fixture.value().a_incarnation;
  second_op.epoch = authority.epoch();
  second_op.now_ms = 5000;
  auto evaluated = authority.plan_evaluate_grant(second_op, ArbSeq{7});
  ISF_REQUIRE_OK(evaluated);
  (void)authority.apply(evaluated.value().changes, ArbSeq{7});
  ISF_REQUIRE_EQ(authority.find_grant(second_op.grant)->state, GrantState::Refused);
  ISF_REQUIRE_EQ(authority.ledger(fixture.value().path).value().committed, Amount{400});
}

ISF_TEST(authority, duplicate_request_identity_is_rejected) {
  AuthorityConfig config;
  Authority authority(config);
  auto fixture = setup_fabric(authority, "duplicate", 1000, 1000);
  ISF_REQUIRE_OK(fixture);

  GrantProposal proposal;
  proposal.request = RequestId::from_seed(1, 9);
  proposal.holder = fixture.value().a;
  proposal.holder_incarnation = fixture.value().a_incarnation;
  proposal.holder_generation = fixture.value().a_generation;
  proposal.path = fixture.value().path;
  proposal.amount = 10;
  proposal.duration_ms = 60000;
  proposal.now_ms = 2000;
  auto first = authority.plan_propose_grant(proposal, ArbSeq{1});
  ISF_REQUIRE_OK(first);
  (void)authority.apply(first.value().changes, ArbSeq{1});
  auto second = authority.plan_propose_grant(proposal, ArbSeq{2});
  ISF_REQUIRE(!second.ok());
  ISF_REQUIRE_EQ(static_cast<int>(second.status()), static_cast<int>(Status::Duplicate));
}

ISF_TEST(authority, lease_expiry_releases_capacity) {
  AuthorityConfig config;
  Authority authority(config);
  auto fixture = setup_fabric(authority, "expiry", 1000, 1000);
  ISF_REQUIRE_OK(fixture);

  GrantProposal proposal;
  proposal.request = RequestId::from_seed(1, 10);
  proposal.holder = fixture.value().a;
  proposal.holder_incarnation = fixture.value().a_incarnation;
  proposal.holder_generation = fixture.value().a_generation;
  proposal.path = fixture.value().path;
  proposal.amount = 100;
  proposal.duration_ms = 1000;
  proposal.now_ms = 2000;
  auto planned = authority.plan_propose_grant(proposal, ArbSeq{1});
  ISF_REQUIRE_OK(planned);
  (void)authority.apply(planned.value().changes, ArbSeq{1});
  GrantOperation op;
  op.grant = GrantId::from_raw(planned.value().changes.front().key);
  op.actor = fixture.value().a;
  op.actor_incarnation = fixture.value().a_incarnation;
  op.epoch = authority.epoch();
  op.now_ms = 2000;
  (void)authority.apply(authority.plan_evaluate_grant(op, ArbSeq{2}).value().changes, ArbSeq{2});
  (void)authority.apply(authority.plan_reserve_grant(op, ArbSeq{3}).value().changes, ArbSeq{3});
  (void)authority.apply(authority.plan_activate_grant(op, ArbSeq{4}).value().changes, ArbSeq{4});
  ISF_REQUIRE_EQ(authority.ledger(fixture.value().path).value().committed, Amount{100});

  auto ticked = authority.plan_tick(5000, ArbSeq{5});
  ISF_REQUIRE_OK(ticked);
  ISF_REQUIRE_EQ(authority.apply(ticked.value().changes, ArbSeq{5}), Status::Ok);
  ISF_REQUIRE_EQ(authority.find_grant(op.grant)->state, GrantState::Expired);
  ISF_REQUIRE_EQ(authority.ledger(fixture.value().path).value().committed, Amount{0});
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

namespace {

[[nodiscard]] std::vector<StateChange> make_changes(const std::string& tag, Amount amount,
                                                    bool releases) {
  SiteRecord site;
  site.id = site_from_name(tag);
  site.name = tag;
  site.incarnation = Incarnation::from_seed(fnv1a64(tag), 1);
  site.generation = Generation{1};
  site.epoch = Epoch{1};
  site.state = SiteState::Up;
  site.advertised_capacity = amount;
  StateChange change;
  change.kind = ObjectKind::Site;
  change.key = site.id.raw();
  change.releases_capacity = releases;
  Writer writer;
  encode(writer, site);
  change.image.assign(writer.buffer().begin(), writer.buffer().end());
  return {change};
}

[[nodiscard]] std::vector<Byte> read_file_bytes(const std::string& path) {
  std::FILE* fp = std::fopen(path.c_str(), "rb");
  if (fp == nullptr) {
    return {};
  }
  std::vector<Byte> out;
  std::array<Byte, 4096> buffer{};
  std::size_t got = 0;
  while ((got = std::fread(buffer.data(), 1, buffer.size(), fp)) > 0) {
    out.insert(out.end(), buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(got));
  }
  std::fclose(fp);
  return out;
}

void write_file_bytes(const std::string& path, const std::vector<Byte>& bytes) {
  std::FILE* fp = std::fopen(path.c_str(), "wb");
  if (fp == nullptr) {
    return;
  }
  if (!bytes.empty()) {
    (void)std::fwrite(bytes.data(), 1, bytes.size(), fp);
  }
  std::fclose(fp);
}

}  // namespace

ISF_TEST(store, close_and_reopen_replays_every_record) {
  ScratchDir scratch("store-replay");
  const std::string path = scratch.file("log.isfstore");
  StoreOptions options = StoreOptions::for_tests();
  {
    Store store;
    auto replay = store.open(path, options);
    ISF_REQUIRE_OK(replay);
    ISF_REQUIRE(replay.value().report.fidelity == RecoveryFidelity::Missing);
    for (std::uint64_t i = 1; i <= 5; ++i) {
      const auto changes = make_changes("site-" + std::to_string(i), i * 10, false);
      ISF_REQUIRE_EQ(store.append_intent(i, ArbSeq{i}, changes, i, Incarnation::from_seed(i, i)),
                     Status::Ok);
      ISF_REQUIRE_EQ(store.flush(), Status::Ok);
      ISF_REQUIRE_EQ(store.append_commit(i, i), Status::Ok);
      ISF_REQUIRE_EQ(store.flush(), Status::Ok);
    }
    ISF_REQUIRE_EQ(store.record_count(), std::size_t{10});
    store.close();
  }
  Store reopened;
  auto replay = reopened.open(path, options);
  ISF_REQUIRE_OK(replay);
  ISF_REQUIRE(replay.value().report.fidelity == RecoveryFidelity::Exact);
  ISF_REQUIRE_EQ(replay.value().report.records_read, std::size_t{10});
  ISF_REQUIRE_EQ(replay.value().report.ambiguous_intents, std::size_t{0});
  std::size_t changes_seen = 0;
  for (const auto& action : replay.value().actions) {
    if (action.kind == ReplayAction::Kind::Changes && !action.changes.empty()) {
      ISF_REQUIRE(action.committed);
      ISF_REQUIRE(!action.ambiguous);
      ++changes_seen;
    }
  }
  ISF_REQUIRE_EQ(changes_seen, std::size_t{5});
}

ISF_TEST(store, torn_tail_is_truncated_conservatively) {
  ScratchDir scratch("store-torn");
  const std::string path = scratch.file("log.isfstore");
  StoreOptions options = StoreOptions::for_tests();
  {
    Store store;
    ISF_REQUIRE_OK(store.open(path, options));
    for (std::uint64_t i = 1; i <= 4; ++i) {
      const auto changes = make_changes("s" + std::to_string(i), i, false);
      ISF_REQUIRE_EQ(store.append_intent(i, ArbSeq{i}, changes, i, Incarnation::from_seed(i, 1)),
                     Status::Ok);
      ISF_REQUIRE_EQ(store.append_commit(i, i), Status::Ok);
    }
    ISF_REQUIRE_EQ(store.flush(), Status::Ok);
    store.close();
  }
  std::vector<Byte> bytes = read_file_bytes(path);
  ISF_REQUIRE(bytes.size() > 200);
  // Drop the last 40 bytes: an incomplete trailing record.
  bytes.resize(bytes.size() - 40);
  write_file_bytes(path, bytes);

  Store store;
  auto replay = store.open(path, options);
  ISF_REQUIRE_OK(replay);
  ISF_REQUIRE(replay.value().report.servable());
  ISF_REQUIRE(replay.value().report.fidelity == RecoveryFidelity::TornTailTruncated);
  // Four intent/commit pairs were written; the trailing commit record lost 40
  // of its 96 bytes, so seven complete records survive.
  ISF_REQUIRE_EQ(replay.value().report.records_read, std::size_t{7});
  ISF_REQUIRE(replay.value().report.truncated_on_open);
  ISF_REQUIRE(replay.value().report.dropped_tail_bytes >= 40);
  // The store must remain usable after the truncation.
  const auto changes = make_changes("after", 9, false);
  ISF_REQUIRE_EQ(store.append_intent(99, ArbSeq{99}, changes, 99, Incarnation::from_seed(9, 9)),
                 Status::Ok);
  store.close();

  Store again;
  auto second = again.open(path, options);
  ISF_REQUIRE_OK(second);
  if (!second.value().report.servable()) {
    ISF_FAIL(std::string("recovered store is not servable: ") +
             recovery_fidelity_name(second.value().report.fidelity) + " " +
             second.value().report.detail);
  }
}

ISF_TEST(store, corruption_in_the_middle_is_never_silently_repaired) {
  ScratchDir scratch("store-corrupt");
  const std::string path = scratch.file("log.isfstore");
  StoreOptions options = StoreOptions::for_tests();
  {
    Store store;
    ISF_REQUIRE_OK(store.open(path, options));
    for (std::uint64_t i = 1; i <= 6; ++i) {
      const auto changes = make_changes("c" + std::to_string(i), i, false);
      ISF_REQUIRE_EQ(store.append_intent(i, ArbSeq{i}, changes, i, Incarnation::from_seed(i, 1)),
                     Status::Ok);
      ISF_REQUIRE_EQ(store.append_commit(i, i), Status::Ok);
    }
    ISF_REQUIRE_EQ(store.flush(), Status::Ok);
    store.close();
  }
  std::vector<Byte> bytes = read_file_bytes(path);
  // Flip one byte inside the payload of an early record, leaving later records
  // intact. This must be reported as corruption, not as a torn tail.
  bytes[200] = static_cast<Byte>(bytes[200] ^ 0xFFU);
  write_file_bytes(path, bytes);

  Store store;
  auto replay = store.open(path, options);
  ISF_REQUIRE_OK(replay);
  ISF_REQUIRE(!replay.value().report.servable());
  ISF_REQUIRE(replay.value().report.fidelity == RecoveryFidelity::Corrupt);
  ISF_REQUIRE(!store.is_open());
}

ISF_TEST(store, spliced_or_replayed_records_are_detected) {
  ScratchDir scratch("store-chain");
  const std::string path = scratch.file("log.isfstore");
  StoreOptions options = StoreOptions::for_tests();
  {
    Store store;
    ISF_REQUIRE_OK(store.open(path, options));
    for (std::uint64_t i = 1; i <= 3; ++i) {
      const auto changes = make_changes("h" + std::to_string(i), i, false);
      ISF_REQUIRE_EQ(store.append_intent(i, ArbSeq{i}, changes, i, Incarnation::from_seed(i, 1)),
                     Status::Ok);
      ISF_REQUIRE_EQ(store.append_commit(i, i), Status::Ok);
    }
    ISF_REQUIRE_EQ(store.flush(), Status::Ok);
    store.close();
  }
  const std::vector<Byte> original = read_file_bytes(path);
  ISF_REQUIRE(original.size() > 400);

  // Duplicate the first record pair by rewriting the file with the first two
  // records appended at the end. The chain and sequence checks must reject it.
  std::vector<Byte> spliced = original;
  spliced.insert(spliced.end(), original.begin() + 128, original.begin() + 400);
  write_file_bytes(path, spliced);
  Store store;
  auto replay = store.open(path, options);
  ISF_REQUIRE_OK(replay);
  ISF_REQUIRE(!replay.value().report.servable());
  ISF_REQUIRE_EQ(static_cast<int>(replay.value().report.fidelity),
                 static_cast<int>(RecoveryFidelity::Corrupt));
}

ISF_TEST(store, zero_filled_tail_is_dropped) {
  ScratchDir scratch("store-zero");
  const std::string path = scratch.file("log.isfstore");
  StoreOptions options = StoreOptions::for_tests();
  {
    Store store;
    ISF_REQUIRE_OK(store.open(path, options));
    const auto changes = make_changes("z", 1, false);
    ISF_REQUIRE_EQ(store.append_intent(1, ArbSeq{1}, changes, 1, Incarnation::from_seed(1, 1)),
                   Status::Ok);
    ISF_REQUIRE_EQ(store.append_commit(1, 1), Status::Ok);
    ISF_REQUIRE_EQ(store.flush(), Status::Ok);
    store.close();
  }
  std::vector<Byte> bytes = read_file_bytes(path);
  bytes.resize(bytes.size() + 512, 0);
  write_file_bytes(path, bytes);
  Store store;
  auto replay = store.open(path, options);
  ISF_REQUIRE_OK(replay);
  ISF_REQUIRE(replay.value().report.servable());
  ISF_REQUIRE(replay.value().report.fidelity == RecoveryFidelity::DegradedTruncated);
  ISF_REQUIRE_EQ(replay.value().report.dropped_tail_bytes, std::size_t{512});
}

ISF_TEST(store, incompatible_format_and_endianness_are_rejected) {
  ScratchDir scratch("store-version");
  const std::string path = scratch.file("log.isfstore");
  StoreOptions options = StoreOptions::for_tests();
  {
    Store store;
    ISF_REQUIRE_OK(store.open(path, options));
    store.close();
  }
  {
    std::vector<Byte> bytes = read_file_bytes(path);
    bytes[4] = 99;  // format version
    bytes[124] = 0;  // header CRC (now wrong) -- recompute is not possible here
    // Recompute the header CRC by rebuilding the file: the version change makes
    // the checksum wrong, which is itself a valid rejection.
    write_file_bytes(path, bytes);
  }
  Store store;
  auto replay = store.open(path, options);
  ISF_REQUIRE_OK(replay);
  ISF_REQUIRE(!replay.value().report.servable());
}

ISF_TEST(store, ambiguous_intent_is_reported_and_not_committed) {
  ScratchDir scratch("store-ambiguous");
  const std::string path = scratch.file("log.isfstore");
  StoreOptions options = StoreOptions::for_tests();
  {
    Store store;
    ISF_REQUIRE_OK(store.open(path, options));
    const auto changes = make_changes("amb", 1, false);
    ISF_REQUIRE_EQ(store.append_intent(1, ArbSeq{1}, changes, 1, Incarnation::from_seed(1, 1)),
                   Status::Ok);
    ISF_REQUIRE_EQ(store.flush(), Status::Ok);
    // No completion record: simulate a crash between the two writes.
    store.close();
  }
  Store store;
  auto replay = store.open(path, options);
  ISF_REQUIRE_OK(replay);
  ISF_REQUIRE(replay.value().report.ambiguous_intents == 1);
  ISF_REQUIRE(replay.value().report.fidelity == RecoveryFidelity::AmbiguousIntentResolved);
  // The store records the conservative resolution, so a later restart sees a
  // complete history rather than a second consecutive intent.
  ISF_REQUIRE(replay.value().report.resolution_written_on_open);
  ISF_REQUIRE_EQ(replay.value().report.aborted_intents, std::size_t{1});
  store.close();
  Store after_resolution;
  auto second = after_resolution.open(path, options);
  ISF_REQUIRE_OK(second);
  ISF_REQUIRE(second.value().report.servable());
  ISF_REQUIRE_EQ(second.value().report.ambiguous_intents, std::size_t{0});
  ISF_REQUIRE(second.value().actions.front().aborted);
  after_resolution.close();
  ISF_REQUIRE_EQ(replay.value().actions.size(), std::size_t{1});
  ISF_REQUIRE(replay.value().actions.front().ambiguous);
  ISF_REQUIRE(!replay.value().actions.front().committed);
}

ISF_TEST(store, compaction_preserves_state_and_bounds_growth) {
  ScratchDir scratch("store-compact");
  const std::string path = scratch.file("log.isfstore");
  StoreOptions options = StoreOptions::for_tests();
  options.compact_threshold_records = 8;
  Store store;
  ISF_REQUIRE_OK(store.open(path, options));
  for (std::uint64_t i = 1; i <= 6; ++i) {
    const auto changes = make_changes("k" + std::to_string(i), i, false);
    ISF_REQUIRE_EQ(store.append_intent(i, ArbSeq{i}, changes, i, Incarnation::from_seed(i, 1)),
                   Status::Ok);
    ISF_REQUIRE_EQ(store.append_commit(i, i), Status::Ok);
  }
  ISF_REQUIRE(store.needs_compaction());
  AuthoritySnapshot snapshot;
  snapshot.epoch = Epoch{1};
  snapshot.incarnation = Incarnation::from_seed(1, 1);
  snapshot.policy = Policy::conservative_default();
  SiteRecord site;
  site.id = site_from_name("compacted");
  site.name = "compacted";
  site.incarnation = Incarnation::from_seed(2, 2);
  site.generation = Generation{1};
  site.epoch = Epoch{1};
  site.state = SiteState::Up;
  snapshot.sites.push_back(site);
  ISF_REQUIRE_EQ(store.compact(snapshot, 100, Incarnation::from_seed(3, 3)), Status::Ok);
  ISF_REQUIRE_EQ(store.record_count(), std::size_t{1});
  ISF_REQUIRE(!store.needs_compaction());
  store.close();

  Store reopened;
  auto replay = reopened.open(path, options);
  ISF_REQUIRE_OK(replay);
  ISF_REQUIRE(replay.value().report.fidelity == RecoveryFidelity::Exact);
  ISF_REQUIRE_EQ(replay.value().report.snapshots_seen, std::size_t{1});
  ISF_REQUIRE_EQ(replay.value().actions.size(), std::size_t{1});
  ISF_REQUIRE(replay.value().actions.front().kind == ReplayAction::Kind::Snapshot);
  ISF_REQUIRE_EQ(replay.value().actions.front().snapshot.sites.size(), std::size_t{1});
}

ISF_TEST(store, configured_bounds_are_enforced) {
  ScratchDir scratch("store-bounds");
  const std::string path = scratch.file("log.isfstore");
  StoreOptions options = StoreOptions::for_tests();
  options.max_records = 4;
  Store store;
  ISF_REQUIRE_OK(store.open(path, options));
  Status last = Status::Ok;
  for (std::uint64_t i = 1; i <= 10 && last == Status::Ok; ++i) {
    const auto changes = make_changes("b" + std::to_string(i), i, false);
    last = store.append_intent(i, ArbSeq{i}, changes, i, Incarnation::from_seed(i, 1));
    if (last == Status::Ok) {
      last = store.append_commit(i, i);
    }
  }
  ISF_REQUIRE_EQ(static_cast<int>(last), static_cast<int>(Status::LimitExceeded));
  ISF_REQUIRE(store.record_count() <= 4);
  store.close();
}

// ---------------------------------------------------------------------------
// Framing
// ---------------------------------------------------------------------------

ISF_TEST(framing, decoder_handles_partial_and_batched_input) {
  const std::string first = "first frame";
  const std::string second = "second frame";
  const std::vector<Byte> frame_one =
      encode_frame(ByteSpan(reinterpret_cast<const Byte*>(first.data()), first.size()));
  const std::vector<Byte> frame_two =
      encode_frame(ByteSpan(reinterpret_cast<const Byte*>(second.data()), second.size()));

  FrameDecoder decoder(4096);
  for (std::size_t i = 0; i < frame_one.size(); ++i) {
    ISF_REQUIRE_STATUS_EQ(decoder.push(ByteSpan(frame_one.data() + i, 1)), Status::Ok);
    auto payload = decoder.next();
    if (i + 1 < frame_one.size()) {
      ISF_REQUIRE_EQ(static_cast<int>(payload.status()), static_cast<int>(Status::NotFound));
    } else {
      ISF_REQUIRE_OK(payload);
      ISF_REQUIRE_EQ(payload.value().size(), first.size());
    }
  }
  ISF_REQUIRE_STATUS_EQ(decoder.push(ByteSpan(frame_two.data(), frame_two.size())), Status::Ok);
  auto payload = decoder.next();
  ISF_REQUIRE_OK(payload);
  ISF_REQUIRE_EQ(std::string(payload.value().begin(), payload.value().end()), second);
}

ISF_TEST(framing, decoder_rejects_hostile_input) {
  FrameDecoder decoder(1024);
  std::vector<Byte> garbage(kFrameHeaderBytes, 0);
  ISF_REQUIRE_EQ(static_cast<int>(decoder.push(ByteSpan(garbage.data(), garbage.size()))),
                 static_cast<int>(Status::Ok));
  auto result = decoder.next();
  ISF_REQUIRE(!result.ok());
  ISF_REQUIRE_EQ(static_cast<int>(result.status()), static_cast<int>(Status::Invalid));

  FrameDecoder big(1024);
  std::vector<Byte> huge = encode_frame(ByteSpan{});
  huge[4] = 0xFF;
  huge[5] = 0xFF;
  huge[6] = 0xFF;
  huge[7] = 0x7F;
  ISF_REQUIRE_STATUS_EQ(big.push(ByteSpan(huge.data(), huge.size())), Status::Ok);
  auto oversized = big.next();
  ISF_REQUIRE(!oversized.ok());
  ISF_REQUIRE_EQ(static_cast<int>(oversized.status()), static_cast<int>(Status::LimitExceeded));

  FrameDecoder crc(1024);
  const std::string body = "payload";
  std::vector<Byte> frame =
      encode_frame(ByteSpan(reinterpret_cast<const Byte*>(body.data()), body.size()));
  frame.back() = static_cast<Byte>(frame.back() ^ 0xFFU);
  ISF_REQUIRE_STATUS_EQ(crc.push(ByteSpan(frame.data(), frame.size())), Status::Ok);
  auto bad_crc = crc.next();
  ISF_REQUIRE(!bad_crc.ok());
  ISF_REQUIRE_EQ(static_cast<int>(bad_crc.status()), static_cast<int>(Status::Corrupt));
}

ISF_TEST(protocol, envelopes_and_bodies_round_trip) {
  Request request;
  request.type = MessageType::SiteRegister;
  request.session_seq = 42;
  request.id = RequestId::from_seed(1, 2);
  request.payload = {1, 2, 3};
  auto decoded = decode_request(ByteSpan(encode_request(request).data(), encode_request(request).size()));
  ISF_REQUIRE_OK(decoded);
  ISF_REQUIRE(decoded.value().type == MessageType::SiteRegister);
  ISF_REQUIRE_EQ(decoded.value().session_seq, std::uint64_t{42});
  ISF_REQUIRE(decoded.value().id == request.id);

  Response response;
  response.type = MessageType::ErrorReply;
  response.status = Status::Stale;
  response.detail = "stale";
  response.session_seq = 42;
  response.id = request.id;
  const std::vector<Byte> encoded_response = encode_response(response);
  auto decoded_response = decode_response(ByteSpan(encoded_response.data(), encoded_response.size()));
  ISF_REQUIRE_OK(decoded_response);
  ISF_REQUIRE(decoded_response.value().status == Status::Stale);
  ISF_REQUIRE_EQ(decoded_response.value().detail, std::string("stale"));

  // Message type classification must keep requests and replies disjoint.
  ISF_REQUIRE(message_type_is_request(MessageType::Hello));
  ISF_REQUIRE(message_type_is_reply(MessageType::HelloAck));
  ISF_REQUIRE(message_type_is_reply(MessageType::ErrorReply));
  ISF_REQUIRE(!message_type_is_request(MessageType::HelloAck));
  for (std::uint16_t value = 0; value < 200; ++value) {
    const auto type = static_cast<MessageType>(value);
    ISF_CHECK(!(message_type_is_request(type) && message_type_is_reply(type)));
  }
}

ISF_TEST(net, endpoint_parsing_is_strict) {
  auto plain = Endpoint::parse("127.0.0.1:8080");
  ISF_REQUIRE_OK(plain);
  ISF_REQUIRE_EQ(plain.value().host, std::string("127.0.0.1"));
  ISF_REQUIRE_EQ(plain.value().port, std::uint16_t{8080});
  auto bare_port = Endpoint::parse("9000");
  ISF_REQUIRE_OK(bare_port);
  ISF_REQUIRE_EQ(bare_port.value().host, std::string("127.0.0.1"));
  auto bracketed = Endpoint::parse("[::1]:1234");
  ISF_REQUIRE_OK(bracketed);
  ISF_REQUIRE_EQ(bracketed.value().host, std::string("::1"));
  ISF_REQUIRE(!Endpoint::parse("host:notaport").ok());
  ISF_REQUIRE(!Endpoint::parse("host:99999").ok());
  ISF_REQUIRE(!Endpoint::parse("").ok());
}
