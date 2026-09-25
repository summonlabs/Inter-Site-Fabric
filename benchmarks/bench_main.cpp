// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Completed-work benchmarks.
//
// Every reported number is measured on the machine that runs this program, over
// a fixed amount of completed work. Nothing is extrapolated, and no hardware
// behaviour (RDMA, InfiniBand, NVLink, switch ASICs, physical link effects) is
// claimed: the transport measured here is loopback TCP.

#include "isf/client.hpp"
#include "isf/clock.hpp"
#include "isf/daemon.hpp"
#include "isf/digest.hpp"
#include "isf/server.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <optional>
#include <filesystem>
#include <string>
#include <vector>

namespace {

using namespace isf;

struct Fixture {
  SiteId a{};
  SiteId b{};
  Incarnation a_incarnation{};
  PathId path{};
  Generation a_generation{};
};

[[nodiscard]] std::optional<Fixture> test_fixture(Authority& authority, std::uint64_t now,
                                                  Amount usable) {
  Fixture fixture;
  fixture.a = SiteId::from_seed(21, 21);
  fixture.b = SiteId::from_seed(22, 22);
  fixture.a_incarnation = Incarnation::from_seed(23, 23);
  fixture.path = PathId::from_seed(24, 24);
  std::uint64_t arbitration = 0;
  const auto apply = [&](MutationResult result) -> bool {
    if (!result.ok()) {
      return false;
    }
    return authority.apply(result.value().changes, ArbSeq{arbitration}) == Status::Ok;
  };
  SiteRegistration registration;
  registration.descriptor.id = fixture.a;
  registration.descriptor.name = "bench-a";
  registration.incarnation = fixture.a_incarnation;
  registration.epoch = authority.epoch();
  registration.now_ms = now;
  if (!apply(authority.plan_register_site(registration, ArbSeq{++arbitration}))) {
    return std::nullopt;
  }
  registration.descriptor.id = fixture.b;
  registration.descriptor.name = "bench-b";
  registration.incarnation = Incarnation::from_seed(25, 25);
  if (!apply(authority.plan_register_site(registration, ArbSeq{++arbitration}))) {
    return std::nullopt;
  }
  const auto site = authority.find_site(fixture.a);
  if (!site.has_value()) {
    return std::nullopt;
  }
  fixture.a_generation = site->generation;

  PathRegistration path;
  path.descriptor.id = fixture.path;
  path.descriptor.name = "bench-path";
  path.descriptor.endpoint_a = fixture.a;
  path.descriptor.endpoint_b = fixture.b;
  path.path_generation = Generation{1};
  path.state = PathState::Up;
  path.now_ms = now;
  if (!apply(authority.plan_register_path(path, ArbSeq{++arbitration}))) {
    return std::nullopt;
  }
  const auto record = authority.find_path(fixture.path);
  if (!record.has_value()) {
    return std::nullopt;
  }
  CapacityAttestation attestation;
  attestation.id = AttestationId::from_seed(26, 26);
  attestation.path = fixture.path;
  attestation.path_generation = record->generation;
  attestation.capacity_generation = Generation{1};
  attestation.usable = usable;
  attestation.advertised = usable;
  attestation.observed = usable;
  attestation.issuer = authority.incarnation();
  attestation.epoch = authority.epoch();
  attestation.principal = PrincipalId::from_seed(27, 27);
  attestation.observed_at_ms = now;
  attestation.evidence = Digest256::of(ByteSpan{});
  attestation.source = "benchmark";
  if (!apply(authority.plan_attest_capacity(attestation, ArbSeq{++arbitration}))) {
    return std::nullopt;
  }
  return fixture;
}

struct Result {
  std::string name;
  double nanoseconds_per_operation{0};
  double operations_per_second{0};
  std::string notes;
};

std::vector<Result> g_results;

void record(const std::string& name, std::uint64_t operations, std::uint64_t elapsed_ns,
            const std::string& notes) {
  Result result;
  result.name = name;
  result.nanoseconds_per_operation =
      operations == 0 ? 0.0 : static_cast<double>(elapsed_ns) / static_cast<double>(operations);
  result.operations_per_second =
      elapsed_ns == 0 ? 0.0 : static_cast<double>(operations) * 1e9 / static_cast<double>(elapsed_ns);
  result.notes = notes;
  g_results.push_back(result);
  std::printf("%-38s %12.1f ns/op %14.0f op/s  %s\n", name.c_str(),
              result.nanoseconds_per_operation, result.operations_per_second, notes.c_str());
}

[[nodiscard]] std::uint64_t now_ns() {
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(
          std::chrono::steady_clock::now().time_since_epoch())
          .count());
}

void benchmark_authority(std::size_t rounds) {
  AuthorityConfig config;
  config.incarnation = Incarnation::from_seed(1, 1);
  Authority authority(config);
  const std::uint64_t now = 1000;
  auto fixture = test_fixture(authority, now, rounds * 2 + 16);
  if (!fixture.has_value()) {
    return;
  }
  std::uint64_t arbitration = 0;
  std::uint64_t operations = 0;
  const std::uint64_t start = now_ns();
  for (std::size_t round = 0; round < rounds; ++round) {
    GrantProposal proposal;
    proposal.request = RequestId::from_seed(round + 1, 7);
    proposal.holder = fixture->a;
    proposal.holder_incarnation = fixture->a_incarnation;
    proposal.holder_generation = fixture->a_generation;
    proposal.path = fixture->path;
    proposal.amount = 1;
    proposal.duration_ms = 600000;
    proposal.now_ms = now;
    auto proposed = authority.plan_propose_grant(proposal, ArbSeq{++arbitration});
    if (!proposed.ok()) {
      continue;
    }
    const GrantId id = GrantId::from_raw(proposed.value().changes.front().key);
    if (authority.apply(proposed.value().changes, ArbSeq{arbitration}) != Status::Ok) {
      continue;
    }
    GrantOperation op;
    op.grant = id;
    op.actor = fixture->a;
    op.actor_incarnation = fixture->a_incarnation;
    op.epoch = authority.epoch();
    op.now_ms = now;

    auto evaluated = authority.plan_evaluate_grant(op, ArbSeq{++arbitration});
    if (evaluated.ok()) {
      (void)authority.apply(evaluated.value().changes, ArbSeq{arbitration});
    }
    auto reserved = authority.plan_reserve_grant(op, ArbSeq{++arbitration});
    if (reserved.ok()) {
      (void)authority.apply(reserved.value().changes, ArbSeq{arbitration});
    }
    auto activated = authority.plan_activate_grant(op, ArbSeq{++arbitration});
    if (activated.ok()) {
      (void)authority.apply(activated.value().changes, ArbSeq{arbitration});
    }
    auto withdrawn = authority.plan_withdraw_grant(op, ArbSeq{++arbitration});
    if (withdrawn.ok()) {
      (void)authority.apply(withdrawn.value().changes, ArbSeq{arbitration});
    }
    auto retired = authority.plan_retire_grant(op, ArbSeq{++arbitration});
    if (retired.ok()) {
      (void)authority.apply(retired.value().changes, ArbSeq{arbitration});
    }
    operations += 6;
  }
  const std::uint64_t elapsed = now_ns() - start;
  record("authority.lifecycle_steps", operations, elapsed,
         "propose/evaluate/reserve/activate/withdraw/retire");

  // Ledger derivation and invariant verification over the accumulated table.
  const std::uint64_t ledger_start = now_ns();
  std::size_t ledger_queries = 0;
  for (std::size_t i = 0; i < 1000; ++i) {
    auto ledger = authority.ledger(fixture->path);
    if (ledger.ok()) {
      ++ledger_queries;
    }
  }
  record("authority.ledger_query", ledger_queries, now_ns() - ledger_start,
         "derives one path ledger over the full grant table");

  const std::uint64_t digest_start = now_ns();
  std::size_t digest_queries = 0;
  for (std::size_t i = 0; i < 200; ++i) {
    (void)authority.state_digest();
    ++digest_queries;
  }
  record("authority.state_digest", digest_queries, now_ns() - digest_start,
         "canonical SHA-256 over all authoritative records");

  const std::uint64_t invariant_start = now_ns();
  std::size_t invariant_runs = 0;
  for (std::size_t i = 0; i < 50; ++i) {
    std::string why;
    if (authority.verify_invariants(&why) == Status::Ok) {
      ++invariant_runs;
    }
  }
  record("authority.verify_invariants", invariant_runs, now_ns() - invariant_start,
         "linear pass over every record");
}

void benchmark_wire(std::size_t rounds) {
  GrantProposal proposal;
  proposal.request = RequestId::from_seed(3, 3);
  proposal.holder = SiteId::from_seed(4, 4);
  proposal.holder_incarnation = Incarnation::from_seed(5, 5);
  proposal.path = PathId::from_seed(6, 6);
  proposal.amount = 123456789;
  proposal.duration_ms = 600000;
  proposal.now_ms = 1000;
  proposal.reason = "benchmark payload of representative size";

  const std::uint64_t start = now_ns();
  std::size_t encoded = 0;
  std::size_t decoded = 0;
  std::size_t bytes = 0;
  std::vector<Byte> last;
  for (std::size_t i = 0; i < rounds; ++i) {
    last = encode_grant_proposal(proposal);
    bytes += last.size();
    ++encoded;
    auto back = decode_grant_proposal(ByteSpan(last.data(), last.size()));
    if (back.ok()) {
      ++decoded;
    }
  }
  record("wire.encode_decode", encoded + decoded, now_ns() - start,
         std::to_string(bytes / std::max<std::size_t>(rounds, 1)) + " bytes per message");

  std::vector<Byte> body(4096, 0x5A);
  const std::uint64_t frame_start = now_ns();
  std::size_t frames = 0;
  for (std::size_t i = 0; i < rounds; ++i) {
    const std::vector<Byte> frame = encode_frame(ByteSpan(body.data(), body.size()));
    FrameDecoder decoder(frame.size() + 64);
    if (decoder.push(ByteSpan(frame.data(), frame.size())) == Status::Ok) {
      auto payload = decoder.next();
      if (payload.ok()) {
        ++frames;
      }
    }
  }
  record("framing.encode_checksum_decode", frames, now_ns() - frame_start,
         "4096 byte payload with CRC-32C");

  const std::uint64_t digest_start = now_ns();
  std::size_t digests = 0;
  for (std::size_t i = 0; i < rounds; ++i) {
    (void)Digest256::of(ByteSpan(body.data(), body.size()));
    ++digests;
  }
  record("digest.sha256_4096", digests, now_ns() - digest_start, "SHA-256 of 4096 bytes");
}

void benchmark_store(std::size_t rounds, const std::string& directory) {
  const std::string path = directory + "/bench.isfstore";
  StoreOptions options;
  options.max_log_bytes = 512U << 20;
  options.max_records = 4U << 20;
  options.compact_threshold_bytes = 256U << 20;
  options.compact_threshold_records = 2U << 20;

  Store store;
  auto opened = store.open(path, options);
  if (!opened.ok()) {
    std::printf("store benchmark skipped: %s\n", opened.detail().c_str());
    return;
  }
  SiteRecord site;
  site.id = SiteId::from_seed(7, 7);
  site.name = "bench-site";
  site.incarnation = Incarnation::from_seed(8, 8);
  site.generation = Generation{1};
  site.epoch = Epoch{1};
  site.state = SiteState::Up;
  Writer writer;
  encode(writer, site);
  StateChange change;
  change.kind = ObjectKind::Site;
  change.key = site.id.raw();
  change.image.assign(writer.buffer().begin(), writer.buffer().end());

  const std::uint64_t start = now_ns();
  std::size_t committed = 0;
  for (std::size_t i = 0; i < rounds; ++i) {
    site.name = "bench-site-" + std::to_string(i);
    Writer local;
    encode(local, site);
    change.image.assign(local.buffer().begin(), local.buffer().end());
    if (store.append_intent(i + 1, ArbSeq{i + 1}, {change}, 1000, site.incarnation) != Status::Ok) {
      break;
    }
    if (store.append_commit(i + 1, 1000) != Status::Ok) {
      break;
    }
    ++committed;
  }
  const std::uint64_t durable_elapsed = now_ns() - start;
  record("store.append_intent_and_commit", committed, durable_elapsed,
         "two records per transaction with an fsync at close");
  if (store.flush() != Status::Ok) {
    std::printf("store flush failed\n");
  }
  store.close();

  const std::uint64_t replay_start = now_ns();
  Store reopened;
  auto replay = reopened.open(path, options);
  if (!replay.ok()) {
    std::printf("store replay failed: %s\n", replay.detail().c_str());
    return;
  }
  const std::size_t records = replay.value().report.records_read;
  record("store.replay", records, now_ns() - replay_start,
         "records validated against CRC-32C and the SHA-256 chain");
  reopened.close();

  const std::uint64_t compact_start = now_ns();
  Store compacted;
  if (compacted.open(path, options).ok()) {
    Authority or_empty(AuthorityConfig{});
    if (compacted.compact(or_empty.snapshot(), 1000, Incarnation::from_seed(1, 1)) == Status::Ok) {
      record("store.compact", 1, now_ns() - compact_start, "full snapshot write and atomic swap");
    }
    compacted.close();
  }
}

void benchmark_transport(std::size_t rounds, const std::string& directory) {
  DaemonOptions daemon_options;
  daemon_options.state_path = directory + "/transport.isfstore";
  daemon_options.enable_ticker = false;
  daemon_options.verify_after_mutation = false;
  daemon_options.store.durable_writes = true;
  auto daemon = Daemon::start(daemon_options);
  if (!daemon.ok()) {
    std::printf("transport benchmark skipped: %s\n", daemon.outcome().to_string().c_str());
    return;
  }
  ServerOptions server_options;
  server_options.bind_endpoint = Endpoint{"127.0.0.1", 0};
  FabricServer server(**daemon, server_options);
  if (server.start() != Status::Ok) {
    std::printf("transport benchmark skipped: server did not start\n");
    return;
  }

  ClientOptions client_options;
  client_options.endpoint = server.local_endpoint();
  client_options.client_kind = "benchmark";
  client_options.io_timeout_ms = 60000;
  auto client = FabricClient::connect(client_options);
  if (client.ok()) {
    const std::uint64_t start = now_ns();
    std::size_t calls = 0;
    for (std::size_t i = 0; i < rounds; ++i) {
      auto status = client.value().status();
      if (status.ok()) {
        ++calls;
      }
    }
    const std::uint64_t elapsed = now_ns() - start;
    record("transport.status_round_trip", calls, elapsed,
           "request and reply over loopback TCP, each durably recorded");

    SiteDescriptor descriptor;
    descriptor.id = SiteId::from_seed(9, 9);
    descriptor.name = "bench-site";
    const std::uint64_t mutation_start = now_ns();
    std::size_t mutations = 0;
    for (std::size_t i = 0; i < rounds; ++i) {
      auto registered = client.value().register_site(
          descriptor, Incarnation::from_seed(10 + i, 10), client.value().hello().epoch, now_ms());
      if (registered.ok()) {
        ++mutations;
      }
    }
    record("transport.durable_mutation", mutations, now_ns() - mutation_start,
           "write-ahead intent, apply, completion record, fsync, reply");
    (void)client.value().request_shutdown();
    client.value().close();
  }
  server.stop();
  (**daemon).stop();
}

}  // namespace

int main(int argc, char** argv) {
  std::size_t scale = 1;
  for (int i = 1; i < argc; ++i) {
    const std::string token = argv[i];
    if (token == "--scale" && i + 1 < argc) {
      scale = static_cast<std::size_t>(std::strtoul(argv[++i], nullptr, 10));
      if (scale == 0) {
        scale = 1;
      }
    }
  }
  namespace fs = std::filesystem;
  const fs::path directory = fs::temp_directory_path() / "isf-benchmarks";
  std::error_code ec;
  fs::remove_all(directory, ec);
  fs::create_directories(directory, ec);

  std::printf("inter-site-fabric benchmarks, %s\n", build_description().c_str());
  std::printf("scale=%zu  transport=loopback TCP only (no RDMA, InfiniBand, NVLink, or ASIC)\n\n",
              scale);

  benchmark_authority(2000 * scale);
  benchmark_wire(20000 * scale);
  benchmark_store(200 * scale, directory.string());
  benchmark_transport(200 * scale, directory.string());

  fs::remove_all(directory, ec);
  std::printf("\ncompleted %zu benchmark(s)\n", g_results.size());
  return 0;
}