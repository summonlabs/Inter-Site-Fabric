// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "testkit.hpp"

#include "isf/clock.hpp"
#include "isf/digest.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

namespace isf::test {
namespace {

struct TestCase {
  std::string suite;
  std::string name;
  TestFunction function;
};

std::vector<TestCase>& registry() {
  static std::vector<TestCase> instance;
  return instance;
}

std::uint64_t g_seed = 1;
std::uint64_t g_iterations = 200;
bool g_verbose = false;
std::string g_filter;
std::string g_current;
std::vector<std::string> g_check_failures;

[[nodiscard]] bool env_truthy(const char* name) {
  const char* value = std::getenv(name);
  if (value == nullptr || value[0] == '\0') {
    return false;
  }
  return std::strcmp(value, "0") != 0 && std::strcmp(value, "false") != 0;
}

void print_usage(const char* program) {
  std::printf(
      "usage: %s [--seed N] [--iterations N] [--filter SUBSTR] [--list] [--verbose]\n",
      program);
}

}  // namespace

void register_test(const char* suite, const char* name, TestFunction fn) {
  registry().push_back(TestCase{suite, name, fn});
}

std::uint64_t run_seed() noexcept { return g_seed; }
std::uint64_t run_iterations() noexcept { return g_iterations; }

void record_check_failure(const std::string& message) { g_check_failures.push_back(message); }

std::uint64_t Rng::next() noexcept {
  if (seed_ == 0) {
    seed_ = state_;
  }
  state_ += 0x9E3779B97F4A7C15ULL;
  std::uint64_t z = state_;
  z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
  z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
  return z ^ (z >> 31);
}

std::uint64_t Rng::below(std::uint64_t bound) noexcept {
  if (bound == 0) {
    return 0;
  }
  return next() % bound;
}

std::uint64_t Rng::in_range(std::uint64_t low, std::uint64_t high) noexcept {
  if (high <= low) {
    return low;
  }
  return low + below(high - low + 1);
}

bool Rng::chance(std::uint32_t percent) noexcept {
  return below(100) < static_cast<std::uint64_t>(percent);
}

std::string describe(bool value) { return value ? "true" : "false"; }
std::string describe(const std::string& value) { return value; }
std::string describe(const char* value) { return value == nullptr ? "<null>" : value; }
std::string describe(std::uint64_t value) { return std::to_string(value); }
std::string describe(std::int64_t value) { return std::to_string(value); }


std::string scratch_root() {
  const char* base = std::getenv("ISF_TEST_BINARY_DIR");
  std::filesystem::path root = base != nullptr && base[0] != '\0' ? std::filesystem::path(base)
                                                                  : std::filesystem::current_path();
  root /= "scratch";
  std::error_code ec;
  std::filesystem::create_directories(root, ec);
  return root.string();
}

ScratchDir::ScratchDir(const std::string& tag) {
  static std::atomic<std::uint64_t> counter{0};
  keep_ = env_truthy("ISF_KEEP_SCRATCH");
  const std::uint64_t index = counter.fetch_add(1, std::memory_order_relaxed);
  std::filesystem::path path = std::filesystem::path(scratch_root()) /
                               (tag + "-" + std::to_string(isf::now_ms()) + "-" +
                                std::to_string(index));
  std::error_code ec;
  std::filesystem::create_directories(path, ec);
  path_ = path.string();
  if (g_verbose) {
    std::printf("        scratch: %s\n", path_.c_str());
  }
}

ScratchDir::~ScratchDir() {
  if (keep_) {
    std::printf("        kept scratch: %s\n", path_.c_str());
    return;
  }
  std::error_code ec;
  std::filesystem::remove_all(path_, ec);
}

std::string ScratchDir::file(const std::string& name) const {
  return (std::filesystem::path(path_) / name).string();
}

std::vector<std::pair<std::string, std::string>> read_report(const std::string& path) {
  std::vector<std::pair<std::string, std::string>> out;
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    return out;
  }
  std::string line;
  while (std::getline(in, line)) {
    if (!line.empty() && line.back() == '\r') {
      line.pop_back();
    }
    const std::size_t equals = line.find('=');
    if (equals == std::string::npos) {
      continue;
    }
    out.emplace_back(line.substr(0, equals), line.substr(equals + 1));
  }
  return out;
}

std::string report_value(const std::vector<std::pair<std::string, std::string>>& report,
                         const std::string& key, const std::string& fallback) {
  for (const auto& entry : report) {
    if (entry.first == key) {
      return entry.second;
    }
  }
  return fallback;
}

SiteId site_from_name(const std::string& name) {
  return SiteId::from_seed(fnv1a64(name), 0x15F0517EULL);
}

PathId path_from_name(const std::string& name) {
  return PathId::from_seed(fnv1a64(name), 0x15F0A7E5ULL);
}

DomainId domain_from_name(const std::string& name) {
  return DomainId::from_seed(fnv1a64(name), 0x15F0D0A1ULL);
}

PrincipalId principal_from_name(const std::string& name) {
  return PrincipalId::from_seed(fnv1a64(name), 0x15F0A11CULL);
}

// ---------------------------------------------------------------------------
// LocalFabric
// ---------------------------------------------------------------------------

Expected<std::unique_ptr<LocalFabric>> LocalFabric::start(const std::string& state_path,
                                                          const Options& options) {
  DaemonOptions daemon_options;
  daemon_options.state_path = state_path;
  daemon_options.policy = options.policy;
  daemon_options.store = options.store;
  daemon_options.enable_ticker = options.enable_ticker;
  daemon_options.auto_compact = options.auto_compact;
  daemon_options.verify_after_mutation = options.verify_after_mutation;
  daemon_options.commit_stage_hook = options.commit_stage_hook;

  auto daemon = Daemon::start(daemon_options);
  if (!daemon.ok()) {
    return daemon.outcome();
  }
  auto fabric = std::unique_ptr<LocalFabric>(new LocalFabric());
  fabric->daemon_ = std::move(daemon.value());

  ServerOptions server_options;
  server_options.bind_endpoint = Endpoint{"127.0.0.1", 0};
  server_options.max_connections = options.max_connections;
  server_options.max_frame_bytes = options.max_frame_bytes;
  server_options.io_timeout_ms = options.io_timeout_ms;
  fabric->server_ = std::make_unique<FabricServer>(*fabric->daemon_, server_options);
  const Status started = fabric->server_->start();
  if (started != Status::Ok) {
    return Outcome(started, "test server could not start");
  }
  return fabric;
}

LocalFabric::~LocalFabric() { stop(); }

void LocalFabric::stop() {
  if (server_) {
    server_->stop();
  }
  if (daemon_) {
    daemon_->stop();
  }
}

Expected<FabricClient> LocalFabric::client(const std::string& kind) {
  ClientOptions options;
  options.endpoint = endpoint();
  options.client_kind = kind;
  options.io_timeout_ms = 60000;
  return FabricClient::connect(options);
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

int run_all(int argc, char** argv, const char* program) {
  bool seed_explicit = false;
  for (int i = 1; i < argc; ++i) {
    const std::string token = argv[i];
    const auto next = [&](std::string& target) {
      if (i + 1 < argc) {
        target = argv[++i];
      }
    };
    if (token == "--seed") {
      std::string value;
      next(value);
      g_seed = std::strtoull(value.c_str(), nullptr, 10);
      seed_explicit = true;
    } else if (token == "--iterations") {
      std::string value;
      next(value);
      g_iterations = std::strtoull(value.c_str(), nullptr, 10);
    } else if (token == "--filter") {
      next(g_filter);
    } else if (token == "--list") {
      for (const auto& test : registry()) {
        std::printf("%s.%s\n", test.suite.c_str(), test.name.c_str());
      }
      return 0;
    } else if (token == "--verbose" || token == "-v") {
      g_verbose = true;
    } else if (token == "--help" || token == "-h") {
      print_usage(program);
      return 0;
    } else {
      std::fprintf(stderr, "%s: unknown option '%s'\n", program, token.c_str());
      print_usage(program);
      return 2;
    }
  }
  if (!seed_explicit) {
    const char* env_seed = std::getenv("ISF_TEST_SEED");
    if (env_seed != nullptr && env_seed[0] != '\0') {
      g_seed = std::strtoull(env_seed, nullptr, 10);
    }
  }

  std::size_t passed = 0;
  std::size_t failed = 0;
  std::vector<std::string> failures;
  const std::uint64_t start_ms = isf::monotonic_ms();

  for (const auto& test : registry()) {
    const std::string full = test.suite + "." + test.name;
    if (!g_filter.empty() && full.find(g_filter) == std::string::npos) {
      continue;
    }
    g_current = full;
    g_check_failures.clear();
    if (g_verbose) {
      std::printf("[ RUN  ] %s\n", full.c_str());
      std::fflush(stdout);
    }
    bool threw = false;
    std::string message;
    try {
      test.function();
    } catch (const TestFailure& failure) {
      threw = true;
      message = failure.what();
    } catch (const std::exception& error) {
      threw = true;
      message = std::string("unexpected exception: ") + error.what();
    } catch (...) {
      threw = true;
      message = "unexpected non-standard exception";
    }
    if (!g_check_failures.empty()) {
      threw = true;
      message = g_check_failures.front();
      if (g_check_failures.size() > 1) {
        message += " (and " + std::to_string(g_check_failures.size() - 1) + " more)";
      }
    }
    if (threw) {
      ++failed;
      failures.push_back(full + ": " + message);
      std::printf("[ FAIL ] %s\n         %s\n", full.c_str(), message.c_str());
    } else {
      ++passed;
      if (g_verbose) {
        std::printf("[  OK  ] %s\n", full.c_str());
      }
    }
    std::fflush(stdout);
  }

  const std::uint64_t elapsed = isf::monotonic_ms() - start_ms;
  std::printf("\n%s: %zu passed, %zu failed in %llu ms (seed=%llu iterations=%llu)\n",
              program, passed, failed, static_cast<unsigned long long>(elapsed),
              static_cast<unsigned long long>(g_seed),
              static_cast<unsigned long long>(g_iterations));
  if (!failures.empty()) {
    std::printf("failures:\n");
    for (const auto& failure : failures) {
      std::printf("  - %s\n", failure.c_str());
    }
    std::printf("reproduce with: %s --seed %llu\n", program,
                static_cast<unsigned long long>(g_seed));
  }
  return failed == 0 ? 0 : 1;
}

// ---------------------------------------------------------------------------
// Fixture builders
// ---------------------------------------------------------------------------

Expected<FabricFixture> setup_fabric(Authority& authority, const std::string& tag, Amount usable,
                                     std::uint64_t now) {
  FabricFixture fixture;
  fixture.a = site_from_name(tag + "-a");
  fixture.b = site_from_name(tag + "-b");
  fixture.a_incarnation = Incarnation::from_seed(fnv1a64(tag + "-a-inc"), 1);
  fixture.b_incarnation = Incarnation::from_seed(fnv1a64(tag + "-b-inc"), 2);
  fixture.path = path_from_name(tag + "-path");
  fixture.usable = usable;

  const auto apply_or_fail = [&authority](MutationResult result) -> Status {
    if (!result.ok()) {
      return result.status();
    }
    return authority.apply(result.value().changes, result.value().arbitration);
  };

  SiteRegistration registration_a;
  registration_a.descriptor.id = fixture.a;
  registration_a.descriptor.name = tag + "-a";
  registration_a.incarnation = fixture.a_incarnation;
  registration_a.epoch = authority.epoch();
  registration_a.now_ms = now;
  if (apply_or_fail(authority.plan_register_site(registration_a, ArbSeq{1})) != Status::Ok) {
    return Outcome(Status::Corrupt, "authority rejected the fixture site A registration");
  }
  SiteRegistration registration_b = registration_a;
  registration_b.descriptor.id = fixture.b;
  registration_b.descriptor.name = tag + "-b";
  registration_b.incarnation = fixture.b_incarnation;
  if (apply_or_fail(authority.plan_register_site(registration_b, ArbSeq{2})) != Status::Ok) {
    return Outcome(Status::Corrupt, "site B registration failed");
  }
  auto site_a = authority.find_site(fixture.a);
  auto site_b = authority.find_site(fixture.b);
  if (!site_a.has_value() || !site_b.has_value()) {
    return Outcome(Status::Corrupt, "registered sites are missing");
  }
  fixture.a_generation = site_a->generation;
  fixture.b_generation = site_b->generation;

  PathRegistration path;
  path.descriptor.id = fixture.path;
  path.descriptor.name = tag + "-path";
  path.descriptor.endpoint_a = fixture.a;
  path.descriptor.endpoint_b = fixture.b;
  path.path_generation = Generation{1};
  path.state = PathState::Up;
  path.advertised = usable;
  path.now_ms = now;
  if (apply_or_fail(authority.plan_register_path(path, ArbSeq{3})) != Status::Ok) {
    return Outcome(Status::Corrupt, "path registration failed");
  }
  auto path_record = authority.find_path(fixture.path);
  if (!path_record.has_value()) {
    return Outcome(Status::Corrupt, "registered path is missing");
  }
  fixture.path_generation = path_record->generation;

  CapacityAttestation attestation;
  attestation.id = AttestationId::from_seed(fnv1a64(tag + "-attest"), 4);
  attestation.path = fixture.path;
  attestation.path_generation = fixture.path_generation;
  attestation.capacity_generation = Generation{1};
  attestation.usable = usable;
  attestation.advertised = usable;
  attestation.observed = usable;
  attestation.issuer = authority.incarnation();
  attestation.epoch = authority.epoch();
  attestation.principal = principal_from_name(tag);
  attestation.observed_at_ms = now;
  attestation.evidence = Digest256::of(ByteSpan(reinterpret_cast<const Byte*>(tag.data()), tag.size()));
  attestation.source = "test-fixture";
  if (apply_or_fail(authority.plan_attest_capacity(attestation, ArbSeq{4})) != Status::Ok) {
    return Outcome(Status::Corrupt, "capacity attestation failed");
  }
  fixture.capacity_generation = Generation{1};
  return fixture;
}

Expected<FabricFixture> setup_fabric(FabricClient& client, const std::string& tag, Amount usable) {
  FabricFixture fixture;
  fixture.a = site_from_name(tag + "-a");
  fixture.b = site_from_name(tag + "-b");
  fixture.a_incarnation = Incarnation::from_seed(fnv1a64(tag + "-a-inc"), 1);
  fixture.b_incarnation = Incarnation::from_seed(fnv1a64(tag + "-b-inc"), 2);
  fixture.path = path_from_name(tag + "-path");
  fixture.usable = usable;
  const std::uint64_t now = isf::now_ms();
  const Epoch epoch = client.hello().epoch;

  SiteDescriptor descriptor_a;
  descriptor_a.id = fixture.a;
  descriptor_a.name = tag + "-a";
  auto registered_a = client.register_site(descriptor_a, fixture.a_incarnation, epoch, now);
  if (!registered_a.ok()) {
    return registered_a.outcome();
  }
  auto site_a = extract_site(registered_a.value());
  if (!site_a.ok()) {
    return site_a.status();
  }
  fixture.a_generation = site_a.value().generation;

  SiteDescriptor descriptor_b;
  descriptor_b.id = fixture.b;
  descriptor_b.name = tag + "-b";
  auto registered_b = client.register_site(descriptor_b, fixture.b_incarnation, epoch, now);
  if (!registered_b.ok()) {
    return registered_b.outcome();
  }
  auto site_b = extract_site(registered_b.value());
  if (!site_b.ok()) {
    return site_b.status();
  }
  fixture.b_generation = site_b.value().generation;

  PathRegistration path;
  path.descriptor.id = fixture.path;
  path.descriptor.name = tag + "-path";
  path.descriptor.endpoint_a = fixture.a;
  path.descriptor.endpoint_b = fixture.b;
  path.path_generation = Generation{1};
  path.state = PathState::Up;
  path.advertised = usable;
  path.now_ms = now;
  auto registered_path = client.register_path(path);
  if (!registered_path.ok()) {
    return registered_path.outcome();
  }
  auto path_record = extract_path(registered_path.value());
  if (!path_record.ok()) {
    return path_record.status();
  }
  fixture.path_generation = path_record.value().generation;

  CapacityAttestation attestation;
  attestation.id = AttestationId::random();
  attestation.path = fixture.path;
  attestation.path_generation = fixture.path_generation;
  attestation.capacity_generation = Generation{1};
  attestation.usable = usable;
  attestation.advertised = usable;
  attestation.observed = usable;
  attestation.issuer = client.hello().server_incarnation;
  attestation.epoch = epoch;
  attestation.principal = principal_from_name(tag);
  attestation.observed_at_ms = isf::now_ms();
  attestation.evidence = Digest256::of(ByteSpan(reinterpret_cast<const Byte*>(tag.data()), tag.size()));
  attestation.source = "test-fixture";
  auto attested = client.attest_capacity(attestation);
  if (!attested.ok()) {
    return attested.outcome();
  }
  auto attested_path = extract_path(attested.value());
  if (!attested_path.ok()) {
    return attested_path.status();
  }
  fixture.capacity_generation = attested_path.value().capacity_generation;
  return fixture;
}

Expected<GrantRecord> request_grant(FabricClient& client, const FabricFixture& fixture, bool site_a,
                                    Amount amount, GrantClass klass, std::uint64_t duration_ms) {
  const SiteId holder = site_a ? fixture.a : fixture.b;
  const Incarnation incarnation = site_a ? fixture.a_incarnation : fixture.b_incarnation;
  const Generation generation = site_a ? fixture.a_generation : fixture.b_generation;

  GrantProposal proposal;
  proposal.request = RequestId::random();
  proposal.holder = holder;
  proposal.holder_incarnation = incarnation;
  proposal.holder_generation = generation;
  proposal.path = fixture.path;
  proposal.amount = amount;
  proposal.grant_class = klass;
  proposal.duration_ms = duration_ms;
  proposal.now_ms = isf::now_ms();
  proposal.reason = "test request";
  auto proposed = client.propose_grant(proposal);
  if (!proposed.ok()) {
    return proposed.outcome();
  }
  auto grant = extract_grant(proposed.value());
  if (!grant.ok()) {
    return grant.status();
  }

  GrantOperation op;
  op.grant = grant.value().id;
  op.actor = holder;
  op.actor_incarnation = incarnation;
  op.actor_generation = generation;
  op.epoch = client.hello().epoch;
  op.lease = grant.value().binding.lease;
  op.now_ms = isf::now_ms();

  auto evaluated = client.evaluate_grant(op);
  if (!evaluated.ok()) {
    return evaluated.outcome();
  }
  auto eligible = extract_grant(evaluated.value());
  if (!eligible.ok()) {
    return eligible.status();
  }
  if (eligible.value().state != GrantState::Eligible) {
    return eligible.value();
  }
  auto reserved = client.reserve_grant(op);
  if (!reserved.ok()) {
    return reserved.outcome();
  }
  auto activated = client.activate_grant(op);
  if (!activated.ok()) {
    return activated.outcome();
  }
  auto active = extract_grant(activated.value());
  if (!active.ok()) {
    return active.status();
  }
  GrantAcknowledgement ack;
  ack.grant = active.value().id;
  ack.actor = holder;
  ack.actor_incarnation = incarnation;
  ack.epoch = client.hello().epoch;
  ack.now_ms = isf::now_ms();
  (void)client.acknowledge_grant(ack);
  return active.value();
}

bool ReferenceLedger::allocate(Amount amount) {
  if (amount > free()) {
    return false;
  }
  held_ += amount;
  return true;
}

}  // namespace isf::test

