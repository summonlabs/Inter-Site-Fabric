// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Multiprocess integration tests. Every test here starts real operating system
// processes that talk over real loopback TCP. Threads are never used as a
// substitute for a second process, and no test claims distributed behaviour
// that it does not exhibit.

#include "process.hpp"
#include "testkit.hpp"

#include "isf/clock.hpp"

#include <cstdio>
#include <string>
#include <vector>

using namespace isf;
using namespace isf::test;

int main(int argc, char** argv) { return run_all(argc, argv, "isf_multiprocess_tests"); }

namespace {

/// Observation bound for a child that is expected to exit. Exceeding it is a
/// test FAILURE, never a silent pass.
constexpr std::uint64_t kExitBoundMs = 30000;
/// Observation bound for a child that is expected to publish a report file.
constexpr std::uint64_t kReadyBoundMs = 30000;

struct DaemonHandle {
  ChildProcess process{};
  std::string endpoint_text{};
  Endpoint endpoint{};
  std::string state_path{};
  std::string ready_path{};
  std::string stdout_path{};
  std::string stderr_path{};
  std::vector<std::pair<std::string, std::string>> ready{};
};

/// Start isfd as a real child process and wait for it to report readiness.
Expected<DaemonHandle> start_daemon(ScratchDir& scratch, const std::string& tag,
                                    const std::string& state_path,
                                    const std::vector<std::string>& extra = {}) {
  auto isfd = find_program("isfd");
  if (!isfd.ok()) {
    return isfd.status();
  }
  DaemonHandle handle;
  handle.state_path = state_path;
  handle.ready_path = scratch.file(tag + "-ready.txt");
  handle.stdout_path = scratch.file(tag + "-stdout.txt");
  handle.stderr_path = scratch.file(tag + "-stderr.txt");

  std::vector<std::string> argv{isfd.value(), "--state", state_path, "--listen", "127.0.0.1:0",
                                "--ready-file", handle.ready_path, "--log-level", "warn"};
  argv.insert(argv.end(), extra.begin(), extra.end());

  auto spawned = ChildProcess::spawn(argv, scratch.path(), handle.stdout_path, handle.stderr_path);
  if (!spawned.ok()) {
    return spawned.status();
  }
  handle.process = std::move(spawned.value());

  auto ready = wait_for_report(handle.ready_path, kReadyBoundMs);
  if (!ready.ok()) {
    (void)handle.process.terminate();
    return Outcome(Status::Unavailable, "daemon did not report readiness within the bound");
  }
  handle.ready = ready.value();
  for (const auto& entry : handle.ready) {
    if (entry.first == "endpoint") {
      handle.endpoint_text = entry.second;
    }
  }
  if (handle.endpoint_text.empty()) {
    (void)handle.process.terminate();
    return Outcome(Status::Incomplete, "daemon readiness report carried no endpoint");
  }
  auto parsed = Endpoint::parse(handle.endpoint_text);
  if (!parsed.ok()) {
    (void)handle.process.terminate();
    return Outcome(Status::Invalid, "daemon reported an unparseable endpoint");
  }
  handle.endpoint = parsed.value();
  return handle;
}

/// Wait for a child to exit and require the expected exit code.
void require_exit(ChildProcess& process, std::uint32_t expected, const std::string& what) {
  std::uint32_t code = 0;
  const ProcessState state = process.wait_for_exit(kExitBoundMs, code);
  if (state == ProcessState::Running) {
    (void)process.terminate();
    ISF_FAIL(what + " did not exit within the observation bound (a hang is a defect, not a pass)");
  }
  if (state == ProcessState::SpawnFailed) {
    ISF_FAIL(what + " could not be observed");
  }
  if (state == ProcessState::Killed) {
    ISF_FAIL(what + " was killed unexpectedly");
  }
  if (code != expected) {
    ISF_FAIL(what + " exited with code " + std::to_string(code) + ", expected " +
                 std::to_string(expected));
  }
}

/// Require that a child process died without running its shutdown path.
void require_abnormal_exit(ChildProcess& process, const std::string& what) {
  std::uint32_t code = 0;
  const ProcessState state = process.wait_for_exit(kExitBoundMs, code);
  if (state == ProcessState::Running) {
    (void)process.terminate();
    ISF_FAIL(what + " did not die within the observation bound");
  }
  ISF_REQUIRE(state == ProcessState::Killed || state == ProcessState::Exited);
  ISF_CHECK(code != 0);
}

Expected<FabricClient> connect_to(const DaemonHandle& handle, const std::string& kind) {
  ClientOptions options;
  options.endpoint = handle.endpoint;
  options.client_kind = kind;
  options.io_timeout_ms = 30000;
  return FabricClient::connect(options);
}

/// Stop a daemon through the isfctl program and require both to exit cleanly.
void shutdown_daemon(ScratchDir& scratch, DaemonHandle& handle) {
  auto ctl = find_program("isfctl");
  ISF_REQUIRE_OK(ctl);
  auto spawned = ChildProcess::spawn({ctl.value(), "--daemon", handle.endpoint_text, "shutdown"},
                                     scratch.path(), scratch.file("shutdown-out.txt"),
                                     scratch.file("shutdown-err.txt"));
  ISF_REQUIRE_OK(spawned);
  require_exit(spawned.value(), 0, "isfctl shutdown");
  require_exit(handle.process, 0, "isfd graceful shutdown");
}

/// Run isfctl as a real process and return its exit code.
std::uint32_t run_ctl(ScratchDir& scratch, const std::vector<std::string>& arguments,
                      const std::string& tag) {
  auto ctl = find_program("isfctl");
  if (!ctl.ok()) {
    ISF_FAIL("isfctl could not be located: " + ctl.detail());
  }
  std::vector<std::string> argv{ctl.value()};
  argv.insert(argv.end(), arguments.begin(), arguments.end());
  auto spawned = ChildProcess::spawn(argv, scratch.path(), scratch.file(tag + "-out.txt"),
                                     scratch.file(tag + "-err.txt"));
  if (!spawned.ok()) {
    ISF_FAIL("isfctl could not be started: " + spawned.detail());
  }
  std::uint32_t code = 0;
  const ProcessState state = spawned.value().wait_for_exit(kExitBoundMs, code);
  if (state == ProcessState::Running) {
    (void)spawned.value().terminate();
    ISF_FAIL("isfctl " + tag + " did not exit within the observation bound");
  }
  return code;
}

Expected<ChildProcess> start_agent(ScratchDir& scratch, const std::string& tag,
                                   const std::vector<std::string>& arguments) {
  auto agent = find_program("isfsited");
  if (!agent.ok()) {
    return agent.status();
  }
  std::vector<std::string> argv{agent.value()};
  argv.insert(argv.end(), arguments.begin(), arguments.end());
  return ChildProcess::spawn(argv, scratch.path(), scratch.file(tag + "-out.txt"),
                             scratch.file(tag + "-err.txt"));
}

struct World {
  std::string a{};
  std::string b{};
  PathId path{};
  SiteId site_a{};
  SiteId site_b{};
  Incarnation a_incarnation{};
  Incarnation b_incarnation{};
};

/// Register two sites, one path, and an attested authoritative capacity.
Expected<World> build_world(FabricClient& client, const std::string& tag, Amount usable) {
  World world;
  world.a = tag + "-a";
  world.b = tag + "-b";
  world.site_a = site_from_name(world.a);
  world.site_b = site_from_name(world.b);
  world.a_incarnation = Incarnation::from_seed(fnv1a64(world.a), 1);
  world.b_incarnation = Incarnation::from_seed(fnv1a64(world.b), 2);
  world.path = path_from_name(tag);
  const std::uint64_t now = now_ms();
  const Epoch epoch = client.hello().epoch;

  SiteDescriptor descriptor_a;
  descriptor_a.id = world.site_a;
  descriptor_a.name = world.a;
  auto registered_a = client.register_site(descriptor_a, world.a_incarnation, epoch, now);
  if (!registered_a.ok()) {
    return registered_a.outcome();
  }
  SiteDescriptor descriptor_b;
  descriptor_b.id = world.site_b;
  descriptor_b.name = world.b;
  auto registered_b = client.register_site(descriptor_b, world.b_incarnation, epoch, now);
  if (!registered_b.ok()) {
    return registered_b.outcome();
  }
  PathRegistration path;
  path.descriptor.id = world.path;
  path.descriptor.name = tag;
  path.descriptor.endpoint_a = world.site_a;
  path.descriptor.endpoint_b = world.site_b;
  path.path_generation = Generation{1};
  path.state = PathState::Up;
  path.now_ms = now;
  auto registered_path = client.register_path(path);
  if (!registered_path.ok()) {
    return registered_path.outcome();
  }
  auto record = extract_path(registered_path.value());
  if (!record.ok()) {
    return record.status();
  }
  CapacityAttestation attestation;
  attestation.id = AttestationId::random();
  attestation.path = world.path;
  attestation.path_generation = record.value().generation;
  attestation.capacity_generation = Generation{1};
  attestation.usable = usable;
  attestation.advertised = usable;
  attestation.observed = usable;
  attestation.issuer = client.hello().server_incarnation;
  attestation.epoch = epoch;
  attestation.principal = principal_from_name(tag);
  attestation.observed_at_ms = now_ms();
  attestation.evidence = Digest256::of(ByteSpan{});
  attestation.source = "multiprocess-fixture";
  auto attested = client.attest_capacity(attestation);
  if (!attested.ok()) {
    return attested.outcome();
  }
  return world;
}

/// Build a fixture describing the live records for use with request_grant.
Expected<FabricFixture> load_fixture(FabricClient& client, const World& world) {
  FabricFixture fixture;
  fixture.a = world.site_a;
  fixture.b = world.site_b;
  fixture.a_incarnation = world.a_incarnation;
  fixture.b_incarnation = world.b_incarnation;
  fixture.path = world.path;
  auto sites = client.list_sites();
  if (!sites.ok()) {
    return sites.status();
  }
  for (const auto& site : sites.value()) {
    if (site.id == world.site_a) {
      fixture.a_generation = site.generation;
      fixture.a_incarnation = site.incarnation;
    }
    if (site.id == world.site_b) {
      fixture.b_generation = site.generation;
      fixture.b_incarnation = site.incarnation;
    }
  }
  auto paths = client.list_paths();
  if (!paths.ok()) {
    return paths.status();
  }
  for (const auto& path : paths.value()) {
    if (path.id == world.path) {
      fixture.path_generation = path.generation;
      fixture.capacity_generation = path.capacity_generation;
      fixture.usable = path.authoritative_usable;
    }
  }
  return fixture;
}

[[nodiscard]] std::vector<GrantRecord> find_grants(FabricClient& client, PathId path) {
  ListFilter filter;
  filter.path = path;
  auto grants = client.list_grants(filter);
  if (!grants.ok()) {
    return {};
  }
  return grants.value();
}

}  // namespace

// ---------------------------------------------------------------------------
// Independent site processes
// ---------------------------------------------------------------------------

ISF_TEST(multiprocess, independent_site_agents_never_overcommit_capacity) {
  ScratchDir scratch("mp-overcommit");
  auto daemon = start_daemon(scratch, "d", scratch.file("state.isfstore"));
  ISF_REQUIRE_OK(daemon);
  auto operator_client = connect_to(daemon.value(), "operator");
  ISF_REQUIRE_OK(operator_client);
  // 1000 authoritative units with the default 10% protected floor leaves 900
  // allocatable, so exactly three of the six 300-unit requests can fit.
  auto world = build_world(operator_client.value(), "mp", 1000);
  ISF_REQUIRE_OK(world);

  constexpr int kAgents = 6;
  const auto tag_for = [](int index) { return "agent-" + std::to_string(index) + "-err.txt"; };
  std::vector<ChildProcess> agents;
  for (int index = 0; index < kAgents; ++index) {
    const bool use_a = (index % 2) == 0;
    const std::string tag = "agent-" + std::to_string(index);
    std::vector<std::string> arguments{
        "--daemon",      daemon.value().endpoint_text,
        "--site-name",   use_a ? world.value().a : world.value().b,
        "--site-id",     (use_a ? world.value().site_a : world.value().site_b).to_string(),
        "--path",        world.value().path.to_string(),
        "--reserve",     "300",
        "--duration-ms", "600000",
        // Agents of the same site share that site's incarnation: a *different*
        // incarnation would legitimately fence the previous agent's grants,
        // which is a different property tested elsewhere.
        "--incarnation",
        (use_a ? world.value().a_incarnation : world.value().b_incarnation).to_string(),
        "--result-file", scratch.file(tag + "-result.txt")};
    auto agent = start_agent(scratch, tag, arguments);
    ISF_REQUIRE_OK(agent);
    agents.push_back(std::move(agent.value()));
  }

  int active = 0;
  int refused = 0;
  for (int index = 0; index < kAgents; ++index) {
    ChildProcess& agent = agents[static_cast<std::size_t>(index)];
    std::uint32_t code = 0;
    const ProcessState state = agent.wait_for_exit(kExitBoundMs, code);
    if (state == ProcessState::Running) {
      (void)agent.terminate();
      ISF_FAIL("site agent did not exit within the observation bound");
    }
    if (code != 0 && code != 5) {
      ISF_FAIL("site agent " + std::to_string(index) + " exited with code " +
               std::to_string(code) + " (agent stderr is in " + scratch.file(tag_for(index)) + ")");
    }
    if (code == 0) {
      ++active;
    } else {
      ++refused;
    }
  }
  // 900 allocatable units and six independent 300-unit requests: exactly three.
  ISF_REQUIRE_EQ(active, 3);
  ISF_REQUIRE_EQ(refused, 3);

  auto ledger = operator_client.value().ledger(world.value().path);
  ISF_REQUIRE_OK(ledger);
  ISF_REQUIRE_EQ(ledger.value().committed, Amount{900});
  ISF_REQUIRE_EQ(ledger.value().allocatable, Amount{0});
  ISF_REQUIRE_EQ(ledger.value().oversubscribed, Amount{0});
  ISF_REQUIRE_EQ(ledger.value().verify_closure(), Status::Ok);

  shutdown_daemon(scratch, daemon.value());
}

ISF_TEST(multiprocess, isfctl_drives_the_full_lifecycle) {
  ScratchDir scratch("mp-ctl");
  auto daemon = start_daemon(scratch, "d", scratch.file("state.isfstore"));
  ISF_REQUIRE_OK(daemon);
  const std::string endpoint = daemon.value().endpoint_text;

  ISF_REQUIRE_EQ(run_ctl(scratch, {"--daemon", endpoint, "probe"}, "probe"), 0U);
  ISF_REQUIRE_EQ(run_ctl(scratch,
                         {"--daemon", endpoint, "site-register", "--name", "ctl-a", "--capacity",
                          "1000"},
                         "site-a"),
                 0U);
  ISF_REQUIRE_EQ(run_ctl(scratch,
                         {"--daemon", endpoint, "site-register", "--name", "ctl-b"},
                         "site-b"),
                 0U);

  const SiteId site_a = site_from_name("ctl-a");
  const SiteId site_b = site_from_name("ctl-b");
  const PathId path = path_from_name("ctl-path");
  ISF_REQUIRE_EQ(run_ctl(scratch,
                         {"--daemon", endpoint, "path-register", "--path", path.to_string(),
                          "--name", "ctl-path", "--a", site_a.to_string(), "--b",
                          site_b.to_string()},
                         "path"),
                 0U);
  ISF_REQUIRE_EQ(run_ctl(scratch,
                         {"--daemon", endpoint, "attest", "--path", path.to_string(), "--usable",
                          "1000"},
                         "attest"),
                 0U);
  ISF_REQUIRE_EQ(run_ctl(scratch,
                         {"--daemon", endpoint, "grant-propose", "--site", site_a.to_string(),
                          "--path", path.to_string(), "--amount", "300"},
                         "propose"),
                 0U);

  // Recover the grant identity from the daemon rather than parsing the CLI.
  auto client = connect_to(daemon.value(), "operator");
  ISF_REQUIRE_OK(client);
  auto grants = find_grants(client.value(), path);
  ISF_REQUIRE_EQ(grants.size(), std::size_t{1});
  const GrantId grant = grants.front().id;

  ISF_REQUIRE_EQ(run_ctl(scratch, {"--daemon", endpoint, "grant-evaluate", "--grant", grant.to_string()},
                         "evaluate"),
                 0U);
  ISF_REQUIRE_EQ(run_ctl(scratch, {"--daemon", endpoint, "grant-reserve", "--grant", grant.to_string()},
                         "reserve"),
                 0U);
  ISF_REQUIRE_EQ(run_ctl(scratch, {"--daemon", endpoint, "grant-activate", "--grant", grant.to_string()},
                         "activate"),
                 0U);
  ISF_REQUIRE_EQ(run_ctl(scratch, {"--daemon", endpoint, "grant-ack", "--grant", grant.to_string()},
                         "ack"),
                 0U);
  ISF_REQUIRE_EQ(run_ctl(scratch,
                         {"--daemon", endpoint, "grant-verify", "--grant", grant.to_string(),
                          "--result", "verified"},
                         "verify"),
                 0U);
  ISF_REQUIRE_EQ(run_ctl(scratch, {"--daemon", endpoint, "verify"}, "verify-ledgers"), 0U);
  ISF_REQUIRE_EQ(run_ctl(scratch, {"--daemon", endpoint, "digest"}, "digest"), 0U);

  auto ledger = client.value().ledger(path);
  ISF_REQUIRE_OK(ledger);
  ISF_REQUIRE_EQ(ledger.value().committed, Amount{300});
  ISF_REQUIRE_EQ(ledger.value().verify_closure(), Status::Ok);

  auto current = client.value().list_grants();
  ISF_REQUIRE_OK(current);
  ISF_REQUIRE_EQ(current.value().size(), std::size_t{1});
  // Acknowledgement and independent verification are tracked separately.
  ISF_CHECK(current.value().front().acknowledged);
  ISF_CHECK(current.value().front().verification == VerificationState::Verified);

  ISF_REQUIRE_EQ(run_ctl(scratch, {"--daemon", endpoint, "grant-withdraw", "--grant", grant.to_string()},
                         "withdraw"),
                 0U);
  ISF_REQUIRE_EQ(run_ctl(scratch, {"--daemon", endpoint, "grant-retire", "--grant", grant.to_string()},
                         "retire"),
                 0U);
  ledger = client.value().ledger(path);
  ISF_REQUIRE_OK(ledger);
  ISF_REQUIRE_EQ(ledger.value().committed, Amount{0});
  ISF_REQUIRE_EQ(ledger.value().withdrawing, Amount{0});

  // A malformed command must fail loudly rather than succeed.
  ISF_CHECK(run_ctl(scratch, {"--daemon", endpoint, "no-such-command"}, "bad-command") != 0U);
  ISF_CHECK(run_ctl(scratch, {"--daemon", endpoint, "ledger", "--path", "not-an-id"}, "bad-id") != 0U);

  shutdown_daemon(scratch, daemon.value());
}

// ---------------------------------------------------------------------------
// Kill and restart at durable commit boundaries
// ---------------------------------------------------------------------------

namespace {

/// Prepare a durable state with one site pair and an attested path, then stop.
Expected<World> prepare_state(ScratchDir& scratch, const std::string& state_path,
                              Amount usable) {
  auto daemon = start_daemon(scratch, "prepare", state_path);
  if (!daemon.ok()) {
    return daemon.status();
  }
  auto client = connect_to(daemon.value(), "operator");
  if (!client.ok()) {
    (void)daemon.value().process.terminate();
    return client.status();
  }
  auto world = build_world(client.value(), "crash", usable);
  if (!world.ok()) {
    (void)daemon.value().process.terminate();
    return world.status();
  }
  client.value().close();
  auto ctl = find_program("isfctl");
  if (!ctl.ok()) {
    (void)daemon.value().process.terminate();
    return ctl.status();
  }
  auto spawned = ChildProcess::spawn({ctl.value(), "--daemon", daemon.value().endpoint_text, "shutdown"},
                                     scratch.path(), scratch.file("stop-out.txt"),
                                     scratch.file("stop-err.txt"));
  if (!spawned.ok()) {
    (void)daemon.value().process.terminate();
    return spawned.status();
  }
  std::uint32_t code = 0;
  (void)spawned.value().wait_for_exit(kExitBoundMs, code);
  std::uint32_t daemon_code = 0;
  const ProcessState state = daemon.value().process.wait_for_exit(kExitBoundMs, daemon_code);
  if (state != ProcessState::Exited || daemon_code != 0) {
    (void)daemon.value().process.terminate();
    return Outcome(Status::Unavailable, "the preparation daemon did not stop cleanly");
  }
  return world.value();
}

}  // namespace

ISF_TEST(multiprocess, ambiguous_intent_at_the_durable_boundary_recovers_conservatively) {
  const std::vector<std::string> stages{"intent-durable", "applied"};
  for (const auto& stage : stages) {
    ScratchDir scratch("mp-ambiguous-" + stage);
    const std::string state_path = scratch.file("state.isfstore");
    auto world = prepare_state(scratch, state_path, 1000);
    ISF_REQUIRE_OK(world);

    // Crash exactly at the named durable boundary while proposing one grant.
    auto doomed = start_daemon(scratch, "doomed", state_path,
                               {"--fault-inject", stage, "--ticker", "false"});
    ISF_REQUIRE_OK(doomed);
    auto client = connect_to(doomed.value(), "operator");
    ISF_REQUIRE_OK(client);
    GrantProposal proposal;
    proposal.request = RequestId::from_seed(0x5A17, 1);
    proposal.holder = world.value().site_a;
    proposal.holder_incarnation = world.value().a_incarnation;
    proposal.path = world.value().path;
    proposal.amount = 200;
    proposal.duration_ms = 600000;
    proposal.now_ms = now_ms();
    // The mutation is processed; the process dies part way through committing
    // it, so the reply may or may not arrive.
    (void)client.value().propose_grant(proposal);
    require_abnormal_exit(doomed.value().process, "daemon with fault injection at " + stage);

    // Restart cleanly and inspect what survived.
    auto restarted = start_daemon(scratch, "restart-" + stage, state_path);
    ISF_REQUIRE_OK(restarted);
    auto recovered = connect_to(restarted.value(), "operator");
    ISF_REQUIRE_OK(recovered);
    auto status = recovered.value().status();
    ISF_REQUIRE_OK(status);
    ISF_REQUIRE(status.value().store_servable);
    ISF_CHECK(status.value().store_fidelity == RecoveryFidelity::AmbiguousIntentResolved ||
              status.value().store_fidelity == RecoveryFidelity::TornTailTruncated ||
              status.value().store_fidelity == RecoveryFidelity::Exact);
    ISF_REQUIRE(status.value().ambiguous_intents >= std::size_t{1});

    auto grants = find_grants(recovered.value(), world.value().path);
    ISF_REQUIRE_EQ(grants.size(), std::size_t{1});
    // The write-ahead intent is present but has no completion record, so the
    // grant is recovered as ambiguous and must be reconciled before use.
    ISF_CHECK(grants.front().ambiguous);
    ISF_CHECK(grants.front().historical);
    ISF_CHECK(grants.front().provenance == Provenance::AmbiguousCommit);
    ISF_CHECK(grants.front().state == GrantState::Proposed);

    GrantOperation op;
    op.grant = grants.front().id;
    op.epoch = recovered.value().hello().epoch;
    op.now_ms = now_ms();
    auto evaluated = recovered.value().evaluate_grant(op);
    ISF_REQUIRE(!evaluated.ok());
    ISF_REQUIRE_EQ(static_cast<int>(evaluated.status()), static_cast<int>(Status::Indeterminate));

    // An operator resolves the ambiguity explicitly.
    auto reconciled = recovered.value().reconcile_grant(op, GrantState::Retired,
                                                        principal_from_name("operator"));
    ISF_REQUIRE_OK(reconciled);
    auto ledger = recovered.value().ledger(world.value().path);
    ISF_REQUIRE_OK(ledger);
    ISF_REQUIRE_EQ(ledger.value().reserved, Amount{0});
    ISF_REQUIRE_EQ(ledger.value().verify_closure(), Status::Ok);
    shutdown_daemon(scratch, restarted.value());
  }
}

ISF_TEST(multiprocess, completed_transaction_at_the_commit_boundary_recovers_cleanly) {
  ScratchDir scratch("mp-committed");
  const std::string state_path = scratch.file("state.isfstore");
  auto world = prepare_state(scratch, state_path, 1000);
  ISF_REQUIRE_OK(world);

  auto doomed = start_daemon(scratch, "doomed", state_path,
                             {"--fault-inject", "commit-durable", "--ticker", "false"});
  ISF_REQUIRE_OK(doomed);
  auto client = connect_to(doomed.value(), "operator");
  ISF_REQUIRE_OK(client);
  GrantProposal proposal;
  proposal.request = RequestId::from_seed(0x5A17, 2);
  proposal.holder = world.value().site_a;
  proposal.holder_incarnation = world.value().a_incarnation;
  proposal.path = world.value().path;
  proposal.amount = 300;
  proposal.duration_ms = 600000;
  proposal.now_ms = now_ms();
  (void)client.value().propose_grant(proposal);
  require_abnormal_exit(doomed.value().process, "daemon with fault injection at commit-durable");

  auto restarted = start_daemon(scratch, "restarted", state_path);
  ISF_REQUIRE_OK(restarted);
  auto recovered = connect_to(restarted.value(), "operator");
  ISF_REQUIRE_OK(recovered);
  auto status = recovered.value().status();
  ISF_REQUIRE_OK(status);
  ISF_REQUIRE(status.value().store_servable);
  ISF_REQUIRE_EQ(status.value().ambiguous_intents, std::size_t{0});

  auto grants = find_grants(recovered.value(), world.value().path);
  ISF_REQUIRE_EQ(grants.size(), std::size_t{1});
  ISF_CHECK(!grants.front().ambiguous);
  ISF_CHECK(grants.front().state == GrantState::Proposed);
  ISF_CHECK(grants.front().provenance == Provenance::RecoveredFromLog);
  ISF_CHECK(grants.front().historical);

  GrantOperation op;
  op.grant = grants.front().id;
  op.actor = world.value().site_a;
  op.actor_incarnation = world.value().a_incarnation;
  op.epoch = recovered.value().hello().epoch;
  op.now_ms = now_ms();
  ISF_REQUIRE_OK(recovered.value().evaluate_grant(op));
  ISF_REQUIRE_OK(recovered.value().reserve_grant(op));
  auto ledger = recovered.value().ledger(world.value().path);
  ISF_REQUIRE_OK(ledger);
  ISF_REQUIRE_EQ(ledger.value().reserved, Amount{300});
  shutdown_daemon(scratch, restarted.value());
}

ISF_TEST(multiprocess, a_crash_during_a_release_never_frees_capacity) {
  ScratchDir scratch("mp-release");
  const std::string state_path = scratch.file("state.isfstore");
  auto world = prepare_state(scratch, state_path, 1000);
  ISF_REQUIRE_OK(world);

  // Establish a live obligation on a clean daemon.
  GrantId grant{};
  {
    auto daemon = start_daemon(scratch, "live", state_path);
    ISF_REQUIRE_OK(daemon);
    auto client = connect_to(daemon.value(), "operator");
    ISF_REQUIRE_OK(client);
    auto fixture = load_fixture(client.value(), world.value());
    ISF_REQUIRE_OK(fixture);
    auto granted = request_grant(client.value(), fixture.value(), true, 400);
    ISF_REQUIRE_OK(granted);
    ISF_REQUIRE(granted.value().state == GrantState::Active);
    grant = granted.value().id;
    auto ledger = client.value().ledger(world.value().path);
    ISF_REQUIRE_OK(ledger);
    ISF_REQUIRE_EQ(ledger.value().committed, Amount{400});
    // Move the grant to WITHDRAWING first: retiring is the step that actually
    // releases capacity, and that is the step whose crash we want to study.
    GrantOperation withdraw;
    withdraw.grant = grant;
    withdraw.epoch = client.value().hello().epoch;
    withdraw.now_ms = now_ms();
    withdraw.reason = "prepare for the release crash";
    ISF_REQUIRE_OK(client.value().withdraw_grant(withdraw));
    ledger = client.value().ledger(world.value().path);
    ISF_REQUIRE_OK(ledger);
    ISF_REQUIRE_EQ(ledger.value().withdrawing, Amount{400});
    shutdown_daemon(scratch, daemon.value());
  }

  // Crash while retiring the grant. Retirement releases capacity, so the
  // ambiguous intent must be suppressed on recovery.
  {
    auto doomed = start_daemon(scratch, "doomed", state_path,
                               {"--fault-inject", "intent-durable", "--ticker", "false"});
    ISF_REQUIRE_OK(doomed);
    auto client = connect_to(doomed.value(), "operator");
    ISF_REQUIRE_OK(client);
    GrantOperation op;
    op.grant = grant;
    op.epoch = client.value().hello().epoch;
    op.now_ms = now_ms();
    op.reason = "crash during release";
    (void)client.value().retire_grant(op);
    require_abnormal_exit(doomed.value().process, "daemon crashing during a release");
  }

  auto restarted = start_daemon(scratch, "restarted", state_path);
  ISF_REQUIRE_OK(restarted);
  auto recovered = connect_to(restarted.value(), "operator");
  ISF_REQUIRE_OK(recovered);
  auto ledger = recovered.value().ledger(world.value().path);
  ISF_REQUIRE_OK(ledger);
  // The release was not applied: the capacity is still accounted for.
  ISF_REQUIRE(ledger.value().committed + ledger.value().withdrawing > 0);
  auto obligations = checked_add(ledger.value().committed, ledger.value().withdrawing);
  ISF_REQUIRE_OK(obligations);
  ISF_REQUIRE_EQ(obligations.value(), Amount{400});
  // The 400 units being withdrawn are blocked, but the rest of the basis is
  // still allocatable: 1000 usable minus a 100 unit protected floor minus 400.
  ISF_REQUIRE_EQ(ledger.value().allocatable,
                 ledger.value().authoritative_usable - ledger.value().protected_headroom -
                     Amount{400});
  ISF_REQUIRE_EQ(ledger.value().verify_closure(), Status::Ok);

  auto grants = find_grants(recovered.value(), world.value().path);
  ISF_REQUIRE_EQ(grants.size(), std::size_t{1});
  ISF_CHECK(grants.front().state != GrantState::Retired);
  ISF_CHECK(grants.front().state != GrantState::Expired);

  // Exactly the reported allocatable headroom is available: one unit more is
  // refused, which is the observable form of "withdrawn capacity is not
  // silently reallocated".
  auto fixture = load_fixture(recovered.value(), world.value());
  ISF_REQUIRE_OK(fixture);
  {
    const Amount headroom = ledger.value().allocatable;
    auto fits = request_grant(recovered.value(), fixture.value(), true, headroom);
    ISF_REQUIRE_OK(fits);
    ISF_CHECK(fits.value().state == GrantState::Active);
    auto over = request_grant(recovered.value(), fixture.value(), false, headroom + 1);
    ISF_CHECK(!over.ok());
    ISF_CHECK_EQ(static_cast<int>(over.status()), static_cast<int>(Status::Exhausted));
    // Release the probe grant again so the rest of the test sees 400 units.
    GrantOperation release;
    release.grant = fits.value().id;
    release.epoch = recovered.value().hello().epoch;
    release.now_ms = now_ms();
    release.reason = "probe cleanup";
    ISF_CHECK(recovered.value().withdraw_grant(release).ok());
    ISF_CHECK(recovered.value().retire_grant(release).ok());
  }
  ledger = recovered.value().ledger(world.value().path);
  ISF_REQUIRE_OK(ledger);
  ISF_REQUIRE_EQ(ledger.value().withdrawing, Amount{400});

  // The operator can now release it explicitly.
  GrantOperation op;
  op.grant = grant;
  op.now_ms = now_ms();
  op.reason = "operator reconciliation";
  auto reconciled =
      recovered.value().reconcile_grant(op, GrantState::Retired, principal_from_name("operator"));
  ISF_REQUIRE_OK(reconciled);
  ledger = recovered.value().ledger(world.value().path);
  ISF_REQUIRE_OK(ledger);
  ISF_REQUIRE_EQ(ledger.value().committed, Amount{0});
  ISF_REQUIRE_EQ(ledger.value().withdrawing, Amount{0});
  ISF_REQUIRE_EQ(ledger.value().verify_closure(), Status::Ok);
  shutdown_daemon(scratch, restarted.value());
}

// ---------------------------------------------------------------------------
// Stale incarnation fencing across an agent restart
// ---------------------------------------------------------------------------

ISF_TEST(multiprocess, stale_site_incarnation_is_fenced_after_an_agent_restart) {
  ScratchDir scratch("mp-fencing");
  auto daemon = start_daemon(scratch, "d", scratch.file("state.isfstore"));
  ISF_REQUIRE_OK(daemon);
  auto operator_client = connect_to(daemon.value(), "operator");
  ISF_REQUIRE_OK(operator_client);
  auto world = build_world(operator_client.value(), "fence", 1000);
  ISF_REQUIRE_OK(world);

  const Incarnation first_incarnation = Incarnation::from_seed(0xF1257, 1);
  {
    auto agent = start_agent(scratch, "agent-1",
                             {"--daemon", daemon.value().endpoint_text, "--site-name",
                              world.value().a, "--site-id", world.value().site_a.to_string(),
                              "--path", world.value().path.to_string(), "--reserve", "400",
                              "--incarnation", first_incarnation.to_string(), "--heartbeat-ms",
                              "200", "--run-ms", "60000", "--ready-file",
                              scratch.file("agent-1-ready.txt"), "--result-file",
                              scratch.file("agent-1-result.txt")});
    ISF_REQUIRE_OK(agent);
    auto report = wait_for_report(scratch.file("agent-1-ready.txt"), kReadyBoundMs);
    ISF_REQUIRE_OK(report);
    // Wait until the grant is live.
    bool active = false;
    for (int attempt = 0; attempt < 200 && !active; ++attempt) {
      auto grants = find_grants(operator_client.value(), world.value().path);
      if (!grants.empty() && grants.front().state == GrantState::Active) {
        active = true;
        break;
      }
      sleep_ms(25);
    }
    ISF_REQUIRE(active);
    // Hard kill: no shutdown path runs in the agent.
    ISF_REQUIRE(agent.value().terminate());
    std::uint32_t code = 0;
    (void)agent.value().wait_for_exit(kExitBoundMs, code);
  }

  auto before = find_grants(operator_client.value(), world.value().path);
  ISF_REQUIRE_EQ(before.size(), std::size_t{1});
  const GrantId stale_grant = before.front().id;
  ISF_REQUIRE(before.front().binding.holder_incarnation == first_incarnation);

  // A replacement agent process for the same site, with a fresh incarnation.
  const Incarnation second_incarnation = Incarnation::from_seed(0xF1257, 2);
  {
    auto agent = start_agent(scratch, "agent-2",
                             {"--daemon", daemon.value().endpoint_text, "--site-name",
                              world.value().a, "--site-id", world.value().site_a.to_string(),
                              "--incarnation", second_incarnation.to_string(),
                              "--register-only", "--ready-file",
                              scratch.file("agent-2-ready.txt"), "--result-file",
                              scratch.file("agent-2-result.txt")});
    ISF_REQUIRE_OK(agent);
    require_exit(agent.value(), 0, "replacement site agent registration");
    auto report = read_report(scratch.file("agent-2-result.txt"));
    // Generation 1 came from the fixture registration, generation 2 from the
    // first agent incarnation, and generation 3 from the replacement agent.
    ISF_REQUIRE_EQ(report_value(report, "site_generation"), std::string("3"));
  }

  auto after = find_grants(operator_client.value(), world.value().path);
  ISF_REQUIRE_EQ(after.size(), std::size_t{1});
  ISF_CHECK(after.front().state == GrantState::Withdrawing);
  ISF_CHECK(after.front().historical);
  ISF_CHECK(after.front().provenance == Provenance::FencedIncarnation);
  ISF_CHECK(after.front().verification == VerificationState::Unverified);

  // The superseded incarnation has no authority left.
  SiteHeartbeat stale_heartbeat;
  stale_heartbeat.id = world.value().site_a;
  stale_heartbeat.incarnation = first_incarnation;
  stale_heartbeat.epoch = operator_client.value().hello().epoch;
  stale_heartbeat.now_ms = now_ms();
  auto beat = operator_client.value().heartbeat(stale_heartbeat);
  ISF_REQUIRE(!beat.ok());
  ISF_REQUIRE_EQ(static_cast<int>(beat.status()), static_cast<int>(Status::Fenced));

  // Capacity stays accounted for until an operator reconciles the stale grant.
  auto ledger = operator_client.value().ledger(world.value().path);
  ISF_REQUIRE_OK(ledger);
  ISF_REQUIRE_EQ(ledger.value().withdrawing, Amount{400});
  // The withdrawn capacity is blocked, and the rest of the basis remains
  // allocatable for grants bound to the current site incarnation.
  ISF_REQUIRE_EQ(ledger.value().allocatable,
                 ledger.value().authoritative_usable - ledger.value().protected_headroom -
                     Amount{400});

  GrantOperation op;
  op.grant = stale_grant;
  op.now_ms = now_ms();
  op.reason = "operator reconciliation";
  auto reconciled =
      operator_client.value().reconcile_grant(op, GrantState::Retired, principal_from_name("operator"));
  ISF_REQUIRE_OK(reconciled);
  ledger = operator_client.value().ledger(world.value().path);
  ISF_REQUIRE_OK(ledger);
  ISF_REQUIRE_EQ(ledger.value().withdrawing, Amount{0});

  // The replacement incarnation can now be granted capacity.
  auto fixture = load_fixture(operator_client.value(), world.value());
  ISF_REQUIRE_OK(fixture);
  auto granted = request_grant(operator_client.value(), fixture.value(), true, 400);
  ISF_REQUIRE_OK(granted);
  ISF_REQUIRE(granted.value().state == GrantState::Active);

  shutdown_daemon(scratch, daemon.value());
}

// ---------------------------------------------------------------------------
// Clean restart and damaged state
// ---------------------------------------------------------------------------

ISF_TEST(multiprocess, clean_restart_preserves_authoritative_state) {
  ScratchDir scratch("mp-restart");
  const std::string state_path = scratch.file("state.isfstore");
  std::string digest_before;
  std::string ledger_before;
  {
    auto daemon = start_daemon(scratch, "first", state_path);
    ISF_REQUIRE_OK(daemon);
    auto client = connect_to(daemon.value(), "operator");
    ISF_REQUIRE_OK(client);
    auto world = build_world(client.value(), "restart", 5000);
    ISF_REQUIRE_OK(world);
    auto fixture = load_fixture(client.value(), world.value());
    ISF_REQUIRE_OK(fixture);
    auto grant = request_grant(client.value(), fixture.value(), true, 700);
    ISF_REQUIRE_OK(grant);
    auto ledger = client.value().ledger(world.value().path);
    ISF_REQUIRE_OK(ledger);
    ledger_before = ledger.value().to_string();
    auto digest = client.value().digest();
    ISF_REQUIRE_OK(digest);
    digest_before = digest.value().state_digest.to_hex();
    auto grants_before = client.value().list_grants();
    ISF_REQUIRE_OK(grants_before);
    ISF_REQUIRE_EQ(grants_before.value().size(), std::size_t{1});
    ISF_CHECK(grants_before.value().front().state == GrantState::Active);
    ISF_CHECK(!grants_before.value().front().historical);
    shutdown_daemon(scratch, daemon.value());
  }
  auto restarted = start_daemon(scratch, "second", state_path);
  ISF_REQUIRE_OK(restarted);
  auto client = connect_to(restarted.value(), "operator");
  ISF_REQUIRE_OK(client);
  auto status = client.value().status();
  ISF_REQUIRE_OK(status);
  ISF_REQUIRE(status.value().store_servable);
  ISF_REQUIRE(status.value().store_fidelity == RecoveryFidelity::Exact ||
              status.value().store_fidelity == RecoveryFidelity::Missing);
  auto digest = client.value().digest();
  ISF_REQUIRE_OK(digest);
  // The digest deliberately changes across a restart: every recovered grant is
  // marked historical with recovered provenance, so recovered dynamic evidence
  // is never silently fresh. The substantive state must be identical.
  ISF_CHECK(digest.value().state_digest.to_hex() != digest_before);

  auto paths = client.value().list_paths();
  ISF_REQUIRE_OK(paths);
  ISF_REQUIRE_EQ(paths.value().size(), std::size_t{1});
  auto ledger = client.value().ledger(paths.value().front().id);
  ISF_REQUIRE_OK(ledger);
  ISF_CHECK_EQ(ledger.value().to_string(), ledger_before);
  ISF_REQUIRE_EQ(ledger.value().verify_closure(), Status::Ok);

  // The recovered grant is historical and unverified: recovered dynamic
  // evidence is never silently fresh.
  auto grants = client.value().list_grants();
  ISF_REQUIRE_OK(grants);
  ISF_REQUIRE_EQ(grants.value().size(), std::size_t{1});
  ISF_CHECK(grants.value().front().historical);
  ISF_CHECK(grants.value().front().verification == VerificationState::Unverified);
  ISF_CHECK(!grants.value().front().ambiguous);
  // The obligation itself is unchanged: same state, same amount.
  ISF_CHECK(grants.value().front().state == GrantState::Active);
  ISF_CHECK_EQ(grants.value().front().amount, Amount{700});
  ISF_CHECK(grants.value().front().provenance == Provenance::RecoveredFromLog);

  shutdown_daemon(scratch, restarted.value());
}

ISF_TEST(multiprocess, corrupt_durable_state_refuses_to_serve_after_restart) {
  ScratchDir scratch("mp-corrupt");
  const std::string state_path = scratch.file("state.isfstore");
  {
    auto daemon = start_daemon(scratch, "first", state_path);
    ISF_REQUIRE_OK(daemon);
    auto client = connect_to(daemon.value(), "operator");
    ISF_REQUIRE_OK(client);
    auto world = build_world(client.value(), "corrupt", 1000);
    ISF_REQUIRE_OK(world);
    auto fixture = load_fixture(client.value(), world.value());
    ISF_REQUIRE_OK(fixture);
    ISF_REQUIRE_OK(request_grant(client.value(), fixture.value(), true, 200));
    shutdown_daemon(scratch, daemon.value());
  }
  // Damage a record in the middle of the log.
  std::vector<Byte> bytes;
  {
    std::FILE* fp = std::fopen(state_path.c_str(), "rb");
    ISF_REQUIRE(fp != nullptr);
    std::array<Byte, 4096> buffer{};
    std::size_t got = 0;
    while ((got = std::fread(buffer.data(), 1, buffer.size(), fp)) > 0) {
      bytes.insert(bytes.end(), buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(got));
    }
    std::fclose(fp);
  }
  ISF_REQUIRE(bytes.size() > 600);
  bytes[400] = static_cast<Byte>(bytes[400] ^ 0x3CU);
  {
    std::FILE* fp = std::fopen(state_path.c_str(), "wb");
    ISF_REQUIRE(fp != nullptr);
    (void)std::fwrite(bytes.data(), 1, bytes.size(), fp);
    std::fclose(fp);
  }

  auto isfd = find_program("isfd");
  ISF_REQUIRE_OK(isfd);
  auto spawned = ChildProcess::spawn({isfd.value(), "--state", state_path, "--listen",
                                      "127.0.0.1:0", "--ready-file",
                                      scratch.file("corrupt-ready.txt"), "--log-level", "error"},
                                     scratch.path(), scratch.file("corrupt-out.txt"),
                                     scratch.file("corrupt-err.txt"));
  ISF_REQUIRE_OK(spawned);
  ChildProcess process = std::move(spawned.value());
  std::uint32_t code = 0;
  const ProcessState state = process.wait_for_exit(kExitBoundMs, code);
  if (state == ProcessState::Running) {
    (void)process.terminate();
    ISF_FAIL("a daemon started on a corrupt store did not exit");
  }
  ISF_CHECK_EQ(code, 4U);
  // It must not have published a readiness file.
  const auto ready = read_report(scratch.file("corrupt-ready.txt"));
  ISF_CHECK(ready.empty());
}
