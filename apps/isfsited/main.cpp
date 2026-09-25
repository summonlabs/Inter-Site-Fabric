// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// isfsited: the site agent. One OS process per physical site. It registers its
// site identity and incarnation with the fabric daemon, heartbeats, and drives
// the grant lifecycle on behalf of that site.

#include "cli.hpp"

#include "isf/client.hpp"
#include "isf/clock.hpp"
#include "isf/digest.hpp"
#include "isf/log.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <thread>
#include <vector>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <csignal>
#endif

namespace {

std::atomic<bool> g_stop_requested{false};

#if defined(_WIN32)
BOOL WINAPI console_handler(DWORD event) {
  if (event == CTRL_C_EVENT || event == CTRL_BREAK_EVENT || event == CTRL_CLOSE_EVENT) {
    g_stop_requested.store(true);
    return TRUE;
  }
  return FALSE;
}
#endif

void usage() {
  std::fputs(
      "isfsited - inter-site fabric site agent\n"
      "\n"
      "usage: isfsited --daemon HOST:PORT --site-name NAME [options]\n"
      "  --site-id ID               stable site identity (default: derived from the name)\n"
      "  --incarnation HEX          fixed process incarnation (default: random)\n"
      "  --path ID                  inter-site path to request capacity on\n"
      "  --reserve N                capacity units to reserve and activate\n"
      "  --duration-ms N            lease duration requested (default 600000)\n"
      "  --grant-class general|protected\n"
      "  --heartbeat-ms N           heartbeat interval (default 0, no heartbeats)\n"
      "  --run-ms N                 exit after N milliseconds (0 means run until stopped)\n"
      "  --ready-file PATH          write identity and endpoint once registered\n"
      "  --result-file PATH         write the resulting grant\n"
      "  --register-only            register and exit without requesting capacity\n"
      "  --reconcile ID             reconcile an existing grant to retired or active\n"
      "  --reconcile-target STATE   retired|active (default retired)\n"
      "  --fault-inject STAGE       abort at registered|reserved|activated\n"
      "  --log-level LEVEL          error|warn|info|debug|trace\n",
      stdout);
}

[[nodiscard]] isf::SiteId derive_site_id(const std::string& name) {
  return isf::SiteId::from_seed(isf::fnv1a64(name), 0x15F0517EULL);
}

[[nodiscard]] std::vector<std::pair<std::string, std::string>> base_report(const isf::SiteRecord& site) {
  std::vector<std::pair<std::string, std::string>> entries;
  entries.emplace_back("site_id", site.id.to_string());
  entries.emplace_back("site_name", site.name);
  entries.emplace_back("site_incarnation", site.incarnation.to_string());
  entries.emplace_back("site_generation", site.generation.to_string());
  entries.emplace_back("site_state", isf::site_state_name(site.state));
  return entries;
}

}  // namespace

int main(int argc, char** argv) {
  isf::cli::Arguments args(argc, argv);
  if (args.has("help")) {
    usage();
    return 0;
  }
  isf::LogLevel level = isf::LogLevel::Info;
  (void)isf::log_level_from_name(args.value_or("log-level", "warn"), level);
  isf::set_log_level(level);

  const isf::Outcome required = args.validate({"daemon", "site-name"});
  if (required != isf::Status::Ok) {
    std::fprintf(stderr, "isfsited: %s\n", required.to_string().c_str());
    usage();
    return 2;
  }
  const std::string daemon_endpoint = args.value_or("daemon", "127.0.0.1:0");
  const std::string site_name = args.value_or("site-name", "");
  const std::string ready_file = args.value_or("ready-file", "");
  const std::string result_file = args.value_or("result-file", "");
  const std::string fault_stage = args.value_or("fault-inject", "");
  const std::string path_text = args.value_or("path", "");
  const bool register_only = args.flag_or("register-only", false);
  const std::uint64_t reserve = args.u64_or("reserve", 0);
  const std::uint64_t duration_ms = args.u64_or("duration-ms", 600000);
  const std::uint64_t heartbeat_ms = args.u64_or("heartbeat-ms", 0);
  const std::uint64_t run_ms = args.u64_or("run-ms", 0);
  const std::string reconcile_text = args.value_or("reconcile", "");

  isf::SiteId site_id = derive_site_id(site_name);
  if (args.has("site-id")) {
    auto parsed = isf::SiteId::parse(args.value_or("site-id", ""));
    if (!parsed.ok()) {
      std::fprintf(stderr, "isfsited: --site-id is not a valid identity\n");
      return 2;
    }
    site_id = parsed.value();
  }
  isf::Incarnation incarnation = isf::Incarnation::random();
  if (args.has("incarnation")) {
    // Accept both the bare 32-digit form and the canonical "inc:..." form.
    auto parsed = isf::Incarnation::parse(args.value_or("incarnation", ""));
    if (!parsed.ok()) {
      std::fprintf(stderr, "isfsited: --incarnation is not a valid identity\n");
      return 2;
    }
    incarnation = parsed.value();
  }

  isf::ClientOptions options;
  auto endpoint = isf::Endpoint::parse(daemon_endpoint);
  if (!endpoint.ok()) {
    std::fprintf(stderr, "isfsited: %s\n", endpoint.detail().c_str());
    return 2;
  }
  options.endpoint = endpoint.value();
  options.client_kind = "isfsited";
  options.io_timeout_ms = 30000;

  auto client = isf::FabricClient::connect(options);
  if (!client.ok()) {
    std::fprintf(stderr, "isfsited: %s\n", client.outcome().to_string().c_str());
    return 3;
  }
  const std::uint64_t now = isf::now_ms();
  const isf::Epoch epoch = client.value().hello().epoch;

  isf::SiteDescriptor descriptor;
  descriptor.id = site_id;
  descriptor.name = site_name;
  descriptor.advertised_capacity = args.u64_or("advertised-capacity", 0);

  auto registered = client.value().register_site(descriptor, incarnation, epoch, now);
  if (!registered.ok()) {
    std::fprintf(stderr, "isfsited: site registration refused: %s\n",
                 registered.outcome().to_string().c_str());
    (void)isf::cli::write_report_file(result_file,
                                      {{"error", registered.outcome().to_string()}});
    return 4;
  }
  auto site = isf::extract_site(registered.value());
  if (!site.ok()) {
    std::fprintf(stderr, "isfsited: registration reply did not carry a site record\n");
    return 4;
  }
  std::vector<std::pair<std::string, std::string>> report = base_report(site.value());
  report.emplace_back("daemon_endpoint", daemon_endpoint);
  report.emplace_back("epoch", epoch.to_string());

  if (fault_stage == "registered") {
    (void)isf::cli::write_report_file(ready_file, report);
    std::fprintf(stderr, "isfsited: fault injection after registration\n");
    std::fflush(stderr);
    std::_Exit(EXIT_FAILURE);
  }

  (void)isf::cli::write_report_file(ready_file, report);

  if (!reconcile_text.empty()) {
    auto grant_id = isf::GrantId::parse(reconcile_text);
    if (!grant_id.ok()) {
      std::fprintf(stderr, "isfsited: --reconcile is not a valid grant identity\n");
      return 2;
    }
    isf::GrantOperation op;
    op.grant = grant_id.value();
    op.actor = site_id;
    op.actor_incarnation = incarnation;
    op.epoch = epoch;
    op.now_ms = isf::now_ms();
    op.reason = "operator reconciliation by site agent";
    isf::GrantState target = isf::GrantState::Retired;
    const std::string target_text = args.value_or("reconcile-target", "retired");
    if (!isf::grant_state_from_name(target_text == "active" ? "ACTIVE" : "RETIRED", target)) {
      std::fprintf(stderr, "isfsited: unknown reconciliation target\n");
      return 2;
    }
    auto reconciled =
        client.value().reconcile_grant(op, target, isf::PrincipalId::from_seed(isf::fnv1a64(site_name), 1));
    if (!reconciled.ok()) {
      std::fprintf(stderr, "isfsited: reconciliation refused: %s\n",
                   reconciled.outcome().to_string().c_str());
      (void)isf::cli::write_report_file(result_file,
                                        {{"error", reconciled.outcome().to_string()}});
      return 6;
    }
    auto grant = isf::extract_grant(reconciled.value());
    if (grant.ok()) {
      report.emplace_back("grant_id", grant.value().id.to_string());
      report.emplace_back("grant_state", isf::grant_state_name(grant.value().state));
    }
    (void)isf::cli::write_report_file(result_file, report);
    if (run_ms == 0) {
      return 0;
    }
  }

  if (!path_text.empty() && reserve > 0) {
    auto path_id = isf::PathId::parse(path_text);
    if (!path_id.ok()) {
      std::fprintf(stderr, "isfsited: --path is not a valid identity\n");
      return 2;
    }
    isf::GrantClass klass = isf::GrantClass::General;
    if (args.value_or("grant-class", "general") == "protected") {
      klass = isf::GrantClass::Protected;
    }
    isf::GrantProposal proposal;
    proposal.request = isf::RequestId::random();
    proposal.holder = site_id;
    proposal.holder_incarnation = incarnation;
    proposal.holder_generation = site.value().generation;
    proposal.path = path_id.value();
    proposal.amount = reserve;
    proposal.grant_class = klass;
    proposal.duration_ms = duration_ms;
    proposal.now_ms = isf::now_ms();
    proposal.reason = "site agent request for " + site_name;

    auto proposed = client.value().propose_grant(proposal);
    if (!proposed.ok()) {
      std::fprintf(stderr, "isfsited: grant proposal refused: %s\n",
                   proposed.outcome().to_string().c_str());
      report.emplace_back("error", proposed.outcome().to_string());
      (void)isf::cli::write_report_file(result_file, report);
      return 5;
    }
    auto grant = isf::extract_grant(proposed.value());
    if (!grant.ok()) {
      std::fprintf(stderr, "isfsited: proposal reply did not carry a grant\n");
      return 5;
    }
    report.emplace_back("grant_id", grant.value().id.to_string());
    report.emplace_back("lease", grant.value().binding.lease.to_string());
    report.emplace_back("arbitration", grant.value().arbitration.to_string());
    report.emplace_back("grant_state", isf::grant_state_name(grant.value().state));

    isf::GrantOperation op;
    op.grant = grant.value().id;
    op.actor = site_id;
    op.actor_incarnation = incarnation;
    op.actor_generation = site.value().generation;
    op.epoch = epoch;
    op.lease = grant.value().binding.lease;
    op.now_ms = isf::now_ms();

    auto evaluated = client.value().evaluate_grant(op);
    if (!evaluated.ok()) {
      std::fprintf(stderr, "isfsited: grant evaluation failed: %s\n",
                   evaluated.outcome().to_string().c_str());
      report.emplace_back("error", evaluated.outcome().to_string());
      (void)isf::cli::write_report_file(result_file, report);
      return 5;
    }
    auto evaluated_grant = isf::extract_grant(evaluated.value());
    const std::string evaluated_state =
        evaluated_grant.ok() ? isf::grant_state_name(evaluated_grant.value().state) : "UNKNOWN";
    report.emplace_back("evaluated_state", evaluated_state);
    if (evaluated_state != "ELIGIBLE") {
      (void)isf::cli::write_report_file(result_file, report);
      return 0;
    }

    auto reserved = client.value().reserve_grant(op);
    if (!reserved.ok()) {
      std::fprintf(stderr, "isfsited: reservation refused: %s\n",
                   reserved.outcome().to_string().c_str());
      report.emplace_back("error", reserved.outcome().to_string());
      (void)isf::cli::write_report_file(result_file, report);
      return 5;
    }
    if (fault_stage == "reserved") {
      (void)isf::cli::write_report_file(result_file, report);
      std::fprintf(stderr, "isfsited: fault injection after reservation\n");
      std::fflush(stderr);
      std::_Exit(EXIT_FAILURE);
    }

    auto activated = client.value().activate_grant(op);
    if (!activated.ok()) {
      std::fprintf(stderr, "isfsited: activation refused: %s\n",
                   activated.outcome().to_string().c_str());
      report.emplace_back("error", activated.outcome().to_string());
      (void)isf::cli::write_report_file(result_file, report);
      return 5;
    }
    auto active_grant = isf::extract_grant(activated.value());
    if (active_grant.ok()) {
      report.emplace_back("grant_state", isf::grant_state_name(active_grant.value().state));
    }
    if (fault_stage == "activated") {
      (void)isf::cli::write_report_file(result_file, report);
      std::fprintf(stderr, "isfsited: fault injection after activation\n");
      std::fflush(stderr);
      std::_Exit(EXIT_FAILURE);
    }

    // Acknowledgement is a claim by this agent that it received the grant. It
    // is recorded, and it deliberately does not verify connectivity.
    isf::GrantAcknowledgement ack;
    ack.grant = grant.value().id;
    ack.actor = site_id;
    ack.actor_incarnation = incarnation;
    ack.epoch = epoch;
    ack.now_ms = isf::now_ms();
    auto acknowledged = client.value().acknowledge_grant(ack);
    report.emplace_back("acknowledged", acknowledged.ok() ? "1" : "0");
  }

  (void)isf::cli::write_report_file(result_file, report);

  if (register_only || (run_ms == 0 && heartbeat_ms == 0)) {
    return 0;
  }

#if defined(_WIN32)
  (void)SetConsoleCtrlHandler(console_handler, TRUE);
#endif
  const std::uint64_t start_ms = isf::monotonic_ms();
  std::uint64_t last_heartbeat = 0;
  while (!g_stop_requested.load()) {
    const std::uint64_t elapsed = isf::monotonic_ms() - start_ms;
    if (run_ms != 0 && elapsed >= run_ms) {
      break;
    }
    if (heartbeat_ms != 0 && elapsed - last_heartbeat >= heartbeat_ms) {
      last_heartbeat = elapsed;
      isf::SiteHeartbeat hb;
      hb.id = site_id;
      hb.incarnation = incarnation;
      hb.generation = site.value().generation;
      hb.epoch = epoch;
      hb.advertised_capacity = descriptor.advertised_capacity;
      hb.now_ms = isf::now_ms();
      auto beat = client.value().heartbeat(hb);
      if (!beat.ok()) {
        std::fprintf(stderr, "isfsited: heartbeat refused: %s\n",
                     beat.outcome().to_string().c_str());
        (void)isf::cli::write_report_file(result_file, report);
        return 7;
      }
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  report.emplace_back("exit", "clean");
  (void)isf::cli::write_report_file(result_file, report);
  return 0;
}
