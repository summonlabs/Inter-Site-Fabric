// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// isfd: the inter-site fabric daemon. It owns the authoritative capacity state,
// its durable log, and the loopback TCP endpoint that site agents and operators
// talk to.

#include "cli.hpp"

#include "isf/clock.hpp"
#include "isf/daemon.hpp"
#include "isf/log.hpp"
#include "isf/server.hpp"

#include <cstddef>

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
#else
extern "C" void signal_handler(int) { g_stop_requested.store(true); }
#endif

void install_signal_handlers() {
#if defined(_WIN32)
  (void)SetConsoleCtrlHandler(console_handler, TRUE);
#else
  std::signal(SIGINT, signal_handler);
  std::signal(SIGTERM, signal_handler);
#endif
}

void usage() {
  std::fputs(
      "isfd - inter-site fabric daemon\n"
      "\n"
      "usage: isfd [options]\n"
      "  --state PATH               durable log path (default ./isf-state/daemon.isfstore)\n"
      "  --listen HOST:PORT         bind endpoint, port 0 selects an ephemeral port\n"
      "  --ready-file PATH          write endpoint and incarnation once listening\n"
      "  --log-level LEVEL          error|warn|info|debug|trace\n"
      "  --max-connections N        connection bound (default 64)\n"
      "  --run-ms N                 exit after N milliseconds (0 means run until asked to stop)\n"
      "  --ticker BOOL              run the lease expiry ticker (default true)\n"
      "  --auto-compact BOOL        compact the log at its threshold (default true)\n"
      "  --verify-after-mutation B  verify invariants after each mutation (default true)\n"
      "  --fault-inject STAGE       abort the process at intent-durable|applied|commit-durable\n"
      "  --print-status BOOL        print a status line once listening (default true)\n",
      stdout);
}

}  // namespace

int main(int argc, char** argv) {
  isf::cli::Arguments args(argc, argv);
  if (args.has("help")) {
    usage();
    return 0;
  }
  isf::LogLevel level = isf::LogLevel::Info;
  if (!isf::log_level_from_name(args.value_or("log-level", "info"), level)) {
    std::fprintf(stderr, "isfd: unknown log level '%s'\n", args.value_or("log-level", "").c_str());
    return 2;
  }
  isf::set_log_level(level);

  const std::string state_path = args.value_or("state", "./isf-state/daemon.isfstore");
  const std::string listen = args.value_or("listen", "127.0.0.1:0");
  const std::string ready_file = args.value_or("ready-file", "");
  const std::string fault_stage = args.value_or("fault-inject", "");
  const std::uint64_t run_ms = args.u64_or("run-ms", 0);
  const bool ticker = args.flag_or("ticker", true);
  const bool auto_compact = args.flag_or("auto-compact", true);
  const bool verify_after = args.flag_or("verify-after-mutation", true);
  const bool print_status = args.flag_or("print-status", true);

  if (fault_stage != "" && fault_stage != "intent-durable" && fault_stage != "applied" &&
      fault_stage != "commit-durable") {
    std::fprintf(stderr, "isfd: unknown fault injection stage '%s'\n", fault_stage.c_str());
    return 2;
  }
  const isf::Outcome prepared = isf::cli::ensure_parent_directory(state_path);
  if (prepared != isf::Status::Ok) {
    std::fprintf(stderr, "isfd: %s\n", prepared.to_string().c_str());
    return 3;
  }

  auto endpoint = isf::Endpoint::parse(listen);
  if (!endpoint.ok()) {
    std::fprintf(stderr, "isfd: %s\n", endpoint.detail().c_str());
    return 2;
  }

  isf::DaemonOptions daemon_options;
  daemon_options.state_path = state_path;
  daemon_options.enable_ticker = ticker;
  daemon_options.auto_compact = auto_compact;
  daemon_options.verify_after_mutation = verify_after;
  if (!fault_stage.empty()) {
    daemon_options.commit_stage_hook = [fault_stage](const char* stage) {
      if (fault_stage == stage) {
        // A deliberate process death with no shutdown path: no destructors run,
        // no atexit handlers run, and no stdio buffer is flushed. _Exit is used
        // rather than abort() because a debug CRT turns abort() into a report
        // dialog, which would block instead of killing the process.
        std::fprintf(stderr, "isfd: fault injection at stage %s\n", stage);
        std::fflush(stderr);
        std::_Exit(EXIT_FAILURE);
      }
    };
  }

  auto daemon = isf::Daemon::start(daemon_options);
  if (!daemon.ok()) {
    std::fprintf(stderr, "isfd: %s\n", daemon.outcome().to_string().c_str());
    return 4;
  }

  isf::ServerOptions server_options;
  server_options.bind_endpoint = endpoint.value();
  server_options.max_connections = static_cast<std::size_t>(args.u64_or("max-connections", 64));
  server_options.log_connections = false;

  isf::FabricServer server(**daemon, server_options);
  const isf::Outcome started = server.start();
  if (started != isf::Status::Ok) {
    std::fprintf(stderr, "isfd: %s\n", started.to_string().c_str());
    return 5;
  }
  server.set_shutdown_handler([] { g_stop_requested.store(true); });
  install_signal_handlers();

  const isf::Endpoint bound = server.local_endpoint();
  const isf::StatusReport report = daemon->get()->status_report();

  std::vector<std::pair<std::string, std::string>> entries;
  entries.emplace_back("endpoint", bound.to_string());
  entries.emplace_back("state_path", state_path);
  entries.emplace_back("incarnation", report.incarnation.to_string());
  entries.emplace_back("epoch", report.epoch.to_string());
  entries.emplace_back("policy_generation", report.policy.generation.to_string());
  entries.emplace_back("store_fidelity", isf::recovery_fidelity_name(report.store_fidelity));
  entries.emplace_back("store_records", std::to_string(report.store_records));
  entries.emplace_back("ambiguous_intents", std::to_string(report.ambiguous_intents));
  entries.emplace_back("store_servable", report.store_servable ? "1" : "0");
  const isf::Outcome wrote = isf::cli::write_report_file(ready_file, entries);
  if (wrote != isf::Status::Ok) {
    std::fprintf(stderr, "isfd: %s\n", wrote.to_string().c_str());
    server.stop();
    return 6;
  }

  if (print_status) {
    std::printf("READY endpoint=%s state=%s incarnation=%s epoch=%s store=%s\n",
                bound.to_string().c_str(), state_path.c_str(),
                report.incarnation.to_string().c_str(), report.epoch.to_string().c_str(),
                isf::recovery_fidelity_name(report.store_fidelity));
    std::fflush(stdout);
  }

  const std::uint64_t start_ms = isf::monotonic_ms();
  while (!g_stop_requested.load()) {
    if (run_ms != 0 && isf::monotonic_ms() - start_ms >= run_ms) {
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }

  server.stop();
  ISF_LOG_DEBUG("isfd", "server stopped");
  (**daemon).stop();
  ISF_LOG_DEBUG("isfd", "daemon stopped");
  if (print_status) {
    std::printf("STOPPED\n");
    std::fflush(stdout);
  }
  return 0;
}
