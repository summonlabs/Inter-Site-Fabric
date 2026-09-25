// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Connectivity probe example.
//
// Starts a daemon and its loopback server inside this process, then drives it
// through the real wire protocol. It shows the full stack: authority, durable
// store, framed transport, and client.

#include "isf/client.hpp"
#include "isf/clock.hpp"
#include "isf/daemon.hpp"
#include "isf/server.hpp"

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <string>
#include <thread>

namespace {

using namespace isf;

int fail(const char* what, const std::string& detail) {
  std::fprintf(stderr, "%s: %s\n", what, detail.c_str());
  return 1;
}

}  // namespace

int main() {
  namespace fs = std::filesystem;
  const fs::path directory = fs::temp_directory_path() / "isf-connectivity-probe";
  std::error_code ec;
  fs::remove_all(directory, ec);
  fs::create_directories(directory, ec);
  const std::string state_path = (directory / "probe.isfstore").string();

  DaemonOptions daemon_options;
  daemon_options.state_path = state_path;
  daemon_options.enable_ticker = false;
  auto daemon = Daemon::start(daemon_options);
  if (!daemon.ok()) {
    return fail("daemon could not start", daemon.outcome().to_string());
  }

  ServerOptions server_options;
  server_options.bind_endpoint = Endpoint{"127.0.0.1", 0};
  FabricServer server(**daemon, server_options);
  const Outcome started = server.start();
  if (started != Status::Ok) {
    return fail("server could not start", started.to_string());
  }

  int exit_code = 0;
  {
    ClientOptions client_options;
    client_options.endpoint = server.local_endpoint();
    client_options.client_kind = "connectivity-probe";
    auto client = FabricClient::connect(client_options);
    if (!client.ok()) {
      exit_code = fail("client could not connect", client.outcome().to_string());
    } else {
      std::printf("connected to %s (protocol %u, epoch %s)\n",
                  server.local_endpoint().to_string().c_str(),
                  static_cast<unsigned>(client.value().hello().protocol_version),
                  client.value().hello().epoch.to_string().c_str());

      SiteDescriptor descriptor;
      descriptor.id = SiteId::from_seed(11, 11);
      descriptor.name = "probe-site";
      auto registered = client.value().register_site(descriptor, Incarnation::from_seed(12, 12),
                                                     client.value().hello().epoch, now_ms());
      if (!registered.ok()) {
        exit_code = fail("site registration failed", registered.outcome().to_string());
      } else {
        auto site = extract_site(registered.value());
        std::printf("registered %s at generation %s\n",
                    site.ok() ? site.value().id.to_string().c_str() : "<missing>",
                    site.ok() ? site.value().generation.to_string().c_str() : "?");
        auto status = client.value().status();
        if (!status.ok()) {
          exit_code = fail("status failed", status.outcome().to_string());
        } else {
          std::printf("sites=%zu paths=%zu grants=%zu digest=%s\n", status.value().sites,
                      status.value().paths, status.value().grants,
                      status.value().state_digest.to_hex().c_str());
        }
      }
      (void)client.value().request_shutdown();
      client.value().close();
    }
  }

  server.stop();
  (**daemon).stop();
  fs::remove_all(directory, ec);
  return exit_code;
}
