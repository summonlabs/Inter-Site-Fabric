// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// The fabric server: a bounded, threaded loopback TCP front end for a Daemon.
//
// Ownership and shutdown
// ----------------------
// One accept thread owns the listener. Each accepted connection gets one worker
// thread that owns that connection's socket and its frame decoder. Connection
// threads never acquire the connection registry mutex, which is why stop() may
// hold it while joining them. stop() sets the stopping flag, closes the
// listener, joins the accept thread, then shuts down every live socket so that
// blocked receives return, and only then joins the workers.

#ifndef ISF_SERVER_HPP
#define ISF_SERVER_HPP

#include "isf/daemon.hpp"
#include "isf/net.hpp"
#include "isf/protocol.hpp"

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace isf {

struct ServerOptions {
  Endpoint bind_endpoint{};
  std::size_t max_connections{64};
  std::size_t max_frame_bytes{kDefaultMaxFrameBytes};
  std::uint64_t io_timeout_ms{30000};
  std::uint64_t send_timeout_ms{15000};
  bool tcp_nodelay{true};
  bool log_connections{false};
};

struct ServerStats {
  std::uint64_t connections_accepted{0};
  std::uint64_t connections_rejected{0};
  std::uint64_t connections_active{0};
  std::uint64_t connections_closed{0};
  std::uint64_t frames_decoded{0};
  std::uint64_t frames_rejected{0};
  std::uint64_t requests_handled{0};
  std::uint64_t responses_sent{0};
  std::uint64_t duplicate_requests{0};
  std::uint64_t stale_requests{0};
  std::uint64_t protocol_mismatches{0};
  std::uint64_t idle_timeouts{0};
  std::uint64_t bytes_received{0};
  std::uint64_t bytes_sent{0};
  std::uint64_t shutdown_requests{0};
};

class FabricServer {
 public:
  FabricServer(Daemon& daemon, ServerOptions options);
  ~FabricServer();
  FabricServer(const FabricServer&) = delete;
  FabricServer& operator=(const FabricServer&) = delete;

  /// Bind and start accepting. Returns the bound endpoint through local_endpoint().
  [[nodiscard]] Status start();
  void stop();

  [[nodiscard]] Endpoint local_endpoint() const;
  [[nodiscard]] ServerStats stats() const;
  [[nodiscard]] bool running() const noexcept { return running_.load(std::memory_order_relaxed); }

  /// Invoked after a ShutdownRequest has been answered. Must not block.
  void set_shutdown_handler(std::function<void()> handler);

 private:
  struct Connection {
    Socket socket{};
    Endpoint peer{};
    std::thread worker{};
    std::atomic<bool> done{false};
    std::uint64_t index{0};
  };

  void accept_loop();
  void serve(Connection& connection);
  void reap_finished();
  [[nodiscard]] Status send_response(Connection& connection, const Response& response);

  Daemon& daemon_;
  ServerOptions options_{};
  Listener listener_{};
  std::atomic<bool> stopping_{false};
  std::atomic<bool> running_{false};
  std::thread accept_thread_{};
  mutable std::mutex connection_mutex_{};
  std::vector<std::unique_ptr<Connection>> connections_{};
  std::uint64_t next_index_{0};
  std::mutex handler_mutex_{};
  std::function<void()> shutdown_handler_{};

  std::atomic<std::uint64_t> connections_accepted_{0};
  std::atomic<std::uint64_t> connections_rejected_{0};
  std::atomic<std::uint64_t> connections_active_{0};
  std::atomic<std::uint64_t> connections_closed_{0};
  std::atomic<std::uint64_t> frames_decoded_{0};
  std::atomic<std::uint64_t> frames_rejected_{0};
  std::atomic<std::uint64_t> requests_handled_{0};
  std::atomic<std::uint64_t> responses_sent_{0};
  std::atomic<std::uint64_t> duplicate_requests_{0};
  std::atomic<std::uint64_t> stale_requests_{0};
  std::atomic<std::uint64_t> protocol_mismatches_{0};
  std::atomic<std::uint64_t> idle_timeouts_{0};
  std::atomic<std::uint64_t> bytes_received_{0};
  std::atomic<std::uint64_t> bytes_sent_{0};
  std::atomic<std::uint64_t> shutdown_requests_{0};
};

}  // namespace isf

#endif  // ISF_SERVER_HPP
