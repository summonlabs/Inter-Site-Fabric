// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "isf/server.hpp"

#include "isf/clock.hpp"
#include "isf/log.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <string>
#include <utility>

namespace isf {
namespace {

constexpr const char* kComponent = "server";
constexpr std::size_t kReceiveChunk = 64U << 10;
/// Readiness poll cadence. Bounds how long a worker can take to notice that the
/// server is stopping, independent of the platform's shutdown semantics.
constexpr std::uint64_t kReadPollMs = 50;

}  // namespace

FabricServer::FabricServer(Daemon& daemon, ServerOptions options)
    : daemon_(daemon), options_(std::move(options)) {}

FabricServer::~FabricServer() { stop(); }

Status FabricServer::start() {
  if (running_.load(std::memory_order_relaxed)) {
    return Outcome(Status::Busy, "server is already running");
  }
  if (options_.max_connections == 0) {
    return Outcome(Status::Invalid, "the connection bound must be non-zero");
  }
  if (options_.max_frame_bytes == 0 || options_.max_frame_bytes > kAbsoluteMaxFrameBytes) {
    return Outcome(Status::Invalid, "the frame bound is outside the permitted range");
  }
  Endpoint bind_endpoint = options_.bind_endpoint;
  if (bind_endpoint.host.empty()) {
    bind_endpoint.host = "127.0.0.1";
  }
  auto bound = Listener::bind(bind_endpoint, static_cast<int>(options_.max_connections));
  if (!bound.ok()) {
    return bound.status();
  }
  listener_ = std::move(bound.value());
  stopping_.store(false, std::memory_order_relaxed);
  running_.store(true, std::memory_order_relaxed);
  accept_thread_ = std::thread([this] { accept_loop(); });
  ISF_LOG_INFO(kComponent, "listening on %s", local_endpoint().to_string().c_str());
  return Status::Ok;
}

Endpoint FabricServer::local_endpoint() const {
  Endpoint out = options_.bind_endpoint;
  if (out.host.empty()) {
    out.host = "127.0.0.1";
  }
  out.port = listener_.port();
  return out;
}

void FabricServer::set_shutdown_handler(std::function<void()> handler) {
  std::lock_guard<std::mutex> guard(handler_mutex_);
  shutdown_handler_ = std::move(handler);
}

void FabricServer::stop() {
  if (stopping_.exchange(true, std::memory_order_acq_rel)) {
    return;
  }
  // The accept loop polls with a bounded wait, so joining it is deterministic:
  // it cannot be left blocked inside accept() by a close from this thread.
  if (accept_thread_.joinable()) {
    accept_thread_.join();
  }
  listener_.close();
  ISF_LOG_DEBUG(kComponent, "stop: accept loop joined");
  std::lock_guard<std::mutex> guard(connection_mutex_);
  for (auto& connection : connections_) {
    if (connection->socket.valid()) {
      connection->socket.shutdown_both();
    }
  }
  ISF_LOG_DEBUG(kComponent, "stop: %zu connection(s) released", connections_.size());
  for (auto& connection : connections_) {
    if (connection->worker.joinable()) {
      connection->worker.join();
    }
  }
  ISF_LOG_DEBUG(kComponent, "stop: workers joined");
  connections_.clear();
  running_.store(false, std::memory_order_relaxed);
}

void FabricServer::reap_finished() {
  std::lock_guard<std::mutex> guard(connection_mutex_);
  for (auto it = connections_.begin(); it != connections_.end();) {
    Connection& connection = **it;
    if (connection.done.load(std::memory_order_acquire)) {
      if (connection.worker.joinable()) {
        connection.worker.join();
      }
      connections_closed_.fetch_add(1, std::memory_order_relaxed);
      connections_active_.fetch_sub(1, std::memory_order_relaxed);
      it = connections_.erase(it);
    } else {
      ++it;
    }
  }
}

void FabricServer::accept_loop() {
  std::uint64_t consecutive_errors = 0;
  while (!stopping_.load(std::memory_order_relaxed)) {
    Endpoint peer;
    bool timed_out = false;
    auto accepted = listener_.accept_for(peer, 100, timed_out);
    if (timed_out) {
      continue;  // no connection within the poll window; re-check the stop flag
    }
    if (!accepted.ok()) {
      if (stopping_.load(std::memory_order_relaxed)) {
        break;
      }
      ++consecutive_errors;
      if (consecutive_errors > 64) {
        ISF_LOG_ERROR(kComponent, "accept failed repeatedly; stopping the accept loop");
        break;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(2));
      continue;
    }
    consecutive_errors = 0;
    reap_finished();

    if (connections_active_.load(std::memory_order_relaxed) >= options_.max_connections) {
      connections_rejected_.fetch_add(1, std::memory_order_relaxed);
      // The peer may not be reading, so the refusal notice is sent under a
      // short timeout rather than the normal send timeout.
      (void)accepted.value().set_timeouts(200, 250);
      Response reply;
      reply.type = MessageType::ErrorReply;
      reply.status = Status::LimitExceeded;
      reply.detail = "connection bound reached";
      const std::vector<Byte> frame = encode_frame(encode_response(reply));
      std::size_t written = 0;
      (void)accepted.value().send_all(ByteSpan(frame.data(), frame.size()), written);
      accepted.value().close();
      continue;
    }

    auto connection = std::make_unique<Connection>();
    connection->socket = std::move(accepted.value());
    connection->peer = peer;
    connection->index = next_index_++;
    (void)connection->socket.set_timeouts(options_.io_timeout_ms, options_.send_timeout_ms);
    if (options_.tcp_nodelay) {
      (void)connection->socket.set_nodelay(true);
    }
    Connection* raw = connection.get();
    // The worker is started before the connection becomes reachable from the
    // registry, so a concurrent stop() can never observe a joinable-but-unset
    // thread object.
    raw->worker = std::thread([this, raw] { serve(*raw); });
    {
      std::lock_guard<std::mutex> guard(connection_mutex_);
      connections_.push_back(std::move(connection));
    }
    connections_accepted_.fetch_add(1, std::memory_order_relaxed);
    connections_active_.fetch_add(1, std::memory_order_relaxed);
    if (options_.log_connections) {
      ISF_LOG_DEBUG(kComponent, "accepted connection %llu from %s",
                    static_cast<unsigned long long>(raw->index), peer.to_string().c_str());
    }
  }
}

Status FabricServer::send_response(Connection& connection, const Response& response) {
  const std::vector<Byte> body = encode_response(response);
  if (body.size() > options_.max_frame_bytes) {
    Response fallback;
    fallback.type = MessageType::ErrorReply;
    fallback.session_seq = response.session_seq;
    fallback.id = response.id;
    fallback.status = Status::LimitExceeded;
    fallback.detail = "reply exceeds the negotiated frame bound";
    const std::vector<Byte> fallback_body = encode_response(fallback);
    const std::vector<Byte> frame = encode_frame(ByteSpan(fallback_body.data(), fallback_body.size()));
    std::size_t written = 0;
    if (connection.socket.send_all(ByteSpan(frame.data(), frame.size()), written) != IoStatus::Ok) {
      return Status::Unavailable;
    }
    bytes_sent_.fetch_add(written, std::memory_order_relaxed);
    return Status::LimitExceeded;
  }
  const std::vector<Byte> frame = encode_frame(ByteSpan(body.data(), body.size()));
  std::size_t written = 0;
  if (connection.socket.send_all(ByteSpan(frame.data(), frame.size()), written) != IoStatus::Ok) {
    return Status::Unavailable;
  }
  bytes_sent_.fetch_add(written, std::memory_order_relaxed);
  responses_sent_.fetch_add(1, std::memory_order_relaxed);
  return Status::Ok;
}

void FabricServer::serve(Connection& connection) {
  struct DoneGuard {
    std::atomic<bool>* flag;
    ~DoneGuard() { flag->store(true, std::memory_order_release); }
  } done_guard{&connection.done};

  FrameDecoder decoder(options_.max_frame_bytes);
  std::array<Byte, kReceiveChunk> buffer{};
  std::uint64_t last_session_sequence = 0;
  std::uint64_t last_activity_ms = monotonic_ms();
  bool handshake_complete = false;
  bool closing = false;

  // Receive only when the socket is known to be readable, re-checking the stop
  // flag on every poll. A reader therefore never depends on another thread's
  // shutdown() to abort a blocked receive, which makes server shutdown
  // deterministic rather than platform dependent.
  const auto receive_ready_bytes = [&]() -> IoStatus {
    std::size_t received = 0;
    const IoStatus status = connection.socket.recv_some(buffer.data(), buffer.size(), received);
    if (status != IoStatus::Ok) {
      return status;
    }
    bytes_received_.fetch_add(received, std::memory_order_relaxed);
    if (decoder.push(ByteSpan(buffer.data(), received)) != Status::Ok) {
      frames_rejected_.fetch_add(1, std::memory_order_relaxed);
      return IoStatus::Error;
    }
    last_activity_ms = monotonic_ms();
    return IoStatus::Ok;
  };

  const auto reject = [&](Status status, const std::string& detail) {
    Response reply;
    reply.type = MessageType::ErrorReply;
    reply.status = status;
    reply.detail = detail;
    (void)send_response(connection, reply);
    closing = true;
  };

  while (!closing && !stopping_.load(std::memory_order_relaxed)) {
    auto frame = decoder.next();
    if (!frame.ok()) {
      if (frame.status() != Status::NotFound) {
        frames_rejected_.fetch_add(1, std::memory_order_relaxed);
        reject(frame.status(), "frame rejected: " + frame.detail());
        break;
      }
      bool readable = false;
      if (connection.socket.wait_readable(kReadPollMs, readable) != Status::Ok) {
        break;
      }
      if (!readable) {
        if (stopping_.load(std::memory_order_relaxed)) {
          break;
        }
        if (monotonic_ms() - last_activity_ms >= options_.io_timeout_ms) {
          idle_timeouts_.fetch_add(1, std::memory_order_relaxed);
          break;
        }
        continue;
      }
      const IoStatus status = receive_ready_bytes();
      if (status == IoStatus::PeerClosed) {
        break;
      }
      if (status != IoStatus::Ok) {
        break;
      }
      continue;
    }
    frames_decoded_.fetch_add(1, std::memory_order_relaxed);

    if (!handshake_complete) {
      auto hello = decode_hello_request(ByteSpan(frame.value().data(), frame.value().size()));
      if (!hello.ok()) {
        protocol_mismatches_.fetch_add(1, std::memory_order_relaxed);
        reject(Status::Invalid, "first frame must be a well formed hello: " + hello.detail());
        break;
      }
      if (hello.value().protocol_version != kWireProtocolVersion) {
        protocol_mismatches_.fetch_add(1, std::memory_order_relaxed);
        Response reply;
        reply.type = MessageType::ErrorReply;
        reply.status = Status::VersionMismatch;
        reply.detail = "wire protocol version mismatch";
        (void)send_response(connection, reply);
        break;
      }
      if (hello.value().max_frame_bytes < 4096 ||
          hello.value().max_frame_bytes > kAbsoluteMaxFrameBytes) {
        protocol_mismatches_.fetch_add(1, std::memory_order_relaxed);
        reject(Status::Invalid, "negotiated frame bound is outside the permitted range");
        break;
      }
      const std::uint32_t negotiated =
          static_cast<std::uint32_t>(std::min<std::size_t>(options_.max_frame_bytes,
                                                           hello.value().max_frame_bytes));
      const StatusReport report = daemon_.status_report();
      HelloReply reply;
      reply.protocol_version = kWireProtocolVersion;
      reply.session = SessionId::random();
      reply.server_incarnation = report.incarnation;
      reply.epoch = report.epoch;
      reply.max_frame_bytes = negotiated;
      reply.store_fidelity = daemon_.recovery().fidelity;
      reply.store_servable = daemon_.recovery().servable();
      reply.durable_writes = true;
      reply.format_version = daemon_.recovery().format_version;
      Response response;
      response.type = MessageType::HelloAck;
      response.payload = encode_hello_reply(reply);
      if (send_response(connection, response) != Status::Ok) {
        break;
      }
      handshake_complete = true;
      continue;
    }

    auto request = decode_request(ByteSpan(frame.value().data(), frame.value().size()));
    if (!request.ok()) {
      frames_rejected_.fetch_add(1, std::memory_order_relaxed);
      reject(request.status(), "request envelope rejected: " + request.detail());
      break;
    }
    if (request.value().session_seq <= last_session_sequence) {
      duplicate_requests_.fetch_add(1, std::memory_order_relaxed);
      Response reply;
      reply.type = MessageType::ErrorReply;
      reply.session_seq = request.value().session_seq;
      reply.id = request.value().id;
      reply.status = Status::Duplicate;
      reply.detail = "request sequence was already seen on this session";
      (void)send_response(connection, reply);
      continue;
    }
    if (last_session_sequence != 0 && request.value().session_seq > last_session_sequence + 1) {
      stale_requests_.fetch_add(1, std::memory_order_relaxed);
    }
    last_session_sequence = request.value().session_seq;

    const bool shutdown_requested = request.value().type == MessageType::ShutdownRequest;
    Response response = daemon_.handle(request.value());
    requests_handled_.fetch_add(1, std::memory_order_relaxed);
    if (send_response(connection, response) != Status::Ok) {
      break;
    }
    if (shutdown_requested && response.status == Status::Ok) {
      shutdown_requests_.fetch_add(1, std::memory_order_relaxed);
      std::function<void()> handler;
      {
        std::lock_guard<std::mutex> guard(handler_mutex_);
        handler = shutdown_handler_;
      }
      if (handler) {
        handler();
      }
      break;
    }
  }
  connection.socket.shutdown_both();
  connection.socket.close();
}

ServerStats FabricServer::stats() const {
  ServerStats out;
  out.connections_accepted = connections_accepted_.load(std::memory_order_relaxed);
  out.connections_rejected = connections_rejected_.load(std::memory_order_relaxed);
  out.connections_active = connections_active_.load(std::memory_order_relaxed);
  out.connections_closed = connections_closed_.load(std::memory_order_relaxed);
  out.frames_decoded = frames_decoded_.load(std::memory_order_relaxed);
  out.frames_rejected = frames_rejected_.load(std::memory_order_relaxed);
  out.requests_handled = requests_handled_.load(std::memory_order_relaxed);
  out.responses_sent = responses_sent_.load(std::memory_order_relaxed);
  out.duplicate_requests = duplicate_requests_.load(std::memory_order_relaxed);
  out.stale_requests = stale_requests_.load(std::memory_order_relaxed);
  out.protocol_mismatches = protocol_mismatches_.load(std::memory_order_relaxed);
  out.idle_timeouts = idle_timeouts_.load(std::memory_order_relaxed);
  out.bytes_received = bytes_received_.load(std::memory_order_relaxed);
  out.bytes_sent = bytes_sent_.load(std::memory_order_relaxed);
  out.shutdown_requests = shutdown_requests_.load(std::memory_order_relaxed);
  return out;
}

}  // namespace isf