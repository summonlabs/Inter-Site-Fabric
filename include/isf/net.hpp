// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// A thin, bounded TCP transport. The runtime ships with loopback TCP only; it
// has no RDMA, InfiniBand, NVLink, or switch/ASIC integration, and it makes no
// claim about physical network behaviour. Everything here is real sockets.

#ifndef ISF_NET_HPP
#define ISF_NET_HPP

#include "isf/digest.hpp"
#include "isf/status.hpp"

#include <cstdint>
#include <string>
#include <string_view>

namespace isf {

/// A host and port. Parsing accepts "host:port", "[v6]:port", and a bare port.
struct Endpoint {
  std::string host{"127.0.0.1"};
  std::uint16_t port{0};

  [[nodiscard]] std::string to_string() const;
  [[nodiscard]] static Expected<Endpoint> parse(std::string_view text);
  friend bool operator==(const Endpoint&, const Endpoint&) = default;
};

#if defined(_WIN32)
using SocketHandle = std::uintptr_t;
inline constexpr SocketHandle kInvalidSocket = static_cast<SocketHandle>(~0ULL);
#else
using SocketHandle = int;
inline constexpr SocketHandle kInvalidSocket = -1;
#endif

/// Result of one socket operation, kept distinct from authority statuses.
enum class IoStatus : std::uint8_t {
  Ok = 0,
  PeerClosed,
  TimedOut,
  Interrupted,
  Refused,
  Error,
};

[[nodiscard]] const char* io_status_name(IoStatus s) noexcept;

/// Owning socket handle.
class Socket {
 public:
  Socket() = default;
  explicit Socket(SocketHandle handle) : handle_(handle) {}
  ~Socket();
  Socket(Socket&& other) noexcept;
  Socket& operator=(Socket&& other) noexcept;
  Socket(const Socket&) = delete;
  Socket& operator=(const Socket&) = delete;

  [[nodiscard]] bool valid() const noexcept { return handle_ != kInvalidSocket; }
  [[nodiscard]] SocketHandle handle() const noexcept { return handle_; }

  void close() noexcept;
  void shutdown_both() noexcept;

  [[nodiscard]] Status set_timeouts(std::uint64_t recv_ms, std::uint64_t send_ms);
  [[nodiscard]] Status set_nodelay(bool enabled);
  [[nodiscard]] Status set_keepalive(bool enabled);

  /// Wait until the socket is readable or the bound expires. `readable` is set
  /// when at least one byte can be received without blocking. This exists so
  /// that a reader can re-check a stop flag on a bounded cadence instead of
  /// depending on another thread's shutdown() to abort a blocked receive.
  [[nodiscard]] Status wait_readable(std::uint64_t timeout_ms, bool& readable);

  /// Send the whole buffer. On failure, bytes_written holds the partial count.
  [[nodiscard]] IoStatus send_all(ByteSpan data, std::size_t& bytes_written);
  [[nodiscard]] IoStatus recv_some(Byte* destination, std::size_t capacity, std::size_t& received);
  [[nodiscard]] Endpoint peer() const;

 private:
  SocketHandle handle_{kInvalidSocket};
};

/// A bound listening socket.
class Listener {
 public:
  Listener() = default;
  ~Listener();
  Listener(Listener&& other) noexcept;
  Listener& operator=(Listener&& other) noexcept;
  Listener(const Listener&) = delete;
  Listener& operator=(const Listener&) = delete;

  /// Bind and listen. Port 0 selects an ephemeral port.
  [[nodiscard]] static Expected<Listener> bind(const Endpoint& endpoint, int backlog);
  [[nodiscard]] Expected<Socket> accept(Endpoint& peer);

  /// Wait up to timeout_ms for an incoming connection and then accept it.
  /// On expiry, timed_out is set and the result is Status::Unavailable. This
  /// exists because closing a listening socket from another thread does not
  /// reliably wake a blocked accept() on every platform; a bounded wait makes
  /// shutdown deterministic instead of relying on that behaviour.
  [[nodiscard]] Expected<Socket> accept_for(Endpoint& peer, std::uint64_t timeout_ms,
                                            bool& timed_out);
  void close() noexcept;
  [[nodiscard]] bool valid() const noexcept { return handle_ != kInvalidSocket; }
  [[nodiscard]] std::uint16_t port() const noexcept { return port_; }
  [[nodiscard]] SocketHandle handle() const noexcept { return handle_; }

 private:
  SocketHandle handle_{kInvalidSocket};
  std::uint16_t port_{0};
};

/// Connect to an endpoint with a bounded timeout.
[[nodiscard]] Status connect(const Endpoint& endpoint, std::uint64_t timeout_ms, Socket& out);

/// One-time transport initialisation. Safe to call repeatedly.
[[nodiscard]] Status ensure_transport_initialized();

}  // namespace isf

#endif  // ISF_NET_HPP
