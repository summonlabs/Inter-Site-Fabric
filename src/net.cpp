// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "isf/net.hpp"

#include <atomic>
#include <cstring>
#include <mutex>
#include <string>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <cerrno>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#endif

namespace isf {
namespace {

std::once_flag g_wsa_once;
std::atomic<bool> g_transport_ok{false};

#if !defined(_WIN32)
[[nodiscard]] int last_socket_error() { return errno; }
#else
[[nodiscard]] int last_socket_error() { return WSAGetLastError(); }
#endif

[[nodiscard]] IoStatus classify_error(int code) {
#if defined(_WIN32)
  switch (code) {
    case WSAETIMEDOUT:
      return IoStatus::TimedOut;
    case WSAEINTR:
      return IoStatus::Interrupted;
    case WSAECONNREFUSED:
      return IoStatus::Refused;
    case WSAECONNRESET:
    case WSAENOTCONN:
    case WSAESHUTDOWN:
      return IoStatus::PeerClosed;
    default:
      return IoStatus::Error;
  }
#else
  switch (code) {
    case ETIMEDOUT:
      return IoStatus::TimedOut;
    case EINTR:
      return IoStatus::Interrupted;
    case ECONNREFUSED:
      return IoStatus::Refused;
    case ECONNRESET:
    case ENOTCONN:
    case EPIPE:
      return IoStatus::PeerClosed;
    default:
      return IoStatus::Error;
  }
#endif
}

void init_transport() {
#if defined(_WIN32)
  WSADATA data{};
  const int result = WSAStartup(MAKEWORD(2, 2), &data);
  g_transport_ok.store(result == 0, std::memory_order_relaxed);
#else
  g_transport_ok.store(true, std::memory_order_relaxed);
#endif
}

[[nodiscard]] Status resolve_ipv4(const std::string& host, std::uint16_t port, sockaddr_in& out) {
  std::memset(&out, 0, sizeof(out));
  out.sin_family = AF_INET;
  out.sin_port = htons(port);
  const std::string target = host.empty() ? std::string("127.0.0.1") : host;
  if (inet_pton(AF_INET, target.c_str(), &out.sin_addr) == 1) {
    return Status::Ok;
  }
  addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  addrinfo* result = nullptr;
  const int rc = getaddrinfo(target.c_str(), nullptr, &hints, &result);
  if (rc != 0 || result == nullptr) {
    return Outcome(Status::Invalid, "host could not be resolved to an IPv4 address");
  }
  auto* address = reinterpret_cast<sockaddr_in*>(result->ai_addr);
  out.sin_addr = address->sin_addr;
  freeaddrinfo(result);
  return Status::Ok;
}

}  // namespace

const char* io_status_name(IoStatus s) noexcept {
  switch (s) {
    case IoStatus::Ok:
      return "OK";
    case IoStatus::PeerClosed:
      return "PEER_CLOSED";
    case IoStatus::TimedOut:
      return "TIMED_OUT";
    case IoStatus::Interrupted:
      return "INTERRUPTED";
    case IoStatus::Refused:
      return "REFUSED";
    case IoStatus::Error:
      return "ERROR";
  }
  return "INVALID";
}

std::string Endpoint::to_string() const {
  if (host.find(':') != std::string::npos) {
    return "[" + host + "]:" + std::to_string(port);
  }
  return host + ":" + std::to_string(port);
}

Expected<Endpoint> Endpoint::parse(std::string_view text) {
  if (text.empty()) {
    return Outcome(Status::Invalid, "endpoint text is empty");
  }
  std::string_view body = text;
  Endpoint out;
  if (body.front() == '[') {
    const std::size_t close = body.find(']');
    if (close == std::string_view::npos) {
      return Outcome(Status::Invalid, "endpoint is missing a closing bracket");
    }
    out.host = std::string(body.substr(1, close - 1));
    body.remove_prefix(close + 1);
    if (body.empty() || body.front() != ':') {
      return Outcome(Status::Invalid, "endpoint is missing a port after the bracket");
    }
    body.remove_prefix(1);
  } else {
    const std::size_t colon = body.rfind(':');
    if (colon == std::string_view::npos) {
      out.host = "127.0.0.1";
    } else {
      out.host = std::string(body.substr(0, colon));
      body.remove_prefix(colon + 1);
    }
  }
  if (body.empty()) {
    return Outcome(Status::Invalid, "endpoint port is empty");
  }
  std::uint32_t port = 0;
  for (const char c : body) {
    if (c < '0' || c > '9') {
      return Outcome(Status::Invalid, "endpoint port must be decimal digits");
    }
    port = port * 10U + static_cast<std::uint32_t>(c - '0');
    if (port > 65535U) {
      return Outcome(Status::Invalid, "endpoint port is out of range");
    }
  }
  if (out.host.empty()) {
    out.host = "127.0.0.1";
  }
  out.port = static_cast<std::uint16_t>(port);
  return out;
}

Status ensure_transport_initialized() {
  std::call_once(g_wsa_once, init_transport);
  if (!g_transport_ok.load(std::memory_order_relaxed)) {
    return Outcome(Status::Unavailable, "the platform socket layer could not be initialised");
  }
  return Status::Ok;
}

// ---------------------------------------------------------------------------
// Socket
// ---------------------------------------------------------------------------

Socket::~Socket() { close(); }

Socket::Socket(Socket&& other) noexcept : handle_(other.handle_) { other.handle_ = kInvalidSocket; }

Socket& Socket::operator=(Socket&& other) noexcept {
  if (this != &other) {
    close();
    handle_ = other.handle_;
    other.handle_ = kInvalidSocket;
  }
  return *this;
}

void Socket::close() noexcept {
  if (handle_ != kInvalidSocket) {
#if defined(_WIN32)
    closesocket(static_cast<SOCKET>(handle_));
#else
    ::close(handle_);
#endif
    handle_ = kInvalidSocket;
  }
}

void Socket::shutdown_both() noexcept {
  if (handle_ != kInvalidSocket) {
#if defined(_WIN32)
    ::shutdown(static_cast<SOCKET>(handle_), SD_BOTH);
#else
    ::shutdown(handle_, SHUT_RDWR);
#endif
  }
}

Status Socket::set_timeouts(std::uint64_t recv_ms, std::uint64_t send_ms) {
  if (!valid()) {
    return Outcome(Status::Invalid, "socket is not open");
  }
#if defined(_WIN32)
  const DWORD recv_value = static_cast<DWORD>(recv_ms);
  const DWORD send_value = static_cast<DWORD>(send_ms);
  if (setsockopt(static_cast<SOCKET>(handle_), SOL_SOCKET, SO_RCVTIMEO,
                 reinterpret_cast<const char*>(&recv_value), sizeof(recv_value)) != 0) {
    return Outcome(Status::Unavailable, "could not set the receive timeout");
  }
  if (setsockopt(static_cast<SOCKET>(handle_), SOL_SOCKET, SO_SNDTIMEO,
                 reinterpret_cast<const char*>(&send_value), sizeof(send_value)) != 0) {
    return Outcome(Status::Unavailable, "could not set the send timeout");
  }
#else
  timeval recv_value{};
  recv_value.tv_sec = static_cast<time_t>(recv_ms / 1000ULL);
  recv_value.tv_usec = static_cast<suseconds_t>((recv_ms % 1000ULL) * 1000ULL);
  timeval send_value{};
  send_value.tv_sec = static_cast<time_t>(send_ms / 1000ULL);
  send_value.tv_usec = static_cast<suseconds_t>((send_ms % 1000ULL) * 1000ULL);
  if (setsockopt(handle_, SOL_SOCKET, SO_RCVTIMEO, &recv_value, sizeof(recv_value)) != 0) {
    return Outcome(Status::Unavailable, "could not set the receive timeout");
  }
  if (setsockopt(handle_, SOL_SOCKET, SO_SNDTIMEO, &send_value, sizeof(send_value)) != 0) {
    return Outcome(Status::Unavailable, "could not set the send timeout");
  }
#endif
  return Status::Ok;
}

Status Socket::set_nodelay(bool enabled) {
  if (!valid()) {
    return Outcome(Status::Invalid, "socket is not open");
  }
  const int value = enabled ? 1 : 0;
#if defined(_WIN32)
  if (setsockopt(static_cast<SOCKET>(handle_), IPPROTO_TCP, TCP_NODELAY,
                 reinterpret_cast<const char*>(&value), sizeof(value)) != 0) {
    return Outcome(Status::Unavailable, "could not set TCP_NODELAY");
  }
#else
  if (setsockopt(handle_, IPPROTO_TCP, TCP_NODELAY, &value, sizeof(value)) != 0) {
    return Outcome(Status::Unavailable, "could not set TCP_NODELAY");
  }
#endif
  return Status::Ok;
}

Status Socket::set_keepalive(bool enabled) {
  if (!valid()) {
    return Outcome(Status::Invalid, "socket is not open");
  }
  const int value = enabled ? 1 : 0;
#if defined(_WIN32)
  if (setsockopt(static_cast<SOCKET>(handle_), SOL_SOCKET, SO_KEEPALIVE,
                 reinterpret_cast<const char*>(&value), sizeof(value)) != 0) {
    return Outcome(Status::Unavailable, "could not set SO_KEEPALIVE");
  }
#else
  if (setsockopt(handle_, SOL_SOCKET, SO_KEEPALIVE, &value, sizeof(value)) != 0) {
    return Outcome(Status::Unavailable, "could not set SO_KEEPALIVE");
  }
#endif
  return Status::Ok;
}

Status Socket::wait_readable(std::uint64_t timeout_ms, bool& readable) {
  readable = false;
  if (!valid()) {
    return Outcome(Status::Unavailable, "socket is not open");
  }
  const SocketHandle handle = handle_;
  fd_set read_set;
  FD_ZERO(&read_set);
  FD_SET(handle, &read_set);
  timeval timeout{};
  timeout.tv_sec = static_cast<long>(timeout_ms / 1000ULL);
  timeout.tv_usec = static_cast<long>((timeout_ms % 1000ULL) * 1000ULL);
#if defined(_WIN32)
  const int ready = ::select(0, &read_set, nullptr, nullptr, &timeout);
#else
  const int ready = ::select(static_cast<int>(handle) + 1, &read_set, nullptr, nullptr, &timeout);
#endif
  if (ready == 0) {
    return Status::Ok;  // nothing to read yet; readable stays false
  }
  if (ready < 0) {
    return Outcome(Status::Unavailable, "waiting for readability failed");
  }
  readable = true;
  return Status::Ok;
}

IoStatus Socket::send_all(ByteSpan data, std::size_t& bytes_written) {
  bytes_written = 0;
  if (!valid()) {
    return IoStatus::Error;
  }
  while (bytes_written < data.size()) {
    const std::size_t chunk = data.size() - bytes_written;
    const int request = static_cast<int>(chunk > 1U << 20 ? 1U << 20 : chunk);
#if defined(_WIN32)
    const int sent =
        ::send(static_cast<SOCKET>(handle_), reinterpret_cast<const char*>(data.data() + bytes_written),
               request, 0);
#else
    const ssize_t sent = ::send(handle_, data.data() + bytes_written, static_cast<std::size_t>(request),
                                MSG_NOSIGNAL);
#endif
    if (sent < 0) {
      return classify_error(last_socket_error());
    }
    if (sent == 0) {
      return IoStatus::PeerClosed;
    }
    bytes_written += static_cast<std::size_t>(sent);
  }
  return IoStatus::Ok;
}

IoStatus Socket::recv_some(Byte* destination, std::size_t capacity, std::size_t& received) {
  received = 0;
  if (!valid()) {
    return IoStatus::Error;
  }
  const int request = static_cast<int>(capacity > 1U << 20 ? 1U << 20 : capacity);
#if defined(_WIN32)
  const int got =
      ::recv(static_cast<SOCKET>(handle_), reinterpret_cast<char*>(destination), request, 0);
#else
  const ssize_t got = ::recv(handle_, destination, static_cast<std::size_t>(request), 0);
#endif
  if (got < 0) {
    return classify_error(last_socket_error());
  }
  if (got == 0) {
    return IoStatus::PeerClosed;
  }
  received = static_cast<std::size_t>(got);
  return IoStatus::Ok;
}

Endpoint Socket::peer() const {
  Endpoint out;
  if (!valid()) {
    return out;
  }
  sockaddr_in address{};
#if defined(_WIN32)
  int length = static_cast<int>(sizeof(address));
#else
  socklen_t length = sizeof(address);
#endif
  if (getpeername(handle_, reinterpret_cast<sockaddr*>(&address), &length) != 0) {
    return out;
  }
  char buffer[INET_ADDRSTRLEN]{};
  if (inet_ntop(AF_INET, &address.sin_addr, buffer, sizeof(buffer)) == nullptr) {
    return out;
  }
  out.host = buffer;
  out.port = ntohs(address.sin_port);
  return out;
}

// ---------------------------------------------------------------------------
// Listener
// ---------------------------------------------------------------------------

Listener::~Listener() { close(); }

Listener::Listener(Listener&& other) noexcept : handle_(other.handle_), port_(other.port_) {
  other.handle_ = kInvalidSocket;
  other.port_ = 0;
}

Listener& Listener::operator=(Listener&& other) noexcept {
  if (this != &other) {
    close();
    handle_ = other.handle_;
    port_ = other.port_;
    other.handle_ = kInvalidSocket;
    other.port_ = 0;
  }
  return *this;
}

void Listener::close() noexcept {
  if (handle_ != kInvalidSocket) {
#if defined(_WIN32)
    closesocket(static_cast<SOCKET>(handle_));
#else
    ::close(handle_);
#endif
    handle_ = kInvalidSocket;
  }
}

Expected<Listener> Listener::bind(const Endpoint& endpoint, int backlog) {
  const Status ready = ensure_transport_initialized();
  if (ready != Status::Ok) {
    return ready;
  }
  sockaddr_in address{};
  const Status resolved = resolve_ipv4(endpoint.host, endpoint.port, address);
  if (resolved != Status::Ok) {
    return resolved;
  }
#if defined(_WIN32)
  SOCKET handle = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (handle == INVALID_SOCKET) {
    return Outcome(Status::Unavailable, "listening socket could not be created");
  }
#else
  const int handle = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (handle < 0) {
    return Outcome(Status::Unavailable, "listening socket could not be created");
  }
#endif
  const int reuse = 1;
#if defined(_WIN32)
  (void)setsockopt(handle, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse),
                   sizeof(reuse));
#else
  (void)setsockopt(handle, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
#endif
  if (::bind(handle, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
#if defined(_WIN32)
    closesocket(handle);
#else
    ::close(handle);
#endif
    return Outcome(Status::Unavailable, "listener could not bind " + endpoint.to_string());
  }
  if (::listen(handle, backlog) != 0) {
#if defined(_WIN32)
    closesocket(handle);
#else
    ::close(handle);
#endif
    return Outcome(Status::Unavailable, "listener could not start listening");
  }
  sockaddr_in bound{};
#if defined(_WIN32)
  int length = static_cast<int>(sizeof(bound));
#else
  socklen_t length = sizeof(bound);
#endif
  Listener out;
  out.handle_ = static_cast<SocketHandle>(handle);
  if (getsockname(handle, reinterpret_cast<sockaddr*>(&bound), &length) == 0) {
    out.port_ = ntohs(bound.sin_port);
  } else {
    out.port_ = endpoint.port;
  }
  return out;
}

Expected<Socket> Listener::accept_for(Endpoint& peer, std::uint64_t timeout_ms,
                                      bool& timed_out) {
  timed_out = false;
  if (!valid()) {
    return Outcome(Status::Unavailable, "listener is not open");
  }
  const SocketHandle handle = handle_;
  fd_set read_set;
  FD_ZERO(&read_set);
  FD_SET(handle, &read_set);
  timeval timeout{};
  timeout.tv_sec = static_cast<long>(timeout_ms / 1000ULL);
  timeout.tv_usec = static_cast<long>((timeout_ms % 1000ULL) * 1000ULL);
#if defined(_WIN32)
  const int ready = ::select(0, &read_set, nullptr, nullptr, &timeout);
#else
  const int ready = ::select(static_cast<int>(handle) + 1, &read_set, nullptr, nullptr, &timeout);
#endif
  if (ready == 0) {
    timed_out = true;
    return Outcome(Status::Unavailable, "no connection arrived within the bound");
  }
  if (ready < 0) {
    return Outcome(Status::Unavailable, "waiting for a connection failed");
  }
  if (handle != handle_) {
    return Outcome(Status::Unavailable, "listener was closed while waiting");
  }
  return accept(peer);
}

Expected<Socket> Listener::accept(Endpoint& peer) {
  if (!valid()) {
    return Outcome(Status::Unavailable, "listener is not open");
  }
  sockaddr_in address{};
#if defined(_WIN32)
  int length = static_cast<int>(sizeof(address));
  const SOCKET accepted = ::accept(static_cast<SOCKET>(handle_),
                                   reinterpret_cast<sockaddr*>(&address), &length);
  if (accepted == INVALID_SOCKET) {
    return Outcome(Status::Unavailable, "accept failed");
  }
#else
  socklen_t length = sizeof(address);
  const int accepted = ::accept(handle_, reinterpret_cast<sockaddr*>(&address), &length);
  if (accepted < 0) {
    return Outcome(Status::Unavailable, "accept failed");
  }
#endif
  char buffer[INET_ADDRSTRLEN]{};
  if (inet_ntop(AF_INET, &address.sin_addr, buffer, sizeof(buffer)) != nullptr) {
    peer.host = buffer;
  }
  peer.port = ntohs(address.sin_port);
  return Socket(static_cast<SocketHandle>(accepted));
}

// ---------------------------------------------------------------------------
// Connect
// ---------------------------------------------------------------------------

Status connect(const Endpoint& endpoint, std::uint64_t timeout_ms, Socket& out) {
  const Status ready = ensure_transport_initialized();
  if (ready != Status::Ok) {
    return ready;
  }
  sockaddr_in address{};
  const Status resolved = resolve_ipv4(endpoint.host, endpoint.port, address);
  if (resolved != Status::Ok) {
    return resolved;
  }
#if defined(_WIN32)
  SOCKET handle = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (handle == INVALID_SOCKET) {
    return Outcome(Status::Unavailable, "client socket could not be created");
  }
#else
  const int handle = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (handle < 0) {
    return Outcome(Status::Unavailable, "client socket could not be created");
  }
#endif
  // Bounded connect: the socket is put in non-blocking mode for the connect and
  // then returned to blocking mode with the operator supplied timeout.
#if defined(_WIN32)
  u_long non_blocking = 1;
  ioctlsocket(handle, FIONBIO, &non_blocking);
#else
  const int original_flags = fcntl(handle, F_GETFL, 0);
  (void)fcntl(handle, F_SETFL, original_flags | O_NONBLOCK);
#endif
  int rc = ::connect(handle, reinterpret_cast<sockaddr*>(&address), sizeof(address));
  bool connected = rc == 0;
  if (!connected) {
    const int code = last_socket_error();
#if defined(_WIN32)
    const bool in_progress = (code == WSAEWOULDBLOCK || code == WSAEINPROGRESS);
#else
    const bool in_progress = (code == EINPROGRESS || code == EWOULDBLOCK);
#endif
    if (!in_progress) {
#if defined(_WIN32)
      closesocket(handle);
#else
      ::close(handle);
#endif
      return Outcome(Status::Unavailable, "connect to " + endpoint.to_string() + " failed");
    }
    fd_set write_set;
    FD_ZERO(&write_set);
    FD_SET(handle, &write_set);
    timeval timeout{};
    timeout.tv_sec = static_cast<long>(timeout_ms / 1000ULL);
    timeout.tv_usec = static_cast<long>((timeout_ms % 1000ULL) * 1000ULL);
#if defined(_WIN32)
    rc = ::select(0, nullptr, &write_set, nullptr, &timeout);
#else
    rc = ::select(handle + 1, nullptr, &write_set, nullptr, &timeout);
#endif
    if (rc <= 0) {
#if defined(_WIN32)
      closesocket(handle);
#else
      ::close(handle);
#endif
      return Outcome(rc == 0 ? Status::Unavailable : Status::Busy,
                     "connect to " + endpoint.to_string() + " timed out");
    }
    int socket_error = 0;
#if defined(_WIN32)
    int length = static_cast<int>(sizeof(socket_error));
#else
    socklen_t length = sizeof(socket_error);
#endif
    if (getsockopt(handle, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&socket_error), &length) != 0 ||
        socket_error != 0) {
#if defined(_WIN32)
      closesocket(handle);
#else
      ::close(handle);
#endif
      return Outcome(Status::Unavailable, "connect to " + endpoint.to_string() + " failed");
    }
  }
#if defined(_WIN32)
  non_blocking = 0;
  ioctlsocket(handle, FIONBIO, &non_blocking);
#else
  (void)fcntl(handle, F_SETFL, original_flags);
#endif
  out = Socket(static_cast<SocketHandle>(handle));
  return Status::Ok;
}

}  // namespace isf
