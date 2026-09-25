// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "isf/client.hpp"

#include "isf/clock.hpp"

#include <array>
#include <string>
#include <utility>

namespace isf {
namespace {

constexpr std::size_t kReceiveChunk = 64U << 10;

[[nodiscard]] Expected<StateChange> find_change(const MutationReport& report, ObjectKind kind) {
  for (const auto& change : report.changes) {
    if (change.kind == kind) {
      return change;
    }
  }
  return Outcome(Status::NotFound, "reply did not carry the expected record");
}

}  // namespace

FabricClient::~FabricClient() { close(); }

void FabricClient::close() {
  socket_.shutdown_both();
  socket_.close();
}

Expected<FabricClient> FabricClient::connect(const ClientOptions& options) {
  const Status ready = ensure_transport_initialized();
  if (ready != Status::Ok) {
    return ready;
  }
  if (options.endpoint.port == 0) {
    return Outcome(Status::Invalid, "client endpoint must carry a port");
  }
  FabricClient client;
  client.options_ = options;
  client.endpoint_ = options.endpoint;
  Socket socket;
  const Status connected =
      isf::connect(options.endpoint, options.connect_timeout_ms, socket);
  if (connected != Status::Ok) {
    return Outcome(connected, "could not connect to " + options.endpoint.to_string());
  }
  if (socket.set_timeouts(options.io_timeout_ms, options.io_timeout_ms) != Status::Ok) {
    return Outcome(Status::Unavailable, "could not configure socket timeouts");
  }
  (void)socket.set_nodelay(true);
  client.socket_ = std::move(socket);
  client.decoder_ = FrameDecoder(options.max_frame_bytes);

  HelloRequest hello;
  hello.protocol_version = kWireProtocolVersion;
  hello.client_nonce = Id128::random();
  hello.client_kind = options.client_kind;
  hello.max_frame_bytes = static_cast<std::uint32_t>(options.max_frame_bytes);
  const std::vector<Byte> body = encode_hello_request(hello);
  const std::vector<Byte> frame = encode_frame(ByteSpan(body.data(), body.size()));
  std::size_t written = 0;
  if (client.socket_.send_all(ByteSpan(frame.data(), frame.size()), written) != IoStatus::Ok) {
    return Outcome(Status::Unavailable, "hello frame could not be sent");
  }

  // Read the hello reply. A server that refuses the handshake answers with an
  // error frame, which is surfaced verbatim.
  for (;;) {
    auto payload = client.decoder_.next();
    if (!payload.ok()) {
      if (payload.status() != Status::NotFound) {
        return Outcome(payload.status(), "handshake failed: " + payload.detail());
      }
      const IoStatus pumped = client.pump();
      if (pumped != IoStatus::Ok) {
        return Outcome(Status::Unavailable,
                       std::string("handshake failed while reading: ") + io_status_name(pumped));
      }
      continue;
    }
    auto response = decode_response(ByteSpan(payload.value().data(), payload.value().size()));
    if (!response.ok()) {
      return Outcome(response.status(), "handshake reply was malformed");
    }
    if (response.value().type == MessageType::ErrorReply) {
      return Outcome(response.value().status,
                     "server refused the handshake: " + response.value().detail);
    }
    if (response.value().type != MessageType::HelloAck) {
      return Outcome(Status::Invalid, "server did not answer the handshake with a hello reply");
    }
    auto reply = decode_hello_reply(ByteSpan(response.value().payload.data(),
                                             response.value().payload.size()));
    if (!reply.ok()) {
      return Outcome(reply.status(), "hello reply body was malformed");
    }
    if (reply.value().protocol_version != kWireProtocolVersion) {
      return Outcome(Status::VersionMismatch, "server negotiated an unsupported protocol version");
    }
    client.hello_ = reply.value();
    client.decoder_ = FrameDecoder(client.hello_.max_frame_bytes);
    return client;
  }
}

IoStatus FabricClient::pump() {
  std::array<Byte, kReceiveChunk> buffer{};
  std::size_t received = 0;
  const IoStatus status = socket_.recv_some(buffer.data(), buffer.size(), received);
  if (status != IoStatus::Ok) {
    return status;
  }
  const Status pushed = decoder_.push(ByteSpan(buffer.data(), received));
  if (pushed != Status::Ok) {
    return IoStatus::Error;
  }
  return IoStatus::Ok;
}

Expected<Response> FabricClient::round_trip(MessageType type, ByteSpan body) {
  if (!socket_.valid()) {
    return Outcome(Status::Unavailable, "client is not connected");
  }
  Request request;
  request.protocol_version = kWireProtocolVersion;
  request.type = type;
  request.session_seq = ++sequence_;
  request.id = RequestId::random();
  request.payload.assign(body.begin(), body.end());
  const std::vector<Byte> encoded = encode_request(request);
  if (encoded.size() > hello_.max_frame_bytes) {
    return Outcome(Status::LimitExceeded, "request exceeds the negotiated frame bound");
  }
  const std::vector<Byte> frame = encode_frame(ByteSpan(encoded.data(), encoded.size()));
  std::size_t written = 0;
  if (socket_.send_all(ByteSpan(frame.data(), frame.size()), written) != IoStatus::Ok) {
    return Outcome(Status::Unavailable, "request frame could not be sent");
  }
  for (;;) {
    auto payload = decoder_.next();
    if (!payload.ok()) {
      if (payload.status() != Status::NotFound) {
        return Outcome(payload.status(), "reply frame was rejected: " + payload.detail());
      }
      const IoStatus pumped = pump();
      if (pumped == IoStatus::TimedOut) {
        return Outcome(Status::Unavailable, "timed out waiting for a reply");
      }
      if (pumped != IoStatus::Ok) {
        return Outcome(Status::Unavailable,
                       std::string("connection ended while waiting for a reply: ") +
                           io_status_name(pumped));
      }
      continue;
    }
    auto response = decode_response(ByteSpan(payload.value().data(), payload.value().size()));
    if (!response.ok()) {
      return Outcome(response.status(), "reply envelope was malformed");
    }
    if (!(response.value().id == request.id)) {
      return Outcome(Status::Conflicting, "reply identity does not match the outstanding request");
    }
    if (response.value().session_seq != request.session_seq) {
      return Outcome(Status::Conflicting, "reply sequence does not match the outstanding request");
    }
    return response.value();
  }
}

Expected<Response> FabricClient::call(MessageType type, ByteSpan body) {
  return round_trip(type, body);
}

Expected<MutationReport> FabricClient::register_site(const SiteDescriptor& descriptor,
                                                     const Incarnation& incarnation,
                                                     const Epoch& epoch, std::uint64_t now) {
  SiteRegistration registration;
  registration.descriptor = descriptor;
  registration.incarnation = incarnation;
  registration.epoch = epoch;
  registration.now_ms = now;
  const std::vector<Byte> body = encode_site_registration(registration);
  auto response = round_trip(MessageType::SiteRegister, ByteSpan(body.data(), body.size()));
  if (!response.ok()) {
    return response.status();
  }
  if (response.value().status != Status::Ok) {
    return Outcome(response.value().status, response.value().detail);
  }
  auto report = decode_mutation_report(ByteSpan(response.value().payload.data(),
                                                response.value().payload.size()));
  if (!report.ok()) {
    return report.status();
  }
  return report.value();
}

Expected<MutationReport> FabricClient::heartbeat(const SiteHeartbeat& hb) {
  const std::vector<Byte> body = encode_heartbeat(hb);
  auto response = round_trip(MessageType::SiteHeartbeat, ByteSpan(body.data(), body.size()));
  if (!response.ok()) {
    return response.status();
  }
  if (response.value().status != Status::Ok) {
    return Outcome(response.value().status, response.value().detail);
  }
  auto report = decode_mutation_report(ByteSpan(response.value().payload.data(),
                                                response.value().payload.size()));
  if (!report.ok()) {
    return report.status();
  }
  return report.value();
}

Expected<MutationReport> FabricClient::set_site_state(const SiteId& site, SiteState state,
                                                      std::string_view reason, std::uint64_t now) {
  const std::vector<Byte> body = encode_site_state_request(site, state, reason, now);
  auto response = round_trip(MessageType::SiteSetState, ByteSpan(body.data(), body.size()));
  if (!response.ok()) {
    return response.status();
  }
  if (response.value().status != Status::Ok) {
    return Outcome(response.value().status, response.value().detail);
  }
  auto report = decode_mutation_report(ByteSpan(response.value().payload.data(),
                                                response.value().payload.size()));
  if (!report.ok()) {
    return report.status();
  }
  return report.value();
}

Expected<MutationReport> FabricClient::register_path(const PathRegistration& registration) {
  const std::vector<Byte> body = encode_path_registration(registration);
  auto response = round_trip(MessageType::PathRegister, ByteSpan(body.data(), body.size()));
  if (!response.ok()) {
    return response.status();
  }
  if (response.value().status != Status::Ok) {
    return Outcome(response.value().status, response.value().detail);
  }
  auto report = decode_mutation_report(ByteSpan(response.value().payload.data(),
                                                response.value().payload.size()));
  if (!report.ok()) {
    return report.status();
  }
  return report.value();
}

Expected<MutationReport> FabricClient::set_path_state(const PathId& path, PathState state,
                                                      std::string_view reason, std::uint64_t now) {
  const std::vector<Byte> body = encode_path_state_request(path, state, reason, now);
  auto response = round_trip(MessageType::PathSetState, ByteSpan(body.data(), body.size()));
  if (!response.ok()) {
    return response.status();
  }
  if (response.value().status != Status::Ok) {
    return Outcome(response.value().status, response.value().detail);
  }
  auto report = decode_mutation_report(ByteSpan(response.value().payload.data(),
                                                response.value().payload.size()));
  if (!report.ok()) {
    return report.status();
  }
  return report.value();
}

Expected<MutationReport> FabricClient::attest_capacity(const CapacityAttestation& attestation) {
  Writer writer;
  encode(writer, attestation);
  auto response = round_trip(MessageType::CapacityAttest,
                             ByteSpan(writer.buffer().data(), writer.buffer().size()));
  if (!response.ok()) {
    return response.status();
  }
  if (response.value().status != Status::Ok) {
    return Outcome(response.value().status, response.value().detail);
  }
  auto report = decode_mutation_report(ByteSpan(response.value().payload.data(),
                                                response.value().payload.size()));
  if (!report.ok()) {
    return report.status();
  }
  return report.value();
}

Expected<MutationReport> FabricClient::issue_oversubscription(
    const OversubscriptionAuthority& authority) {
  Writer writer;
  encode(writer, authority);
  auto response = round_trip(MessageType::Oversubscribe,
                             ByteSpan(writer.buffer().data(), writer.buffer().size()));
  if (!response.ok()) {
    return response.status();
  }
  if (response.value().status != Status::Ok) {
    return Outcome(response.value().status, response.value().detail);
  }
  auto report = decode_mutation_report(ByteSpan(response.value().payload.data(),
                                                response.value().payload.size()));
  if (!report.ok()) {
    return report.status();
  }
  return report.value();
}

Expected<MutationReport> FabricClient::install_policy(const Policy& policy,
                                                      const PrincipalId& principal) {
  const std::vector<Byte> body = encode_policy_install_request(policy, principal);
  auto response = round_trip(MessageType::PolicyInstall, ByteSpan(body.data(), body.size()));
  if (!response.ok()) {
    return response.status();
  }
  if (response.value().status != Status::Ok) {
    return Outcome(response.value().status, response.value().detail);
  }
  auto report = decode_mutation_report(ByteSpan(response.value().payload.data(),
                                                response.value().payload.size()));
  if (!report.ok()) {
    return report.status();
  }
  return report.value();
}

Expected<MutationReport> FabricClient::bump_epoch(const Epoch& epoch,
                                                  const PrincipalId& principal) {
  const std::vector<Byte> body = encode_epoch_bump_request(epoch, principal);
  auto response = round_trip(MessageType::EpochBump, ByteSpan(body.data(), body.size()));
  if (!response.ok()) {
    return response.status();
  }
  if (response.value().status != Status::Ok) {
    return Outcome(response.value().status, response.value().detail);
  }
  auto report = decode_mutation_report(ByteSpan(response.value().payload.data(),
                                                response.value().payload.size()));
  if (!report.ok()) {
    return report.status();
  }
  return report.value();
}

namespace {

template <class T>
Expected<MutationReport> simple_mutation(FabricClient& client, MessageType type,
                                         const std::vector<Byte>& body) {
  auto response = client.call(type, ByteSpan(body.data(), body.size()));
  if (!response.ok()) {
    return response.status();
  }
  if (response.value().status != Status::Ok) {
    return Outcome(response.value().status, response.value().detail);
  }
  auto report = decode_mutation_report(ByteSpan(response.value().payload.data(),
                                                response.value().payload.size()));
  if (!report.ok()) {
    return report.status();
  }
  return report.value();
}

}  // namespace

Expected<MutationReport> FabricClient::propose_grant(const GrantProposal& proposal) {
  const std::vector<Byte> body = encode_grant_proposal(proposal);
  return simple_mutation<GrantProposal>(*this, MessageType::GrantPropose, body);
}

Expected<MutationReport> FabricClient::evaluate_grant(const GrantOperation& op) {
  const std::vector<Byte> body = encode_grant_operation(op);
  return simple_mutation<GrantOperation>(*this, MessageType::GrantEvaluate, body);
}

Expected<MutationReport> FabricClient::reserve_grant(const GrantOperation& op) {
  const std::vector<Byte> body = encode_grant_operation(op);
  return simple_mutation<GrantOperation>(*this, MessageType::GrantReserve, body);
}

Expected<MutationReport> FabricClient::activate_grant(const GrantOperation& op) {
  const std::vector<Byte> body = encode_grant_operation(op);
  return simple_mutation<GrantOperation>(*this, MessageType::GrantActivate, body);
}

Expected<MutationReport> FabricClient::degrade_grant(const GrantOperation& op) {
  const std::vector<Byte> body = encode_grant_operation(op);
  return simple_mutation<GrantOperation>(*this, MessageType::GrantDegrade, body);
}

Expected<MutationReport> FabricClient::withdraw_grant(const GrantOperation& op) {
  const std::vector<Byte> body = encode_grant_operation(op);
  return simple_mutation<GrantOperation>(*this, MessageType::GrantWithdraw, body);
}

Expected<MutationReport> FabricClient::retire_grant(const GrantOperation& op) {
  const std::vector<Byte> body = encode_grant_operation(op);
  return simple_mutation<GrantOperation>(*this, MessageType::GrantRetire, body);
}

Expected<MutationReport> FabricClient::cancel_grant(const GrantOperation& op) {
  const std::vector<Byte> body = encode_grant_operation(op);
  return simple_mutation<GrantOperation>(*this, MessageType::GrantCancel, body);
}

Expected<MutationReport> FabricClient::acknowledge_grant(const GrantAcknowledgement& ack) {
  const std::vector<Byte> body = encode_acknowledgement(ack);
  return simple_mutation<GrantAcknowledgement>(*this, MessageType::GrantAcknowledge, body);
}

Expected<MutationReport> FabricClient::verify_grant(const GrantVerification& verification) {
  const std::vector<Byte> body = encode_verification(verification);
  return simple_mutation<GrantVerification>(*this, MessageType::GrantVerify, body);
}

Expected<MutationReport> FabricClient::reconcile_grant(const GrantOperation& op, GrantState target,
                                                       const PrincipalId& principal) {
  const std::vector<Byte> body = encode_reconcile_request(op, target, principal);
  return simple_mutation<GrantOperation>(*this, MessageType::GrantReconcile, body);
}

Expected<MutationReport> FabricClient::tick(std::uint64_t now) {
  const std::vector<Byte> body = encode_u64_body(now);
  return simple_mutation<std::uint64_t>(*this, MessageType::TickRequest, body);
}

Expected<StatusReport> FabricClient::status() {
  auto response = round_trip(MessageType::StatusRequest, ByteSpan{});
  if (!response.ok()) {
    return response.status();
  }
  if (response.value().status != Status::Ok) {
    return Outcome(response.value().status, response.value().detail);
  }
  return decode_status_report(
      ByteSpan(response.value().payload.data(), response.value().payload.size()));
}

Expected<std::vector<SiteRecord>> FabricClient::list_sites() {
  auto response = round_trip(MessageType::ListSites, ByteSpan{});
  if (!response.ok()) {
    return response.status();
  }
  if (response.value().status != Status::Ok) {
    return Outcome(response.value().status, response.value().detail);
  }
  return decode_site_list(ByteSpan(response.value().payload.data(), response.value().payload.size()));
}

Expected<std::vector<PathRecord>> FabricClient::list_paths() {
  auto response = round_trip(MessageType::ListPaths, ByteSpan{});
  if (!response.ok()) {
    return response.status();
  }
  if (response.value().status != Status::Ok) {
    return Outcome(response.value().status, response.value().detail);
  }
  return decode_path_list(ByteSpan(response.value().payload.data(), response.value().payload.size()));
}

Expected<std::vector<GrantRecord>> FabricClient::list_grants(const ListFilter& filter) {
  const std::vector<Byte> body = encode_list_filter(filter);
  auto response = round_trip(MessageType::ListGrants, ByteSpan(body.data(), body.size()));
  if (!response.ok()) {
    return response.status();
  }
  if (response.value().status != Status::Ok) {
    return Outcome(response.value().status, response.value().detail);
  }
  return decode_grant_list(
      ByteSpan(response.value().payload.data(), response.value().payload.size()));
}

Expected<CapacityLedger> FabricClient::ledger(const PathId& path) {
  const std::vector<Byte> body = encode_id_body(path.raw());
  auto response = round_trip(MessageType::LedgerRequest, ByteSpan(body.data(), body.size()));
  if (!response.ok()) {
    return response.status();
  }
  if (response.value().status != Status::Ok) {
    return Outcome(response.value().status, response.value().detail);
  }
  auto report = decode_ledger_report(
      ByteSpan(response.value().payload.data(), response.value().payload.size()));
  if (!report.ok()) {
    return report.status();
  }
  return report.value().ledger;
}

Expected<DigestReport> FabricClient::digest() {
  auto response = round_trip(MessageType::DigestRequest, ByteSpan{});
  if (!response.ok()) {
    return response.status();
  }
  if (response.value().status != Status::Ok) {
    return Outcome(response.value().status, response.value().detail);
  }
  return decode_digest_report(
      ByteSpan(response.value().payload.data(), response.value().payload.size()));
}

Expected<AuthoritySnapshot> FabricClient::snapshot() {
  auto response = round_trip(MessageType::SnapshotRequest, ByteSpan{});
  if (!response.ok()) {
    return response.status();
  }
  if (response.value().status != Status::Ok) {
    return Outcome(response.value().status, response.value().detail);
  }
  Reader reader(ByteSpan(response.value().payload.data(), response.value().payload.size()),
                WireLimits{kAbsoluteMaxFrameBytes, 4096, 1U << 20, 8});
  auto snapshot = decode_snapshot(reader);
  if (!snapshot.ok()) {
    return snapshot.status();
  }
  return snapshot.value();
}

Status FabricClient::request_shutdown() {
  auto response = round_trip(MessageType::ShutdownRequest, ByteSpan{});
  if (!response.ok()) {
    return response.status();
  }
  return response.value().status;
}

Expected<GrantRecord> extract_grant(const MutationReport& report) {
  auto change = find_change(report, ObjectKind::Grant);
  if (!change.ok()) {
    return change.status();
  }
  Reader reader(ByteSpan(change.value().image.data(), change.value().image.size()),
                WireLimits{16U << 20, 4096, 1U << 20, 8});
  auto grant = decode_grant(reader);
  if (!grant.ok()) {
    return grant.status();
  }
  return grant.value();
}

Expected<SiteRecord> extract_site(const MutationReport& report) {
  auto change = find_change(report, ObjectKind::Site);
  if (!change.ok()) {
    return change.status();
  }
  Reader reader(ByteSpan(change.value().image.data(), change.value().image.size()),
                WireLimits{16U << 20, 4096, 1U << 20, 8});
  auto record = decode_site(reader);
  if (!record.ok()) {
    return record.status();
  }
  return record.value();
}

Expected<PathRecord> extract_path(const MutationReport& report) {
  auto change = find_change(report, ObjectKind::Path);
  if (!change.ok()) {
    return change.status();
  }
  Reader reader(ByteSpan(change.value().image.data(), change.value().image.size()),
                WireLimits{16U << 20, 4096, 1U << 20, 8});
  auto record = decode_path(reader);
  if (!record.ok()) {
    return record.status();
  }
  return record.value();
}

}  // namespace isf
