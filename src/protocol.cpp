// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "isf/protocol.hpp"

#include "isf/checked.hpp"

#include <algorithm>
#include <cstring>
#include <string>

namespace isf {
namespace {

void put_u32(Byte* out, std::uint32_t value) {
  for (unsigned i = 0; i < 4; ++i) {
    out[i] = static_cast<Byte>((value >> (i * 8U)) & 0xFFU);
  }
}

[[nodiscard]] std::uint32_t get_u32(const Byte* in) {
  std::uint32_t out = 0;
  for (unsigned i = 0; i < 4; ++i) {
    out |= static_cast<std::uint32_t>(in[i]) << (i * 8U);
  }
  return out;
}

[[nodiscard]] WireLimits message_limits() {
  WireLimits limits;
  limits.max_bytes = kDefaultMaxFrameBytes;
  limits.max_string = 4096;
  limits.max_container = 65536;
  limits.max_nesting = 8;
  return limits;
}

}  // namespace

const char* message_type_name(MessageType type) noexcept {
  switch (type) {
    case MessageType::Invalid:
      return "INVALID";
    case MessageType::Hello:
      return "HELLO";
    case MessageType::HelloAck:
      return "HELLO_ACK";
    case MessageType::ErrorReply:
      return "ERROR";
    case MessageType::StatusRequest:
      return "STATUS_REQUEST";
    case MessageType::SiteRegister:
      return "SITE_REGISTER";
    case MessageType::SiteHeartbeat:
      return "SITE_HEARTBEAT";
    case MessageType::SiteSetState:
      return "SITE_SET_STATE";
    case MessageType::PathRegister:
      return "PATH_REGISTER";
    case MessageType::PathSetState:
      return "PATH_SET_STATE";
    case MessageType::CapacityAttest:
      return "CAPACITY_ATTEST";
    case MessageType::Oversubscribe:
      return "OVERSUBSCRIBE";
    case MessageType::PolicyInstall:
      return "POLICY_INSTALL";
    case MessageType::EpochBump:
      return "EPOCH_BUMP";
    case MessageType::GrantPropose:
      return "GRANT_PROPOSE";
    case MessageType::GrantEvaluate:
      return "GRANT_EVALUATE";
    case MessageType::GrantReserve:
      return "GRANT_RESERVE";
    case MessageType::GrantActivate:
      return "GRANT_ACTIVATE";
    case MessageType::GrantDegrade:
      return "GRANT_DEGRADE";
    case MessageType::GrantWithdraw:
      return "GRANT_WITHDRAW";
    case MessageType::GrantRetire:
      return "GRANT_RETIRE";
    case MessageType::GrantCancel:
      return "GRANT_CANCEL";
    case MessageType::GrantAcknowledge:
      return "GRANT_ACKNOWLEDGE";
    case MessageType::GrantVerify:
      return "GRANT_VERIFY";
    case MessageType::GrantReconcile:
      return "GRANT_RECONCILE";
    case MessageType::ListSites:
      return "LIST_SITES";
    case MessageType::ListPaths:
      return "LIST_PATHS";
    case MessageType::ListGrants:
      return "LIST_GRANTS";
    case MessageType::LedgerRequest:
      return "LEDGER_REQUEST";
    case MessageType::DigestRequest:
      return "DIGEST_REQUEST";
    case MessageType::SnapshotRequest:
      return "SNAPSHOT_REQUEST";
    case MessageType::TickRequest:
      return "TICK_REQUEST";
    case MessageType::ShutdownRequest:
      return "SHUTDOWN_REQUEST";
    case MessageType::MutationReply:
      return "MUTATION_REPLY";
    case MessageType::StatusReply:
      return "STATUS_REPLY";
    case MessageType::SitesReply:
      return "SITES_REPLY";
    case MessageType::PathsReply:
      return "PATHS_REPLY";
    case MessageType::GrantsReply:
      return "GRANTS_REPLY";
    case MessageType::LedgerReply:
      return "LEDGER_REPLY";
    case MessageType::DigestReply:
      return "DIGEST_REPLY";
    case MessageType::SnapshotReply:
      return "SNAPSHOT_REPLY";
    case MessageType::ShutdownReply:
      return "SHUTDOWN_REPLY";
  }
  return "INVALID";
}

bool message_type_is_request(MessageType type) noexcept {
  if (type == MessageType::Hello) {
    return true;
  }
  const auto value = static_cast<std::uint16_t>(type);
  return value >= static_cast<std::uint16_t>(MessageType::StatusRequest) &&
         value <= static_cast<std::uint16_t>(MessageType::ShutdownRequest);
}

bool message_type_is_reply(MessageType type) noexcept {
  if (type == MessageType::HelloAck || type == MessageType::ErrorReply) {
    return true;
  }
  const auto value = static_cast<std::uint16_t>(type);
  return value >= static_cast<std::uint16_t>(MessageType::MutationReply) &&
         value <= static_cast<std::uint16_t>(MessageType::ShutdownReply);
}

const char* frame_error_name(FrameError e) noexcept {
  switch (e) {
    case FrameError::Ok:
      return "OK";
    case FrameError::ShortHeader:
      return "SHORT_HEADER";
    case FrameError::BadMagic:
      return "BAD_MAGIC";
    case FrameError::LengthTooLarge:
      return "LENGTH_TOO_LARGE";
    case FrameError::LengthZero:
      return "LENGTH_ZERO";
    case FrameError::ChecksumMismatch:
      return "CHECKSUM_MISMATCH";
    case FrameError::UnexpectedFlags:
      return "UNEXPECTED_FLAGS";
    case FrameError::TruncatedPayload:
      return "TRUNCATED_PAYLOAD";
    case FrameError::Closed:
      return "CLOSED";
    case FrameError::TimedOut:
      return "TIMED_OUT";
    case FrameError::IoError:
      return "IO_ERROR";
  }
  return "INVALID";
}

std::vector<Byte> encode_frame(ByteSpan payload) {
  std::vector<Byte> out(kFrameHeaderBytes + payload.size());
  put_u32(out.data(), kFrameMagic);
  put_u32(out.data() + 4, static_cast<std::uint32_t>(payload.size()));
  put_u32(out.data() + 8, crc32c(payload));
  put_u32(out.data() + 12, 0);
  if (!payload.empty()) {
    std::memcpy(out.data() + kFrameHeaderBytes, payload.data(), payload.size());
  }
  return out;
}

Status FrameDecoder::push(ByteSpan data) {
  if (failed_) {
    return Outcome(Status::Corrupt, "frame decoder is in a failed state");
  }
  if (cursor_ > 0) {
    buffer_.erase(buffer_.begin(), buffer_.begin() + static_cast<std::ptrdiff_t>(cursor_));
    cursor_ = 0;
  }
  if (data.size() > (max_frame_bytes_ + kFrameHeaderBytes) * 2U) {
    failed_ = true;
    last_error_ = FrameError::LengthTooLarge;
    return Outcome(Status::LimitExceeded, "incoming batch exceeds the frame bound");
  }
  buffer_.insert(buffer_.end(), data.begin(), data.end());
  if (buffer_.size() > (max_frame_bytes_ + kFrameHeaderBytes) * 2U) {
    failed_ = true;
    last_error_ = FrameError::LengthTooLarge;
    return Outcome(Status::LimitExceeded, "buffered bytes exceed the frame bound");
  }
  return Status::Ok;
}

Expected<std::vector<Byte>> FrameDecoder::next() {
  if (failed_) {
    return Outcome(Status::Corrupt, "frame decoder is in a failed state");
  }
  const std::size_t available = buffer_.size() - cursor_;
  if (available < kFrameHeaderBytes) {
    return Status::NotFound;
  }
  const Byte* header = buffer_.data() + cursor_;
  if (get_u32(header) != kFrameMagic) {
    failed_ = true;
    last_error_ = FrameError::BadMagic;
    return Outcome(Status::Invalid, "frame magic does not match");
  }
  const std::uint32_t length = get_u32(header + 4);
  const std::uint32_t expected_crc = get_u32(header + 8);
  const std::uint32_t flags = get_u32(header + 12);
  if (flags != 0) {
    failed_ = true;
    last_error_ = FrameError::UnexpectedFlags;
    return Outcome(Status::Invalid, "frame flags must be zero");
  }
  if (length > max_frame_bytes_) {
    failed_ = true;
    last_error_ = FrameError::LengthTooLarge;
    return Outcome(Status::LimitExceeded, "declared frame length exceeds the configured bound");
  }
  const std::size_t total = kFrameHeaderBytes + length;
  if (available < total) {
    return Status::NotFound;
  }
  const ByteSpan payload(buffer_.data() + cursor_ + kFrameHeaderBytes, length);
  if (crc32c(payload) != expected_crc) {
    failed_ = true;
    last_error_ = FrameError::ChecksumMismatch;
    return Outcome(Status::Corrupt, "frame payload checksum does not match");
  }
  std::vector<Byte> out(payload.begin(), payload.end());
  cursor_ += total;
  if (cursor_ == buffer_.size()) {
    buffer_.clear();
    cursor_ = 0;
  }
  return out;
}

void FrameDecoder::reset() {
  buffer_.clear();
  cursor_ = 0;
  last_error_ = FrameError::Ok;
  failed_ = false;
}

// ---------------------------------------------------------------------------
// Envelope codecs
// ---------------------------------------------------------------------------

std::vector<Byte> encode_request(const Request& request) {
  Writer writer(message_limits());
  writer.u16(request.protocol_version);
  writer.u16(static_cast<std::uint16_t>(request.type));
  writer.u64(request.session_seq);
  writer.id128(request.id.raw());
  writer.bytes(ByteSpan(request.payload.data(), request.payload.size()));
  return writer.buffer();
}

Expected<Request> decode_request(ByteSpan payload, const WireLimits& limits) {
  Reader reader(payload, limits);
  Request out;
  auto version = reader.u16();
  if (!version.ok()) return version.status();
  out.protocol_version = version.value();
  auto type = reader.u16();
  if (!type.ok()) return type.status();
  out.type = static_cast<MessageType>(type.value());
  if (!message_type_is_request(out.type)) {
    return Outcome(Status::Invalid, "message type is not a request");
  }
  auto sequence = reader.u64();
  if (!sequence.ok()) return sequence.status();
  out.session_seq = sequence.value();
  auto id = reader.id128();
  if (!id.ok()) return id.status();
  out.id = RequestId::from_raw(id.value());
  auto body = reader.bytes();
  if (!body.ok()) return body.status();
  out.payload.assign(body.value().begin(), body.value().end());
  if (reader.require_end() != Status::Ok) {
    return Outcome(Status::Invalid, "request envelope has trailing bytes");
  }
  return out;
}

std::vector<Byte> encode_response(const Response& response) {
  Writer writer(message_limits());
  writer.u16(response.protocol_version);
  writer.u16(static_cast<std::uint16_t>(response.type));
  writer.u64(response.session_seq);
  writer.id128(response.id.raw());
  writer.u8(static_cast<std::uint8_t>(response.status));
  writer.str(response.detail);
  writer.bytes(ByteSpan(response.payload.data(), response.payload.size()));
  return writer.buffer();
}

Expected<Response> decode_response(ByteSpan payload, const WireLimits& limits) {
  Reader reader(payload, limits);
  Response out;
  auto version = reader.u16();
  if (!version.ok()) return version.status();
  out.protocol_version = version.value();
  auto type = reader.u16();
  if (!type.ok()) return type.status();
  out.type = static_cast<MessageType>(type.value());
  if (!message_type_is_reply(out.type)) {
    return Outcome(Status::Invalid, "message type is not a reply");
  }
  auto sequence = reader.u64();
  if (!sequence.ok()) return sequence.status();
  out.session_seq = sequence.value();
  auto id = reader.id128();
  if (!id.ok()) return id.status();
  out.id = RequestId::from_raw(id.value());
  auto status = reader.u8();
  if (!status.ok()) return status.status();
  bool recognized = false;
  out.status = Status::Ok;
  if (status.value() != 0) {
    // Statuses are transported by ordinal; validate the ordinal range.
    if (status.value() > static_cast<std::uint8_t>(Status::Ambiguous)) {
      return Outcome(Status::Invalid, "reply carries an unknown status ordinal");
    }
    out.status = static_cast<Status>(status.value());
  }
  (void)recognized;
  auto detail = reader.str();
  if (!detail.ok()) return detail.status();
  out.detail = detail.value();
  auto body = reader.bytes();
  if (!body.ok()) return body.status();
  out.payload.assign(body.value().begin(), body.value().end());
  if (reader.require_end() != Status::Ok) {
    return Outcome(Status::Invalid, "response envelope has trailing bytes");
  }
  return out;
}

// ---------------------------------------------------------------------------
// Message bodies
// ---------------------------------------------------------------------------

std::vector<Byte> encode_hello_request(const HelloRequest& value) {
  Writer writer(message_limits());
  writer.u16(value.protocol_version);
  writer.id128(value.client_nonce);
  writer.str(value.client_kind);
  writer.u32(value.max_frame_bytes);
  return writer.buffer();
}

Expected<HelloRequest> decode_hello_request(ByteSpan payload) {
  Reader reader(payload, message_limits());
  HelloRequest out;
  auto version = reader.u16();
  if (!version.ok()) return version.status();
  out.protocol_version = version.value();
  auto nonce = reader.id128();
  if (!nonce.ok()) return nonce.status();
  out.client_nonce = nonce.value();
  auto kind = reader.str();
  if (!kind.ok()) return kind.status();
  out.client_kind = kind.value();
  auto max_frame = reader.u32();
  if (!max_frame.ok()) return max_frame.status();
  out.max_frame_bytes = max_frame.value();
  if (reader.require_end() != Status::Ok) {
    return Outcome(Status::Invalid, "hello request has trailing bytes");
  }
  return out;
}

std::vector<Byte> encode_hello_reply(const HelloReply& value) {
  Writer writer(message_limits());
  writer.u16(value.protocol_version);
  writer.id128(value.session.raw());
  writer.id128(value.server_incarnation.raw());
  writer.epoch(value.epoch);
  writer.u32(value.max_frame_bytes);
  writer.u8(static_cast<std::uint8_t>(value.store_fidelity));
  writer.boolean(value.store_servable);
  writer.boolean(value.durable_writes);
  writer.u32(value.format_version);
  return writer.buffer();
}

Expected<HelloReply> decode_hello_reply(ByteSpan payload) {
  Reader reader(payload, message_limits());
  HelloReply out;
  auto version = reader.u16();
  if (!version.ok()) return version.status();
  out.protocol_version = version.value();
  auto session = reader.id128();
  if (!session.ok()) return session.status();
  out.session = SessionId::from_raw(session.value());
  auto incarnation = reader.id128();
  if (!incarnation.ok()) return incarnation.status();
  out.server_incarnation = Incarnation::from_raw(incarnation.value());
  auto epoch = reader.epoch();
  if (!epoch.ok()) return epoch.status();
  out.epoch = epoch.value();
  auto max_frame = reader.u32();
  if (!max_frame.ok()) return max_frame.status();
  out.max_frame_bytes = max_frame.value();
  auto fidelity = reader.u8();
  if (!fidelity.ok()) return fidelity.status();
  if (fidelity.value() > static_cast<std::uint8_t>(RecoveryFidelity::Missing)) {
    return Outcome(Status::Invalid, "hello reply carries an unknown recovery fidelity");
  }
  out.store_fidelity = static_cast<RecoveryFidelity>(fidelity.value());
  auto servable = reader.boolean();
  if (!servable.ok()) return servable.status();
  out.store_servable = servable.value();
  auto durable = reader.boolean();
  if (!durable.ok()) return durable.status();
  out.durable_writes = durable.value();
  auto format = reader.u32();
  if (!format.ok()) return format.status();
  out.format_version = format.value();
  if (reader.require_end() != Status::Ok) {
    return Outcome(Status::Invalid, "hello reply has trailing bytes");
  }
  return out;
}

std::vector<Byte> encode_site_registration(const SiteRegistration& value) {
  Writer writer(message_limits());
  writer.id128(value.descriptor.id.raw());
  writer.str(value.descriptor.name);
  writer.u64(value.descriptor.advertised_capacity);
  writer.id128(value.incarnation.raw());
  writer.epoch(value.epoch);
  writer.u64(value.now_ms);
  return writer.buffer();
}

Expected<SiteRegistration> decode_site_registration(ByteSpan payload) {
  Reader reader(payload, message_limits());
  SiteRegistration out;
  auto id = reader.id128();
  if (!id.ok()) return id.status();
  out.descriptor.id = SiteId::from_raw(id.value());
  auto name = reader.str();
  if (!name.ok()) return name.status();
  out.descriptor.name = name.value();
  auto advertised = reader.u64();
  if (!advertised.ok()) return advertised.status();
  out.descriptor.advertised_capacity = advertised.value();
  auto incarnation = reader.id128();
  if (!incarnation.ok()) return incarnation.status();
  out.incarnation = Incarnation::from_raw(incarnation.value());
  auto epoch = reader.epoch();
  if (!epoch.ok()) return epoch.status();
  out.epoch = epoch.value();
  auto now = reader.u64();
  if (!now.ok()) return now.status();
  out.now_ms = now.value();
  if (reader.require_end() != Status::Ok) {
    return Outcome(Status::Invalid, "site registration has trailing bytes");
  }
  return out;
}

std::vector<Byte> encode_heartbeat(const SiteHeartbeat& value) {
  Writer writer(message_limits());
  writer.id128(value.id.raw());
  writer.id128(value.incarnation.raw());
  writer.generation(value.generation);
  writer.epoch(value.epoch);
  writer.u64(value.advertised_capacity);
  writer.u64(value.now_ms);
  return writer.buffer();
}

Expected<SiteHeartbeat> decode_heartbeat(ByteSpan payload) {
  Reader reader(payload, message_limits());
  SiteHeartbeat out;
  auto id = reader.id128();
  if (!id.ok()) return id.status();
  out.id = SiteId::from_raw(id.value());
  auto incarnation = reader.id128();
  if (!incarnation.ok()) return incarnation.status();
  out.incarnation = Incarnation::from_raw(incarnation.value());
  auto generation = reader.generation();
  if (!generation.ok()) return generation.status();
  out.generation = generation.value();
  auto epoch = reader.epoch();
  if (!epoch.ok()) return epoch.status();
  out.epoch = epoch.value();
  auto advertised = reader.u64();
  if (!advertised.ok()) return advertised.status();
  out.advertised_capacity = advertised.value();
  auto now = reader.u64();
  if (!now.ok()) return now.status();
  out.now_ms = now.value();
  if (reader.require_end() != Status::Ok) {
    return Outcome(Status::Invalid, "heartbeat has trailing bytes");
  }
  return out;
}

std::vector<Byte> encode_path_registration(const PathRegistration& value) {
  Writer writer(message_limits());
  writer.id128(value.descriptor.id.raw());
  writer.str(value.descriptor.name);
  writer.id128(value.descriptor.edge.raw());
  writer.id128(value.descriptor.shared_risk_domain.raw());
  writer.id128(value.descriptor.endpoint_a.raw());
  writer.id128(value.descriptor.endpoint_b.raw());
  writer.generation(value.path_generation);
  writer.u8(static_cast<std::uint8_t>(value.state));
  writer.u64(value.advertised);
  writer.u64(value.observed);
  writer.u64(value.now_ms);
  return writer.buffer();
}

Expected<PathRegistration> decode_path_registration(ByteSpan payload) {
  Reader reader(payload, message_limits());
  PathRegistration out;
  auto id = reader.id128();
  if (!id.ok()) return id.status();
  out.descriptor.id = PathId::from_raw(id.value());
  auto name = reader.str();
  if (!name.ok()) return name.status();
  out.descriptor.name = name.value();
  auto edge = reader.id128();
  if (!edge.ok()) return edge.status();
  out.descriptor.edge = EdgeId::from_raw(edge.value());
  auto domain = reader.id128();
  if (!domain.ok()) return domain.status();
  out.descriptor.shared_risk_domain = DomainId::from_raw(domain.value());
  auto a = reader.id128();
  if (!a.ok()) return a.status();
  out.descriptor.endpoint_a = SiteId::from_raw(a.value());
  auto b = reader.id128();
  if (!b.ok()) return b.status();
  out.descriptor.endpoint_b = SiteId::from_raw(b.value());
  auto generation = reader.generation();
  if (!generation.ok()) return generation.status();
  out.path_generation = generation.value();
  auto state = reader.u8();
  if (!state.ok()) return state.status();
  if (state.value() > static_cast<std::uint8_t>(PathState::Fenced)) {
    return Outcome(Status::Invalid, "path state out of range");
  }
  out.state = static_cast<PathState>(state.value());
  auto advertised = reader.u64();
  if (!advertised.ok()) return advertised.status();
  out.advertised = advertised.value();
  auto observed = reader.u64();
  if (!observed.ok()) return observed.status();
  out.observed = observed.value();
  auto now = reader.u64();
  if (!now.ok()) return now.status();
  out.now_ms = now.value();
  if (reader.require_end() != Status::Ok) {
    return Outcome(Status::Invalid, "path registration has trailing bytes");
  }
  return out;
}

std::vector<Byte> encode_grant_proposal(const GrantProposal& value) {
  Writer writer(message_limits());
  writer.id128(value.request.raw());
  writer.id128(value.holder.raw());
  writer.id128(value.holder_incarnation.raw());
  writer.generation(value.holder_generation);
  writer.id128(value.path.raw());
  writer.u64(value.amount);
  writer.u8(static_cast<std::uint8_t>(value.grant_class));
  writer.u64(value.duration_ms);
  writer.u64(value.now_ms);
  writer.str(value.reason);
  writer.id128(value.grant_id.raw());
  writer.id128(value.lease.raw());
  return writer.buffer();
}

Expected<GrantProposal> decode_grant_proposal(ByteSpan payload) {
  Reader reader(payload, message_limits());
  GrantProposal out;
  auto request = reader.id128();
  if (!request.ok()) return request.status();
  out.request = RequestId::from_raw(request.value());
  auto holder = reader.id128();
  if (!holder.ok()) return holder.status();
  out.holder = SiteId::from_raw(holder.value());
  auto incarnation = reader.id128();
  if (!incarnation.ok()) return incarnation.status();
  out.holder_incarnation = Incarnation::from_raw(incarnation.value());
  auto generation = reader.generation();
  if (!generation.ok()) return generation.status();
  out.holder_generation = generation.value();
  auto path = reader.id128();
  if (!path.ok()) return path.status();
  out.path = PathId::from_raw(path.value());
  auto amount = reader.u64();
  if (!amount.ok()) return amount.status();
  out.amount = amount.value();
  auto klass = reader.u8();
  if (!klass.ok()) return klass.status();
  if (klass.value() > static_cast<std::uint8_t>(GrantClass::Protected)) {
    return Outcome(Status::Invalid, "grant class out of range");
  }
  out.grant_class = static_cast<GrantClass>(klass.value());
  auto duration = reader.u64();
  if (!duration.ok()) return duration.status();
  out.duration_ms = duration.value();
  auto now = reader.u64();
  if (!now.ok()) return now.status();
  out.now_ms = now.value();
  auto reason = reader.str();
  if (!reason.ok()) return reason.status();
  out.reason = reason.value();
  auto grant = reader.id128();
  if (!grant.ok()) return grant.status();
  out.grant_id = GrantId::from_raw(grant.value());
  auto lease = reader.id128();
  if (!lease.ok()) return lease.status();
  out.lease = LeaseId::from_raw(lease.value());
  if (reader.require_end() != Status::Ok) {
    return Outcome(Status::Invalid, "grant proposal has trailing bytes");
  }
  return out;
}

std::vector<Byte> encode_grant_operation(const GrantOperation& value) {
  Writer writer(message_limits());
  writer.id128(value.grant.raw());
  writer.id128(value.request.raw());
  writer.id128(value.actor.raw());
  writer.id128(value.actor_incarnation.raw());
  writer.generation(value.actor_generation);
  writer.epoch(value.epoch);
  writer.generation(value.path_generation);
  writer.generation(value.capacity_generation);
  writer.generation(value.policy_generation);
  writer.id128(value.lease.raw());
  writer.u64(value.now_ms);
  writer.str(value.reason);
  return writer.buffer();
}

Expected<GrantOperation> decode_grant_operation(ByteSpan payload) {
  Reader reader(payload, message_limits());
  GrantOperation out;
  auto grant = reader.id128();
  if (!grant.ok()) return grant.status();
  out.grant = GrantId::from_raw(grant.value());
  auto request = reader.id128();
  if (!request.ok()) return request.status();
  out.request = RequestId::from_raw(request.value());
  auto actor = reader.id128();
  if (!actor.ok()) return actor.status();
  out.actor = SiteId::from_raw(actor.value());
  auto incarnation = reader.id128();
  if (!incarnation.ok()) return incarnation.status();
  out.actor_incarnation = Incarnation::from_raw(incarnation.value());
  auto actor_generation = reader.generation();
  if (!actor_generation.ok()) return actor_generation.status();
  out.actor_generation = actor_generation.value();
  auto epoch = reader.epoch();
  if (!epoch.ok()) return epoch.status();
  out.epoch = epoch.value();
  auto path_generation = reader.generation();
  if (!path_generation.ok()) return path_generation.status();
  out.path_generation = path_generation.value();
  auto capacity_generation = reader.generation();
  if (!capacity_generation.ok()) return capacity_generation.status();
  out.capacity_generation = capacity_generation.value();
  auto policy_generation = reader.generation();
  if (!policy_generation.ok()) return policy_generation.status();
  out.policy_generation = policy_generation.value();
  auto lease = reader.id128();
  if (!lease.ok()) return lease.status();
  out.lease = LeaseId::from_raw(lease.value());
  auto now = reader.u64();
  if (!now.ok()) return now.status();
  out.now_ms = now.value();
  auto reason = reader.str();
  if (!reason.ok()) return reason.status();
  out.reason = reason.value();
  if (reader.require_end() != Status::Ok) {
    return Outcome(Status::Invalid, "grant operation has trailing bytes");
  }
  return out;
}

std::vector<Byte> encode_acknowledgement(const GrantAcknowledgement& value) {
  Writer writer(message_limits());
  writer.id128(value.grant.raw());
  writer.id128(value.actor.raw());
  writer.id128(value.actor_incarnation.raw());
  writer.epoch(value.epoch);
  writer.u64(value.now_ms);
  return writer.buffer();
}

Expected<GrantAcknowledgement> decode_acknowledgement(ByteSpan payload) {
  Reader reader(payload, message_limits());
  GrantAcknowledgement out;
  auto grant = reader.id128();
  if (!grant.ok()) return grant.status();
  out.grant = GrantId::from_raw(grant.value());
  auto actor = reader.id128();
  if (!actor.ok()) return actor.status();
  out.actor = SiteId::from_raw(actor.value());
  auto incarnation = reader.id128();
  if (!incarnation.ok()) return incarnation.status();
  out.actor_incarnation = Incarnation::from_raw(incarnation.value());
  auto epoch = reader.epoch();
  if (!epoch.ok()) return epoch.status();
  out.epoch = epoch.value();
  auto now = reader.u64();
  if (!now.ok()) return now.status();
  out.now_ms = now.value();
  if (reader.require_end() != Status::Ok) {
    return Outcome(Status::Invalid, "acknowledgement has trailing bytes");
  }
  return out;
}

std::vector<Byte> encode_verification(const GrantVerification& value) {
  Writer writer(message_limits());
  writer.id128(value.id.raw());
  writer.id128(value.grant.raw());
  writer.id128(value.verifier.raw());
  writer.u8(static_cast<std::uint8_t>(value.result));
  writer.digest(value.evidence);
  writer.u64(value.now_ms);
  writer.str(value.detail);
  return writer.buffer();
}

Expected<GrantVerification> decode_verification_message(ByteSpan payload) {
  Reader reader(payload, message_limits());
  GrantVerification out;
  auto id = reader.id128();
  if (!id.ok()) return id.status();
  out.id = VerificationId::from_raw(id.value());
  auto grant = reader.id128();
  if (!grant.ok()) return grant.status();
  out.grant = GrantId::from_raw(grant.value());
  auto verifier = reader.id128();
  if (!verifier.ok()) return verifier.status();
  out.verifier = PrincipalId::from_raw(verifier.value());
  auto result = reader.u8();
  if (!result.ok()) return result.status();
  if (result.value() > static_cast<std::uint8_t>(VerificationState::Indeterminate)) {
    return Outcome(Status::Invalid, "verification result out of range");
  }
  out.result = static_cast<VerificationState>(result.value());
  auto evidence = reader.digest();
  if (!evidence.ok()) return evidence.status();
  out.evidence = evidence.value();
  auto now = reader.u64();
  if (!now.ok()) return now.status();
  out.now_ms = now.value();
  auto detail = reader.str();
  if (!detail.ok()) return detail.status();
  out.detail = detail.value();
  if (reader.require_end() != Status::Ok) {
    return Outcome(Status::Invalid, "verification has trailing bytes");
  }
  return out;
}

std::vector<Byte> encode_site_state_request(const SiteId& site, SiteState state,
                                            std::string_view reason, std::uint64_t now_ms) {
  Writer writer(message_limits());
  writer.id128(site.raw());
  writer.u8(static_cast<std::uint8_t>(state));
  writer.str(reason);
  writer.u64(now_ms);
  return writer.buffer();
}

Expected<std::tuple<SiteId, SiteState, std::string, std::uint64_t>> decode_site_state_request(
    ByteSpan payload) {
  Reader reader(payload, message_limits());
  auto site = reader.id128();
  if (!site.ok()) return site.status();
  auto state = reader.u8();
  if (!state.ok()) return state.status();
  if (state.value() > static_cast<std::uint8_t>(SiteState::Fenced)) {
    return Outcome(Status::Invalid, "site state out of range");
  }
  auto reason = reader.str();
  if (!reason.ok()) return reason.status();
  auto now = reader.u64();
  if (!now.ok()) return now.status();
  if (reader.require_end() != Status::Ok) {
    return Outcome(Status::Invalid, "site state request has trailing bytes");
  }
  return std::make_tuple(SiteId::from_raw(site.value()), static_cast<SiteState>(state.value()),
                         reason.value(), now.value());
}

std::vector<Byte> encode_path_state_request(const PathId& path, PathState state,
                                            std::string_view reason, std::uint64_t now_ms) {
  Writer writer(message_limits());
  writer.id128(path.raw());
  writer.u8(static_cast<std::uint8_t>(state));
  writer.str(reason);
  writer.u64(now_ms);
  return writer.buffer();
}

Expected<std::tuple<PathId, PathState, std::string, std::uint64_t>> decode_path_state_request(
    ByteSpan payload) {
  Reader reader(payload, message_limits());
  auto path = reader.id128();
  if (!path.ok()) return path.status();
  auto state = reader.u8();
  if (!state.ok()) return state.status();
  if (state.value() > static_cast<std::uint8_t>(PathState::Fenced)) {
    return Outcome(Status::Invalid, "path state out of range");
  }
  auto reason = reader.str();
  if (!reason.ok()) return reason.status();
  auto now = reader.u64();
  if (!now.ok()) return now.status();
  if (reader.require_end() != Status::Ok) {
    return Outcome(Status::Invalid, "path state request has trailing bytes");
  }
  return std::make_tuple(PathId::from_raw(path.value()), static_cast<PathState>(state.value()),
                         reason.value(), now.value());
}

std::vector<Byte> encode_policy_install_request(const Policy& policy, const PrincipalId& principal) {
  Writer writer(message_limits());
  encode(writer, policy);
  writer.id128(principal.raw());
  return writer.buffer();
}

Expected<std::pair<Policy, PrincipalId>> decode_policy_install_request(ByteSpan payload) {
  Reader reader(payload, message_limits());
  auto policy = decode_policy(reader);
  if (!policy.ok()) return policy.status();
  auto principal = reader.id128();
  if (!principal.ok()) return principal.status();
  if (reader.require_end() != Status::Ok) {
    return Outcome(Status::Invalid, "policy install request has trailing bytes");
  }
  return std::make_pair(policy.value(), PrincipalId::from_raw(principal.value()));
}

std::vector<Byte> encode_epoch_bump_request(Epoch epoch, const PrincipalId& principal) {
  Writer writer(message_limits());
  writer.epoch(epoch);
  writer.id128(principal.raw());
  return writer.buffer();
}

Expected<std::pair<Epoch, PrincipalId>> decode_epoch_bump_request(ByteSpan payload) {
  Reader reader(payload, message_limits());
  auto epoch = reader.epoch();
  if (!epoch.ok()) return epoch.status();
  auto principal = reader.id128();
  if (!principal.ok()) return principal.status();
  if (reader.require_end() != Status::Ok) {
    return Outcome(Status::Invalid, "epoch bump request has trailing bytes");
  }
  return std::make_pair(epoch.value(), PrincipalId::from_raw(principal.value()));
}

std::vector<Byte> encode_reconcile_request(const GrantOperation& op, GrantState target,
                                           const PrincipalId& principal) {
  Writer writer(message_limits());
  const std::vector<Byte> base = encode_grant_operation(op);
  writer.bytes(ByteSpan(base.data(), base.size()));
  writer.u8(static_cast<std::uint8_t>(target));
  writer.id128(principal.raw());
  return writer.buffer();
}

Expected<std::tuple<GrantOperation, GrantState, PrincipalId>> decode_reconcile_request(
    ByteSpan payload) {
  Reader reader(payload, message_limits());
  auto base = reader.bytes();
  if (!base.ok()) return base.status();
  auto op = decode_grant_operation(base.value());
  if (!op.ok()) return op.status();
  auto target = reader.u8();
  if (!target.ok()) return target.status();
  if (target.value() > static_cast<std::uint8_t>(GrantState::Expired)) {
    return Outcome(Status::Invalid, "reconciliation target out of range");
  }
  auto principal = reader.id128();
  if (!principal.ok()) return principal.status();
  if (reader.require_end() != Status::Ok) {
    return Outcome(Status::Invalid, "reconciliation request has trailing bytes");
  }
  return std::make_tuple(op.value(), static_cast<GrantState>(target.value()),
                         PrincipalId::from_raw(principal.value()));
}

std::vector<Byte> encode_list_filter(const ListFilter& value) {
  Writer writer(message_limits());
  writer.boolean(value.include_terminal);
  writer.u32(value.limit);
  writer.id128(value.path.raw());
  writer.id128(value.site.raw());
  return writer.buffer();
}

Expected<ListFilter> decode_list_filter(ByteSpan payload) {
  Reader reader(payload, message_limits());
  ListFilter out;
  auto include = reader.boolean();
  if (!include.ok()) return include.status();
  out.include_terminal = include.value();
  auto limit = reader.u32();
  if (!limit.ok()) return limit.status();
  if (limit.value() > 65536) {
    return Outcome(Status::LimitExceeded, "list limit exceeds the protocol bound");
  }
  out.limit = limit.value();
  auto path = reader.id128();
  if (!path.ok()) return path.status();
  out.path = PathId::from_raw(path.value());
  auto site = reader.id128();
  if (!site.ok()) return site.status();
  out.site = SiteId::from_raw(site.value());
  if (reader.require_end() != Status::Ok) {
    return Outcome(Status::Invalid, "list filter has trailing bytes");
  }
  return out;
}

std::vector<Byte> encode_mutation_report(const MutationReport& value) {
  Writer writer(message_limits());
  writer.u64(value.arbitration.value);
  writer.u8(static_cast<std::uint8_t>(value.primary_kind));
  writer.id128(value.primary_key);
  writer.u32(value.total_changes);
  writer.boolean(value.truncated);
  writer.u32(static_cast<std::uint32_t>(value.changes.size()));
  for (const auto& change : value.changes) {
    encode(writer, change);
  }
  return writer.buffer();
}

Expected<MutationReport> decode_mutation_report(ByteSpan payload, const WireLimits& limits) {
  Reader reader(payload, limits);
  MutationReport out;
  auto arbitration = reader.u64();
  if (!arbitration.ok()) return arbitration.status();
  out.arbitration = ArbSeq{arbitration.value()};
  auto kind = reader.u8();
  if (!kind.ok()) return kind.status();
  if (kind.value() > static_cast<std::uint8_t>(ObjectKind::AuthorityMeta)) {
    return Outcome(Status::Invalid, "primary object kind out of range");
  }
  out.primary_kind = static_cast<ObjectKind>(kind.value());
  auto key = reader.id128();
  if (!key.ok()) return key.status();
  out.primary_key = key.value();
  auto total = reader.u32();
  if (!total.ok()) return total.status();
  out.total_changes = total.value();
  auto truncated = reader.boolean();
  if (!truncated.ok()) return truncated.status();
  out.truncated = truncated.value();
  auto count = reader.container_count();
  if (!count.ok()) return count.status();
  if (count.value() > 8192) {
    return Outcome(Status::LimitExceeded, "mutation report change count exceeds the bound");
  }
  out.changes.reserve(count.value());
  for (std::uint32_t i = 0; i < count.value(); ++i) {
    auto change = decode_state_change(reader);
    if (!change.ok()) return change.status();
    out.changes.push_back(std::move(change.value()));
  }
  if (reader.require_end() != Status::Ok) {
    return Outcome(Status::Invalid, "mutation report has trailing bytes");
  }
  return out;
}

std::vector<Byte> encode_status_report(const StatusReport& value) {
  Writer writer(message_limits());
  writer.u32(value.version.major);
  writer.u32(value.version.minor);
  writer.u32(value.version.patch);
  writer.u16(value.wire_protocol);
  writer.id128(value.incarnation.raw());
  writer.epoch(value.epoch);
  encode(writer, value.policy);
  writer.u8(static_cast<std::uint8_t>(value.store_fidelity));
  writer.id128(value.store_id.raw());
  writer.u32(value.store_format_version);
  writer.u64(value.store_records);
  writer.u64(value.store_bytes);
  writer.u64(value.ambiguous_intents);
  writer.boolean(value.store_servable);
  writer.boolean(value.store_truncated_on_open);
  writer.u64(value.uptime_ms);
  writer.u64(value.mutations_applied);
  writer.u64(value.mutations_refused);
  writer.u64(value.mutations_failed);
  writer.u64(value.connections_accepted);
  writer.u64(value.frames_decoded);
  writer.u64(value.frames_rejected);
  writer.u64(value.duplicate_requests);
  writer.u64(value.stale_requests);
  writer.u64(value.sites);
  writer.u64(value.paths);
  writer.u64(value.grants);
  writer.u64(value.aggregate.authoritative_usable);
  writer.u64(value.aggregate.committed);
  writer.u64(value.aggregate.withdrawing);
  writer.u64(value.aggregate.reserved);
  writer.u64(value.aggregate.protected_headroom);
  writer.u64(value.aggregate.unavailable);
  writer.u64(value.aggregate.free);
  writer.u64(value.aggregate.allocatable);
  writer.u64(value.aggregate.reclaimable);
  writer.u64(value.aggregate.oversubscribed);
  writer.u64(value.aggregate.authorized_extension);
  writer.digest(value.state_digest);
  writer.str(value.detail);
  return writer.buffer();
}

Expected<StatusReport> decode_status_report(ByteSpan payload) {
  Reader reader(payload, message_limits());
  StatusReport out;
  auto major = reader.u32();
  if (!major.ok()) return major.status();
  auto minor = reader.u32();
  if (!minor.ok()) return minor.status();
  auto patch = reader.u32();
  if (!patch.ok()) return patch.status();
  out.version = Version{major.value(), minor.value(), patch.value()};
  auto wire = reader.u16();
  if (!wire.ok()) return wire.status();
  out.wire_protocol = wire.value();
  auto incarnation = reader.id128();
  if (!incarnation.ok()) return incarnation.status();
  out.incarnation = Incarnation::from_raw(incarnation.value());
  auto epoch = reader.epoch();
  if (!epoch.ok()) return epoch.status();
  out.epoch = epoch.value();
  auto policy = decode_policy(reader);
  if (!policy.ok()) return policy.status();
  out.policy = policy.value();
  auto fidelity = reader.u8();
  if (!fidelity.ok()) return fidelity.status();
  if (fidelity.value() > static_cast<std::uint8_t>(RecoveryFidelity::Missing)) {
    return Outcome(Status::Invalid, "status carries an unknown recovery fidelity");
  }
  out.store_fidelity = static_cast<RecoveryFidelity>(fidelity.value());
  auto store_id = reader.id128();
  if (!store_id.ok()) return store_id.status();
  out.store_id = StoreId::from_raw(store_id.value());
  auto format = reader.u32();
  if (!format.ok()) return format.status();
  out.store_format_version = format.value();
  auto records = reader.u64();
  if (!records.ok()) return records.status();
  out.store_records = static_cast<std::size_t>(records.value());
  auto bytes = reader.u64();
  if (!bytes.ok()) return bytes.status();
  out.store_bytes = static_cast<std::size_t>(bytes.value());
  auto ambiguous = reader.u64();
  if (!ambiguous.ok()) return ambiguous.status();
  out.ambiguous_intents = static_cast<std::size_t>(ambiguous.value());
  auto servable = reader.boolean();
  if (!servable.ok()) return servable.status();
  out.store_servable = servable.value();
  auto truncated = reader.boolean();
  if (!truncated.ok()) return truncated.status();
  out.store_truncated_on_open = truncated.value();
  const auto read_u64_field = [&reader](std::uint64_t& target) -> Status {
    auto value = reader.u64();
    if (!value.ok()) {
      return value.status();
    }
    target = value.value();
    return Status::Ok;
  };
  Status status = Status::Ok;
  status = read_u64_field(out.uptime_ms);
  if (status != Status::Ok) return status;
  status = read_u64_field(out.mutations_applied);
  if (status != Status::Ok) return status;
  status = read_u64_field(out.mutations_refused);
  if (status != Status::Ok) return status;
  status = read_u64_field(out.mutations_failed);
  if (status != Status::Ok) return status;
  status = read_u64_field(out.connections_accepted);
  if (status != Status::Ok) return status;
  status = read_u64_field(out.frames_decoded);
  if (status != Status::Ok) return status;
  status = read_u64_field(out.frames_rejected);
  if (status != Status::Ok) return status;
  status = read_u64_field(out.duplicate_requests);
  if (status != Status::Ok) return status;
  status = read_u64_field(out.stale_requests);
  if (status != Status::Ok) return status;
  std::uint64_t sites = 0;
  std::uint64_t paths = 0;
  std::uint64_t grants = 0;
  status = read_u64_field(sites);
  if (status != Status::Ok) return status;
  status = read_u64_field(paths);
  if (status != Status::Ok) return status;
  status = read_u64_field(grants);
  if (status != Status::Ok) return status;
  out.sites = static_cast<std::size_t>(sites);
  out.paths = static_cast<std::size_t>(paths);
  out.grants = static_cast<std::size_t>(grants);
  status = read_u64_field(out.aggregate.authoritative_usable);
  if (status != Status::Ok) return status;
  status = read_u64_field(out.aggregate.committed);
  if (status != Status::Ok) return status;
  status = read_u64_field(out.aggregate.withdrawing);
  if (status != Status::Ok) return status;
  status = read_u64_field(out.aggregate.reserved);
  if (status != Status::Ok) return status;
  status = read_u64_field(out.aggregate.protected_headroom);
  if (status != Status::Ok) return status;
  status = read_u64_field(out.aggregate.unavailable);
  if (status != Status::Ok) return status;
  status = read_u64_field(out.aggregate.free);
  if (status != Status::Ok) return status;
  status = read_u64_field(out.aggregate.allocatable);
  if (status != Status::Ok) return status;
  status = read_u64_field(out.aggregate.reclaimable);
  if (status != Status::Ok) return status;
  status = read_u64_field(out.aggregate.oversubscribed);
  if (status != Status::Ok) return status;
  status = read_u64_field(out.aggregate.authorized_extension);
  if (status != Status::Ok) return status;
  auto digest = reader.digest();
  if (!digest.ok()) return digest.status();
  out.state_digest = digest.value();
  auto detail = reader.str();
  if (!detail.ok()) return detail.status();
  out.detail = detail.value();
  if (reader.require_end() != Status::Ok) {
    return Outcome(Status::Invalid, "status report has trailing bytes");
  }
  return out;
}

namespace {

template <class T>
std::vector<Byte> encode_record_list(const std::vector<T>& value) {
  Writer writer(message_limits());
  writer.u32(static_cast<std::uint32_t>(value.size()));
  for (const auto& item : value) {
    encode(writer, item);
  }
  return writer.buffer();
}

}  // namespace

std::vector<Byte> encode_site_list(const std::vector<SiteRecord>& value) {
  return encode_record_list(value);
}

Expected<std::vector<SiteRecord>> decode_site_list(ByteSpan payload) {
  Reader reader(payload, message_limits());
  auto count = reader.container_count();
  if (!count.ok()) return count.status();
  std::vector<SiteRecord> out;
  out.reserve(count.value());
  for (std::uint32_t i = 0; i < count.value(); ++i) {
    auto item = decode_site(reader);
    if (!item.ok()) return item.status();
    out.push_back(std::move(item.value()));
  }
  if (reader.require_end() != Status::Ok) {
    return Outcome(Status::Invalid, "site list has trailing bytes");
  }
  return out;
}

std::vector<Byte> encode_path_list(const std::vector<PathRecord>& value) {
  return encode_record_list(value);
}

Expected<std::vector<PathRecord>> decode_path_list(ByteSpan payload) {
  Reader reader(payload, message_limits());
  auto count = reader.container_count();
  if (!count.ok()) return count.status();
  std::vector<PathRecord> out;
  out.reserve(count.value());
  for (std::uint32_t i = 0; i < count.value(); ++i) {
    auto item = decode_path(reader);
    if (!item.ok()) return item.status();
    out.push_back(std::move(item.value()));
  }
  if (reader.require_end() != Status::Ok) {
    return Outcome(Status::Invalid, "path list has trailing bytes");
  }
  return out;
}

std::vector<Byte> encode_grant_list(const std::vector<GrantRecord>& value) {
  return encode_record_list(value);
}

Expected<std::vector<GrantRecord>> decode_grant_list(ByteSpan payload) {
  Reader reader(payload, message_limits());
  auto count = reader.container_count();
  if (!count.ok()) return count.status();
  std::vector<GrantRecord> out;
  out.reserve(count.value());
  for (std::uint32_t i = 0; i < count.value(); ++i) {
    auto item = decode_grant(reader);
    if (!item.ok()) return item.status();
    out.push_back(std::move(item.value()));
  }
  if (reader.require_end() != Status::Ok) {
    return Outcome(Status::Invalid, "grant list has trailing bytes");
  }
  return out;
}

std::vector<Byte> encode_ledger_report(const LedgerReport& value) {
  Writer writer(message_limits());
  writer.id128(value.path.raw());
  writer.u64(value.ledger.authoritative_usable);
  writer.u64(value.ledger.committed);
  writer.u64(value.ledger.withdrawing);
  writer.u64(value.ledger.reserved);
  writer.u64(value.ledger.protected_headroom);
  writer.u64(value.ledger.unavailable);
  writer.u64(value.ledger.free);
  writer.u64(value.ledger.allocatable);
  writer.u64(value.ledger.reclaimable);
  writer.u64(value.ledger.oversubscribed);
  writer.u64(value.ledger.authorized_extension);
  return writer.buffer();
}

Expected<LedgerReport> decode_ledger_report(ByteSpan payload) {
  Reader reader(payload, message_limits());
  LedgerReport out;
  auto path = reader.id128();
  if (!path.ok()) return path.status();
  out.path = PathId::from_raw(path.value());
  const auto field = [&reader](Amount& target) -> Status {
    auto value = reader.u64();
    if (!value.ok()) {
      return value.status();
    }
    target = value.value();
    return Status::Ok;
  };
  Status status = field(out.ledger.authoritative_usable);
  if (status != Status::Ok) return status;
  status = field(out.ledger.committed);
  if (status != Status::Ok) return status;
  status = field(out.ledger.withdrawing);
  if (status != Status::Ok) return status;
  status = field(out.ledger.reserved);
  if (status != Status::Ok) return status;
  status = field(out.ledger.protected_headroom);
  if (status != Status::Ok) return status;
  status = field(out.ledger.unavailable);
  if (status != Status::Ok) return status;
  status = field(out.ledger.free);
  if (status != Status::Ok) return status;
  status = field(out.ledger.allocatable);
  if (status != Status::Ok) return status;
  status = field(out.ledger.reclaimable);
  if (status != Status::Ok) return status;
  status = field(out.ledger.oversubscribed);
  if (status != Status::Ok) return status;
  status = field(out.ledger.authorized_extension);
  if (status != Status::Ok) return status;
  if (reader.require_end() != Status::Ok) {
    return Outcome(Status::Invalid, "ledger report has trailing bytes");
  }
  return out;
}

std::vector<Byte> encode_digest_report(const DigestReport& value) {
  Writer writer(message_limits());
  writer.digest(value.state_digest);
  writer.str(value.policy_digest);
  writer.u64(value.last_arbitration);
  writer.u64(value.sites);
  writer.u64(value.paths);
  writer.u64(value.grants);
  return writer.buffer();
}

Expected<DigestReport> decode_digest_report(ByteSpan payload) {
  Reader reader(payload, message_limits());
  DigestReport out;
  auto digest = reader.digest();
  if (!digest.ok()) return digest.status();
  out.state_digest = digest.value();
  auto policy = reader.str();
  if (!policy.ok()) return policy.status();
  out.policy_digest = policy.value();
  auto arb = reader.u64();
  if (!arb.ok()) return arb.status();
  out.last_arbitration = arb.value();
  auto sites = reader.u64();
  if (!sites.ok()) return sites.status();
  out.sites = static_cast<std::size_t>(sites.value());
  auto paths = reader.u64();
  if (!paths.ok()) return paths.status();
  out.paths = static_cast<std::size_t>(paths.value());
  auto grants = reader.u64();
  if (!grants.ok()) return grants.status();
  out.grants = static_cast<std::size_t>(grants.value());
  if (reader.require_end() != Status::Ok) {
    return Outcome(Status::Invalid, "digest report has trailing bytes");
  }
  return out;
}

std::vector<Byte> encode_u64_body(std::uint64_t value) {
  Writer writer(message_limits());
  writer.u64(value);
  return writer.buffer();
}

Expected<std::uint64_t> decode_u64_body(ByteSpan payload) {
  Reader reader(payload, message_limits());
  auto value = reader.u64();
  if (!value.ok()) return value.status();
  if (reader.require_end() != Status::Ok) {
    return Outcome(Status::Invalid, "u64 body has trailing bytes");
  }
  return value.value();
}

std::vector<Byte> encode_id_body(const Id128& value) {
  Writer writer(message_limits());
  writer.id128(value);
  return writer.buffer();
}

Expected<Id128> decode_id_body(ByteSpan payload) {
  Reader reader(payload, message_limits());
  auto value = reader.id128();
  if (!value.ok()) return value.status();
  if (reader.require_end() != Status::Ok) {
    return Outcome(Status::Invalid, "id body has trailing bytes");
  }
  return value.value();
}

}  // namespace isf
