// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Framing and messages for the inter-site fabric protocol.
//
// Framing is length prefixed with the length validated against a configured
// bound *before* any allocation, plus a CRC-32C over the payload. The decoder is
// written to reject hostile framing: absurd lengths, truncated frames, bad
// magic, unexpected flags, and payloads that do not match their checksum are all
// refused without allocating attacker-controlled amounts of memory.

#ifndef ISF_PROTOCOL_HPP
#define ISF_PROTOCOL_HPP

#include "isf/authority.hpp"
#include "isf/capacity.hpp"
#include "isf/digest.hpp"
#include "isf/ids.hpp"
#include "isf/model.hpp"
#include "isf/policy.hpp"
#include "isf/status.hpp"
#include "isf/store.hpp"
#include "isf/version.hpp"
#include "isf/wire.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

namespace isf {

/// Frame layout: magic(4) length(4) crc32c(4) flags(4) payload(length).
inline constexpr std::uint32_t kFrameMagic = 0x31465349U;  // bytes 'I' 'S' 'F' '1'
inline constexpr std::size_t kFrameHeaderBytes = 16;
inline constexpr std::size_t kDefaultMaxFrameBytes = 1U << 20;
inline constexpr std::size_t kAbsoluteMaxFrameBytes = 64U << 20;

enum class MessageType : std::uint16_t {
  Invalid = 0,
  Hello = 1,
  HelloAck = 2,
  ErrorReply = 3,
  StatusRequest = 10,
  SiteRegister = 20,
  SiteHeartbeat = 21,
  SiteSetState = 22,
  PathRegister = 30,
  PathSetState = 31,
  CapacityAttest = 32,
  Oversubscribe = 33,
  PolicyInstall = 40,
  EpochBump = 41,
  GrantPropose = 50,
  GrantEvaluate = 51,
  GrantReserve = 52,
  GrantActivate = 53,
  GrantDegrade = 54,
  GrantWithdraw = 55,
  GrantRetire = 56,
  GrantCancel = 57,
  GrantAcknowledge = 58,
  GrantVerify = 59,
  GrantReconcile = 60,
  ListSites = 70,
  ListPaths = 71,
  ListGrants = 72,
  LedgerRequest = 73,
  DigestRequest = 74,
  SnapshotRequest = 75,
  TickRequest = 76,
  ShutdownRequest = 77,
  MutationReply = 100,
  StatusReply = 101,
  SitesReply = 102,
  PathsReply = 103,
  GrantsReply = 104,
  LedgerReply = 105,
  DigestReply = 106,
  SnapshotReply = 107,
  ShutdownReply = 108,
};

[[nodiscard]] const char* message_type_name(MessageType type) noexcept;
[[nodiscard]] bool message_type_is_request(MessageType type) noexcept;
[[nodiscard]] bool message_type_is_reply(MessageType type) noexcept;

/// Error codes carried by the frame layer, distinct from authority statuses.
enum class FrameError : std::uint8_t {
  Ok = 0,
  ShortHeader,
  BadMagic,
  LengthTooLarge,
  LengthZero,
  ChecksumMismatch,
  UnexpectedFlags,
  TruncatedPayload,
  Closed,
  TimedOut,
  IoError,
};

[[nodiscard]] const char* frame_error_name(FrameError e) noexcept;

/// Encode a frame into a fresh buffer.
[[nodiscard]] std::vector<Byte> encode_frame(ByteSpan payload);

/// Incremental frame decoder. Feed it bytes; pull complete frames.
class FrameDecoder {
 public:
  explicit FrameDecoder(std::size_t max_frame_bytes = kDefaultMaxFrameBytes)
      : max_frame_bytes_(max_frame_bytes) {}

  /// Append received bytes. The buffer is bounded: a peer that never completes a
  /// frame cannot make the decoder grow past one maximum frame plus one header.
  [[nodiscard]] Status push(ByteSpan data);

  /// Extract one complete payload. Returns Status::NotFound when more bytes are
  /// required, and a specific status when the stream is unusable.
  [[nodiscard]] Expected<std::vector<Byte>> next();

  [[nodiscard]] std::size_t buffered() const noexcept { return buffer_.size() - cursor_; }
  [[nodiscard]] FrameError last_error() const noexcept { return last_error_; }
  void reset();

 private:
  std::size_t max_frame_bytes_{kDefaultMaxFrameBytes};
  std::vector<Byte> buffer_{};
  std::size_t cursor_{0};
  FrameError last_error_{FrameError::Ok};
  bool failed_{false};
};

/// A protocol request. The payload is the canonical encoding of the message
/// body; the envelope fields are common to every request.
struct Request {
  std::uint16_t protocol_version{kWireProtocolVersion};
  MessageType type{MessageType::Invalid};
  std::uint64_t session_seq{0};
  RequestId id{};
  std::vector<Byte> payload{};
};

/// A protocol reply.
struct Response {
  std::uint16_t protocol_version{kWireProtocolVersion};
  MessageType type{MessageType::Invalid};
  std::uint64_t session_seq{0};
  RequestId id{};
  Status status{Status::Ok};
  std::string detail{};
  std::vector<Byte> payload{};
};

/// Envelope codecs. Both validate the protocol version and bound every field.
[[nodiscard]] std::vector<Byte> encode_request(const Request& request);
[[nodiscard]] Expected<Request> decode_request(ByteSpan payload,
                                               const WireLimits& limits = WireLimits{});
[[nodiscard]] std::vector<Byte> encode_response(const Response& response);
[[nodiscard]] Expected<Response> decode_response(ByteSpan payload,
                                                 const WireLimits& limits = WireLimits{});

// ---- message bodies --------------------------------------------------------

struct StatusReport {
  Version version{};
  std::uint16_t wire_protocol{kWireProtocolVersion};
  Incarnation incarnation{};
  Epoch epoch{};
  Policy policy{};
  RecoveryFidelity store_fidelity{RecoveryFidelity::Missing};
  StoreId store_id{};
  std::uint32_t store_format_version{0};
  std::size_t store_records{0};
  std::size_t store_bytes{0};
  std::size_t ambiguous_intents{0};
  bool store_servable{false};
  bool store_truncated_on_open{false};
  std::uint64_t uptime_ms{0};
  std::uint64_t mutations_applied{0};
  std::uint64_t mutations_refused{0};
  std::uint64_t mutations_failed{0};
  std::uint64_t connections_accepted{0};
  std::uint64_t frames_decoded{0};
  std::uint64_t frames_rejected{0};
  std::uint64_t duplicate_requests{0};
  std::uint64_t stale_requests{0};
  std::size_t sites{0};
  std::size_t paths{0};
  std::size_t grants{0};
  CapacityLedger aggregate{};
  Digest256 state_digest{};
  std::string detail{};
};

struct MutationReport {
  ArbSeq arbitration{};
  ObjectKind primary_kind{ObjectKind::Grant};
  Id128 primary_key{};
  std::uint32_t total_changes{0};
  bool truncated{false};
  std::vector<StateChange> changes{};
};

struct ListFilter {
  bool include_terminal{true};
  std::uint32_t limit{4096};
  PathId path{};
  SiteId site{};
};

struct LedgerReport {
  PathId path{};
  CapacityLedger ledger{};
};

struct DigestReport {
  Digest256 state_digest{};
  std::string policy_digest{};
  std::uint64_t last_arbitration{0};
  std::size_t sites{0};
  std::size_t paths{0};
  std::size_t grants{0};
};

struct HelloRequest {
  std::uint16_t protocol_version{kWireProtocolVersion};
  Id128 client_nonce{};
  std::string client_kind{};
  std::uint32_t max_frame_bytes{static_cast<std::uint32_t>(kDefaultMaxFrameBytes)};
};

struct HelloReply {
  std::uint16_t protocol_version{kWireProtocolVersion};
  SessionId session{};
  Incarnation server_incarnation{};
  Epoch epoch{};
  std::uint32_t max_frame_bytes{static_cast<std::uint32_t>(kDefaultMaxFrameBytes)};
  RecoveryFidelity store_fidelity{RecoveryFidelity::Missing};
  bool store_servable{false};
  bool durable_writes{false};
  std::uint32_t format_version{kStoreFormatVersion};
};

// Body codecs.
[[nodiscard]] std::vector<Byte> encode_hello_request(const HelloRequest& value);
[[nodiscard]] Expected<HelloRequest> decode_hello_request(ByteSpan payload);
[[nodiscard]] std::vector<Byte> encode_hello_reply(const HelloReply& value);
[[nodiscard]] Expected<HelloReply> decode_hello_reply(ByteSpan payload);

[[nodiscard]] std::vector<Byte> encode_site_registration(const SiteRegistration& value);
[[nodiscard]] Expected<SiteRegistration> decode_site_registration(ByteSpan payload);
[[nodiscard]] std::vector<Byte> encode_heartbeat(const SiteHeartbeat& value);
[[nodiscard]] Expected<SiteHeartbeat> decode_heartbeat(ByteSpan payload);
[[nodiscard]] std::vector<Byte> encode_path_registration(const PathRegistration& value);
[[nodiscard]] Expected<PathRegistration> decode_path_registration(ByteSpan payload);

[[nodiscard]] std::vector<Byte> encode_grant_proposal(const GrantProposal& value);
[[nodiscard]] Expected<GrantProposal> decode_grant_proposal(ByteSpan payload);
[[nodiscard]] std::vector<Byte> encode_grant_operation(const GrantOperation& value);
[[nodiscard]] Expected<GrantOperation> decode_grant_operation(ByteSpan payload);
[[nodiscard]] std::vector<Byte> encode_acknowledgement(const GrantAcknowledgement& value);
[[nodiscard]] Expected<GrantAcknowledgement> decode_acknowledgement(ByteSpan payload);
[[nodiscard]] std::vector<Byte> encode_verification(const GrantVerification& value);
[[nodiscard]] Expected<GrantVerification> decode_verification_message(ByteSpan payload);

/// Composite request bodies that carry more than one record.
[[nodiscard]] std::vector<Byte> encode_site_state_request(const SiteId& site, SiteState state,
                                                          std::string_view reason,
                                                          std::uint64_t now_ms);
[[nodiscard]] Expected<std::tuple<SiteId, SiteState, std::string, std::uint64_t>>
decode_site_state_request(ByteSpan payload);
[[nodiscard]] std::vector<Byte> encode_path_state_request(const PathId& path, PathState state,
                                                          std::string_view reason,
                                                          std::uint64_t now_ms);
[[nodiscard]] Expected<std::tuple<PathId, PathState, std::string, std::uint64_t>>
decode_path_state_request(ByteSpan payload);
[[nodiscard]] std::vector<Byte> encode_policy_install_request(const Policy& policy,
                                                              const PrincipalId& principal);
[[nodiscard]] Expected<std::pair<Policy, PrincipalId>> decode_policy_install_request(
    ByteSpan payload);
[[nodiscard]] std::vector<Byte> encode_epoch_bump_request(Epoch epoch,
                                                          const PrincipalId& principal);
[[nodiscard]] Expected<std::pair<Epoch, PrincipalId>> decode_epoch_bump_request(ByteSpan payload);
[[nodiscard]] std::vector<Byte> encode_reconcile_request(const GrantOperation& op, GrantState target,
                                                         const PrincipalId& principal);
[[nodiscard]] Expected<std::tuple<GrantOperation, GrantState, PrincipalId>> decode_reconcile_request(
    ByteSpan payload);

[[nodiscard]] std::vector<Byte> encode_list_filter(const ListFilter& value);
[[nodiscard]] Expected<ListFilter> decode_list_filter(ByteSpan payload);

[[nodiscard]] std::vector<Byte> encode_mutation_report(const MutationReport& value);
[[nodiscard]] Expected<MutationReport> decode_mutation_report(ByteSpan payload,
                                                              const WireLimits& limits = WireLimits{});
[[nodiscard]] std::vector<Byte> encode_status_report(const StatusReport& value);
[[nodiscard]] Expected<StatusReport> decode_status_report(ByteSpan payload);

[[nodiscard]] std::vector<Byte> encode_site_list(const std::vector<SiteRecord>& value);
[[nodiscard]] Expected<std::vector<SiteRecord>> decode_site_list(ByteSpan payload);
[[nodiscard]] std::vector<Byte> encode_path_list(const std::vector<PathRecord>& value);
[[nodiscard]] Expected<std::vector<PathRecord>> decode_path_list(ByteSpan payload);
[[nodiscard]] std::vector<Byte> encode_grant_list(const std::vector<GrantRecord>& value);
[[nodiscard]] Expected<std::vector<GrantRecord>> decode_grant_list(ByteSpan payload);
[[nodiscard]] std::vector<Byte> encode_ledger_report(const LedgerReport& value);
[[nodiscard]] Expected<LedgerReport> decode_ledger_report(ByteSpan payload);
[[nodiscard]] std::vector<Byte> encode_digest_report(const DigestReport& value);
[[nodiscard]] Expected<DigestReport> decode_digest_report(ByteSpan payload);

[[nodiscard]] std::vector<Byte> encode_u64_body(std::uint64_t value);
[[nodiscard]] Expected<std::uint64_t> decode_u64_body(ByteSpan payload);
[[nodiscard]] std::vector<Byte> encode_id_body(const Id128& value);
[[nodiscard]] Expected<Id128> decode_id_body(ByteSpan payload);

}  // namespace isf

#endif  // ISF_PROTOCOL_HPP
