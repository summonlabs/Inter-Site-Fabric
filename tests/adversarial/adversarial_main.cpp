// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Adversarial tests. Everything here attacks the runtime deliberately: hostile
// framing over a real socket, malformed envelopes, stale authority, extreme
// values, duplicated identities, and damaged durable state.

#include "process.hpp"
#include "testkit.hpp"

#include "isf/clock.hpp"
#include "isf/digest.hpp"
#include "isf/net.hpp"

#include <array>
#include <cstdio>
#include <string>
#include <vector>

using namespace isf;
using namespace isf::test;

int main(int argc, char** argv) { return run_all(argc, argv, "isf_adversarial_tests"); }

namespace {

/// Read one frame from a raw socket, or report why not.
Expected<std::vector<Byte>> read_frame(Socket& socket, std::size_t max_bytes, std::uint64_t bound_ms) {
  FrameDecoder decoder(max_bytes);
  std::array<Byte, 8192> buffer{};
  const std::uint64_t deadline = monotonic_ms() + bound_ms;
  for (;;) {
    auto payload = decoder.next();
    if (payload.ok()) {
      return payload.value();
    }
    if (payload.status() != Status::NotFound) {
      return payload.status();
    }
    if (monotonic_ms() > deadline) {
      return Outcome(Status::Unavailable, "no frame arrived within the observation bound");
    }
    std::size_t received = 0;
    const IoStatus status = socket.recv_some(buffer.data(), buffer.size(), received);
    if (status == IoStatus::PeerClosed) {
      return Outcome(Status::Unavailable, "peer closed before sending a frame");
    }
    if (status != IoStatus::Ok) {
      return Outcome(Status::Unavailable, std::string("receive failed: ") + io_status_name(status));
    }
    const Status pushed = decoder.push(ByteSpan(buffer.data(), received));
    if (pushed != Status::Ok) {
      return pushed;
    }
  }
}

/// Perform a bare handshake so a test can send requests directly.
Expected<Socket> handshake(LocalFabric& fabric) {
  ClientOptions options;
  options.endpoint = fabric.endpoint();
  Socket socket;
  const Status connected = isf::connect(options.endpoint, 5000, socket);
  if (connected != Status::Ok) {
    return connected;
  }
  (void)socket.set_timeouts(5000, 5000);
  HelloRequest hello;
  hello.client_nonce = Id128::from_seed(1, 1);
  hello.client_kind = "raw";
  const std::vector<Byte> body = encode_hello_request(hello);
  const std::vector<Byte> frame = encode_frame(ByteSpan(body.data(), body.size()));
  std::size_t written = 0;
  if (socket.send_all(ByteSpan(frame.data(), frame.size()), written) != IoStatus::Ok) {
    return Outcome(Status::Unavailable, "hello could not be sent");
  }
  auto reply = read_frame(socket, kDefaultMaxFrameBytes, 5000);
  if (!reply.ok()) {
    return reply.status();
  }
  auto response = decode_response(ByteSpan(reply.value().data(), reply.value().size()));
  if (!response.ok() || response.value().type != MessageType::HelloAck) {
    return Outcome(Status::Invalid, "handshake was not acknowledged");
  }
  return socket;
}

[[nodiscard]] std::vector<Byte> read_file_bytes(const std::string& path) {
  std::vector<Byte> out;
  std::FILE* fp = std::fopen(path.c_str(), "rb");
  if (fp == nullptr) {
    return out;
  }
  std::array<Byte, 4096> buffer{};
  std::size_t got = 0;
  while ((got = std::fread(buffer.data(), 1, buffer.size(), fp)) > 0) {
    out.insert(out.end(), buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(got));
  }
  std::fclose(fp);
  return out;
}

void write_file_bytes(const std::string& path, const std::vector<Byte>& bytes) {
  std::FILE* fp = std::fopen(path.c_str(), "wb");
  if (fp == nullptr) {
    return;
  }
  if (!bytes.empty()) {
    (void)std::fwrite(bytes.data(), 1, bytes.size(), fp);
  }
  std::fclose(fp);
}

void send_raw(Socket& socket, ByteSpan bytes) {
  std::size_t written = 0;
  (void)socket.send_all(bytes, written);
}

/// The server must still be healthy after an attack.
void expect_server_alive(LocalFabric& fabric) {
  auto client = fabric.client("alive-check");
  ISF_REQUIRE_OK(client);
  auto status = client.value().status();
  ISF_REQUIRE_OK(status);
}

}  // namespace

ISF_TEST(adversarial, hostile_frames_over_a_real_socket) {
  ScratchDir scratch("adv-frames");
  auto fabric = LocalFabric::start(scratch.file("state.isfstore"));
  ISF_REQUIRE_OK(fabric);

  // 1. Bad magic.
  {
    auto socket = handshake(**fabric);
    ISF_REQUIRE_OK(socket);
    std::vector<Byte> garbage(kFrameHeaderBytes, 0xAB);
    send_raw(socket.value(), ByteSpan(garbage.data(), garbage.size()));
    socket.value().close();
  }
  expect_server_alive(**fabric);

  // 2. Declared length far beyond the negotiated bound.
  {
    auto socket = handshake(**fabric);
    ISF_REQUIRE_OK(socket);
    std::vector<Byte> header(kFrameHeaderBytes, 0);
    const std::uint32_t magic = 0x31465349U;
    for (unsigned i = 0; i < 4; ++i) {
      header[i] = static_cast<Byte>((magic >> (i * 8U)) & 0xFFU);
    }
    const std::uint32_t length = 0x7FFFFFFFU;
    for (unsigned i = 0; i < 4; ++i) {
      header[4 + i] = static_cast<Byte>((length >> (i * 8U)) & 0xFFU);
    }
    send_raw(socket.value(), ByteSpan(header.data(), header.size()));
    // The only acceptable answers are an error frame or a closed connection.
    auto reply = read_frame(socket.value(), kDefaultMaxFrameBytes, 5000);
    if (reply.ok()) {
      auto decoded = decode_response(ByteSpan(reply.value().data(), reply.value().size()));
      ISF_CHECK(!decoded.ok() || decoded.value().status != Status::Ok);
    }
    socket.value().close();
  }
  expect_server_alive(**fabric);

  // 3. Valid header, corrupted payload checksum.
  {
    auto socket = handshake(**fabric);
    ISF_REQUIRE_OK(socket);
    Request request;
    request.type = MessageType::StatusRequest;
    request.session_seq = 1;
    request.id = RequestId::from_seed(2, 2);
    std::vector<Byte> frame = encode_frame(encode_request(request));
    frame.back() = static_cast<Byte>(frame.back() ^ 0xFFU);
    send_raw(socket.value(), ByteSpan(frame.data(), frame.size()));
    socket.value().close();
  }
  expect_server_alive(**fabric);

  // 4. Truncated frame followed by an immediate close.
  {
    auto socket = handshake(**fabric);
    ISF_REQUIRE_OK(socket);
    std::vector<Byte> frame = encode_frame(encode_request(Request{}));
    send_raw(socket.value(), ByteSpan(frame.data(), 8));
    socket.value().close();
  }
  expect_server_alive(**fabric);

  // 5. A frame whose payload is not a valid request envelope.
  {
    auto socket = handshake(**fabric);
    ISF_REQUIRE_OK(socket);
    const std::string nonsense = "this is definitely not a request envelope";
    std::vector<Byte> frame =
        encode_frame(ByteSpan(reinterpret_cast<const Byte*>(nonsense.data()), nonsense.size()));
    send_raw(socket.value(), ByteSpan(frame.data(), frame.size()));
    auto reply = read_frame(socket.value(), kDefaultMaxFrameBytes, 5000);
    ISF_REQUIRE_OK(reply);
    auto response = decode_response(ByteSpan(reply.value().data(), reply.value().size()));
    ISF_REQUIRE_OK(response);
    ISF_CHECK(response.value().status != Status::Ok);
    socket.value().close();
  }
  expect_server_alive(**fabric);
}

ISF_TEST(adversarial, protocol_version_mismatch_is_refused) {
  ScratchDir scratch("adv-version");
  auto fabric = LocalFabric::start(scratch.file("state.isfstore"));
  ISF_REQUIRE_OK(fabric);

  Socket socket;
  ISF_REQUIRE_STATUS_EQ(isf::connect(fabric->get()->endpoint(), 5000, socket), Status::Ok);
  (void)socket.set_timeouts(5000, 5000);
  HelloRequest hello;
  hello.protocol_version = static_cast<std::uint16_t>(kWireProtocolVersion + 7);
  hello.client_nonce = Id128::from_seed(3, 3);
  hello.client_kind = "future";
  const std::vector<Byte> body = encode_hello_request(hello);
  const std::vector<Byte> frame = encode_frame(ByteSpan(body.data(), body.size()));
  send_raw(socket, ByteSpan(frame.data(), frame.size()));
  auto reply = read_frame(socket, kDefaultMaxFrameBytes, 5000);
  ISF_REQUIRE_OK(reply);
  auto response = decode_response(ByteSpan(reply.value().data(), reply.value().size()));
  ISF_REQUIRE_OK(response);
  ISF_REQUIRE_EQ(static_cast<int>(response.value().status),
                 static_cast<int>(Status::VersionMismatch));
  socket.close();

  // The daemon survives and still serves a correct client.
  auto client = fabric->get()->client();
  ISF_REQUIRE_OK(client);
  ISF_REQUIRE_OK(client.value().status());
}

ISF_TEST(adversarial, replayed_session_sequence_is_rejected) {
  ScratchDir scratch("adv-replay");
  auto fabric = LocalFabric::start(scratch.file("state.isfstore"));
  ISF_REQUIRE_OK(fabric);

  auto socket = handshake(**fabric);
  ISF_REQUIRE_OK(socket);

  Request request;
  request.type = MessageType::StatusRequest;
  request.session_seq = 5;
  request.id = RequestId::from_seed(4, 4);
  const std::vector<Byte> frame = encode_frame(encode_request(request));
  send_raw(socket.value(), ByteSpan(frame.data(), frame.size()));
  auto first = read_frame(socket.value(), kDefaultMaxFrameBytes, 5000);
  ISF_REQUIRE_OK(first);
  auto first_response = decode_response(ByteSpan(first.value().data(), first.value().size()));
  ISF_REQUIRE_OK(first_response);
  ISF_REQUIRE_EQ(static_cast<int>(first_response.value().status), static_cast<int>(Status::Ok));

  // Replay the identical envelope.
  send_raw(socket.value(), ByteSpan(frame.data(), frame.size()));
  auto second = read_frame(socket.value(), kDefaultMaxFrameBytes, 5000);
  ISF_REQUIRE_OK(second);
  auto second_response = decode_response(ByteSpan(second.value().data(), second.value().size()));
  ISF_REQUIRE_OK(second_response);
  ISF_REQUIRE_EQ(static_cast<int>(second_response.value().status),
                 static_cast<int>(Status::Duplicate));

  // An older sequence number is also refused.
  request.session_seq = 2;
  const std::vector<Byte> older = encode_frame(encode_request(request));
  send_raw(socket.value(), ByteSpan(older.data(), older.size()));
  auto third = read_frame(socket.value(), kDefaultMaxFrameBytes, 5000);
  ISF_REQUIRE_OK(third);
  auto third_response = decode_response(ByteSpan(third.value().data(), third.value().size()));
  ISF_REQUIRE_OK(third_response);
  ISF_REQUIRE_EQ(static_cast<int>(third_response.value().status),
                 static_cast<int>(Status::Duplicate));
  socket.value().close();
}

ISF_TEST(adversarial, invalid_utf8_and_oversized_names_are_refused) {
  ScratchDir scratch("adv-utf8");
  auto fabric = LocalFabric::start(scratch.file("state.isfstore"));
  ISF_REQUIRE_OK(fabric);

  auto socket = handshake(**fabric);
  ISF_REQUIRE_OK(socket);

  // Build a site registration envelope by hand with an invalid UTF-8 name.
  Writer writer;
  writer.u16(kWireProtocolVersion);
  writer.u16(static_cast<std::uint16_t>(MessageType::SiteRegister));
  writer.u64(1);
  writer.id128(RequestId::from_seed(9, 9).raw());
  Writer body;
  body.id128(site_from_name("bad").raw());
  const std::string invalid = "bad\xC3\x28name";
  body.u32(static_cast<std::uint32_t>(invalid.size()));
  for (const char c : invalid) {
    body.u8(static_cast<Byte>(c));
  }
  body.u64(0);
  body.id128(Incarnation::from_seed(1, 1).raw());
  body.u64(1);
  body.u64(1000);
  writer.bytes(body.span());
  const std::vector<Byte> frame = encode_frame(writer.span());
  send_raw(socket.value(), ByteSpan(frame.data(), frame.size()));
  auto reply = read_frame(socket.value(), kDefaultMaxFrameBytes, 5000);
  ISF_REQUIRE_OK(reply);
  auto response = decode_response(ByteSpan(reply.value().data(), reply.value().size()));
  ISF_REQUIRE_OK(response);
  ISF_REQUIRE(response.value().status != Status::Ok);
  socket.value().close();

  // A name longer than the protocol's string bound is refused as well.
  auto client = fabric->get()->client();
  ISF_REQUIRE_OK(client);
  SiteDescriptor descriptor;
  descriptor.id = site_from_name("long-name");
  descriptor.name = std::string(5000, 'n');
  auto registered = client.value().register_site(
      descriptor, Incarnation::from_seed(1, 1), client.value().hello().epoch, now_ms());
  ISF_CHECK(!registered.ok());
}

ISF_TEST(adversarial, extreme_amounts_never_wrap) {
  ScratchDir scratch("adv-extreme");
  auto fabric = LocalFabric::start(scratch.file("state.isfstore"));
  ISF_REQUIRE_OK(fabric);
  auto client = fabric->get()->client();
  ISF_REQUIRE_OK(client);
  auto fixture = setup_fabric(client.value(), "extreme", 1000);
  ISF_REQUIRE_OK(fixture);

  GrantProposal proposal;
  proposal.request = RequestId::from_seed(1, 1);
  proposal.holder = fixture.value().a;
  proposal.holder_incarnation = fixture.value().a_incarnation;
  proposal.holder_generation = fixture.value().a_generation;
  proposal.path = fixture.value().path;
  proposal.amount = kAmountMax;
  proposal.duration_ms = 60000;
  proposal.now_ms = now_ms();
  auto proposed = client.value().propose_grant(proposal);
  ISF_REQUIRE_OK(proposed);
  auto grant = extract_grant(proposed.value());
  ISF_REQUIRE_OK(grant);

  GrantOperation op;
  op.grant = grant.value().id;
  op.actor = fixture.value().a;
  op.actor_incarnation = fixture.value().a_incarnation;
  op.epoch = client.value().hello().epoch;
  op.now_ms = now_ms();
  auto evaluated = client.value().evaluate_grant(op);
  ISF_REQUIRE_OK(evaluated);
  auto reserved = client.value().reserve_grant(op);
  ISF_REQUIRE(!reserved.ok());
  ISF_REQUIRE_EQ(static_cast<int>(reserved.status()), static_cast<int>(Status::Exhausted));

  // The ledger is untouched by the refused attempt.
  auto ledger = client.value().ledger(fixture.value().path);
  ISF_REQUIRE_OK(ledger);
  ISF_REQUIRE_EQ(ledger.value().reserved, Amount{0});
  ISF_REQUIRE_EQ(ledger.value().verify_closure(), Status::Ok);
}

ISF_TEST(adversarial, duplicated_request_identity_is_refused) {
  ScratchDir scratch("adv-duplicate");
  auto fabric = LocalFabric::start(scratch.file("state.isfstore"));
  ISF_REQUIRE_OK(fabric);
  auto client = fabric->get()->client();
  ISF_REQUIRE_OK(client);
  auto fixture = setup_fabric(client.value(), "duplicate", 1000);
  ISF_REQUIRE_OK(fixture);

  GrantProposal proposal;
  proposal.request = RequestId::from_seed(7, 7);
  proposal.holder = fixture.value().a;
  proposal.holder_incarnation = fixture.value().a_incarnation;
  proposal.holder_generation = fixture.value().a_generation;
  proposal.path = fixture.value().path;
  proposal.amount = 10;
  proposal.duration_ms = 60000;
  proposal.now_ms = now_ms();

  ISF_REQUIRE_OK(client.value().propose_grant(proposal));
  auto second = client.value().propose_grant(proposal);
  ISF_REQUIRE(!second.ok());
  ISF_REQUIRE_EQ(static_cast<int>(second.status()), static_cast<int>(Status::Duplicate));

  auto grants = client.value().list_grants();
  ISF_REQUIRE_OK(grants);
  ISF_REQUIRE_EQ(grants.value().size(), std::size_t{1});
}

ISF_TEST(adversarial, stale_generations_and_epochs_are_refused) {
  ScratchDir scratch("adv-stale");
  auto fabric = LocalFabric::start(scratch.file("state.isfstore"));
  ISF_REQUIRE_OK(fabric);
  auto client = fabric->get()->client();
  ISF_REQUIRE_OK(client);
  auto fixture = setup_fabric(client.value(), "stale", 5000);
  ISF_REQUIRE_OK(fixture);

  auto grant = request_grant(client.value(), fixture.value(), true, 100);
  ISF_REQUIRE_OK(grant);
  ISF_REQUIRE(grant.value().state == GrantState::Active);

  // A heartbeat with a superseded epoch is stale.
  SiteHeartbeat heartbeat;
  heartbeat.id = fixture.value().a;
  heartbeat.incarnation = fixture.value().a_incarnation;
  heartbeat.generation = fixture.value().a_generation;
  heartbeat.epoch = Epoch{client.value().hello().epoch.value + 5};
  heartbeat.now_ms = now_ms();
  auto beat = client.value().heartbeat(heartbeat);
  ISF_REQUIRE(!beat.ok());
  ISF_REQUIRE_EQ(static_cast<int>(beat.status()), static_cast<int>(Status::Stale));

  // A heartbeat from a superseded incarnation is fenced.
  SiteHeartbeat alien = heartbeat;
  alien.epoch = client.value().hello().epoch;
  alien.incarnation = Incarnation::from_seed(0xDEAD, 1);
  auto alien_beat = client.value().heartbeat(alien);
  ISF_REQUIRE(!alien_beat.ok());
  ISF_REQUIRE_EQ(static_cast<int>(alien_beat.status()), static_cast<int>(Status::Fenced));

  // Path registration with a generation that does not advance is stale.
  PathRegistration repeat;
  repeat.descriptor.id = fixture.value().path;
  repeat.descriptor.name = "stale-path";
  repeat.descriptor.endpoint_a = fixture.value().a;
  repeat.descriptor.endpoint_b = fixture.value().b;
  repeat.path_generation = fixture.value().path_generation;
  repeat.state = PathState::Up;
  repeat.now_ms = now_ms();
  auto repeated = client.value().register_path(repeat);
  ISF_REQUIRE(!repeated.ok());
  ISF_REQUIRE_EQ(static_cast<int>(repeated.status()), static_cast<int>(Status::Stale));

  // A capacity attestation that does not advance the capacity generation is
  // stale, and so is one bound to a superseded path generation.
  CapacityAttestation attestation;
  attestation.id = AttestationId::random();
  attestation.path = fixture.value().path;
  attestation.path_generation = fixture.value().path_generation;
  attestation.capacity_generation = fixture.value().capacity_generation;
  attestation.usable = 4000;
  attestation.issuer = client.value().hello().server_incarnation;
  attestation.epoch = client.value().hello().epoch;
  attestation.principal = principal_from_name("operator");
  attestation.observed_at_ms = now_ms();
  attestation.evidence = Digest256::of(ByteSpan{});
  auto stale_attestation = client.value().attest_capacity(attestation);
  ISF_REQUIRE(!stale_attestation.ok());
  ISF_REQUIRE_EQ(static_cast<int>(stale_attestation.status()), static_cast<int>(Status::Stale));

  // An attestation without evidence is incomplete, never accepted.
  CapacityAttestation no_evidence = attestation;
  no_evidence.capacity_generation = Generation{fixture.value().capacity_generation.value + 1};
  no_evidence.evidence = Digest256{};
  auto incomplete = client.value().attest_capacity(no_evidence);
  ISF_REQUIRE(!incomplete.ok());
  ISF_REQUIRE_EQ(static_cast<int>(incomplete.status()), static_cast<int>(Status::Incomplete));
}

ISF_TEST(adversarial, epoch_bump_invalidates_live_grants) {
  ScratchDir scratch("adv-epoch");
  auto fabric = LocalFabric::start(scratch.file("state.isfstore"));
  ISF_REQUIRE_OK(fabric);
  auto client = fabric->get()->client();
  ISF_REQUIRE_OK(client);
  auto fixture = setup_fabric(client.value(), "epoch", 5000);
  ISF_REQUIRE_OK(fixture);
  auto grant = request_grant(client.value(), fixture.value(), true, 250);
  ISF_REQUIRE_OK(grant);
  ISF_REQUIRE(grant.value().state == GrantState::Active);

  ISF_REQUIRE_OK(client.value().bump_epoch(Epoch{2}, principal_from_name("operator")));
  auto grants = client.value().list_grants();
  ISF_REQUIRE_OK(grants);
  ISF_REQUIRE_EQ(grants.value().size(), std::size_t{1});
  ISF_REQUIRE(grants.value().front().state == GrantState::Withdrawing);
  // The capacity stays committed: an epoch change never silently frees it.
  auto ledger = client.value().ledger(fixture.value().path);
  ISF_REQUIRE_OK(ledger);
  ISF_REQUIRE_EQ(ledger.value().withdrawing, Amount{250});
  ISF_REQUIRE_EQ(ledger.value().committed, Amount{0});
  // The withdrawn capacity is blocked, but the rest of the path is still
  // allocatable for grants bound to the new epoch.
  ISF_REQUIRE_EQ(ledger.value().allocatable,
                 Amount{5000} - ledger.value().protected_headroom - Amount{250});
  ISF_REQUIRE_EQ(ledger.value().verify_closure(), Status::Ok);
}

ISF_TEST(adversarial, damaged_durable_state_is_never_served_as_authority) {
  ScratchDir scratch("adv-corrupt");
  const std::string path = scratch.file("state.isfstore");

  // Build a durable state with a live grant.
  {
    auto fabric = LocalFabric::start(path);
    ISF_REQUIRE_OK(fabric);
    auto client = fabric->get()->client();
    ISF_REQUIRE_OK(client);
    auto fixture = setup_fabric(client.value(), "corrupt", 1000);
    ISF_REQUIRE_OK(fixture);
    auto grant = request_grant(client.value(), fixture.value(), true, 200);
    ISF_REQUIRE_OK(grant);
    fabric->get()->stop();
  }
  const std::vector<Byte> pristine = read_file_bytes(path);
  ISF_REQUIRE(pristine.size() > 400);

  // Damage one record in the middle, leaving later records intact.
  {
    std::vector<Byte> damaged = pristine;
    damaged[300] = static_cast<Byte>(damaged[300] ^ 0x5AU);
    write_file_bytes(path, damaged);
  }
  auto fabric = LocalFabric::start(path);
  ISF_REQUIRE(!fabric.ok());
  ISF_REQUIRE_EQ(static_cast<int>(fabric.status()), static_cast<int>(Status::Corrupt));

  // A truncated tail, by contrast, is recovered conservatively, and the
  // recovered state can never hold more authority than the original did.
  {
    std::vector<Byte> truncated = pristine;
    truncated.resize(truncated.size() - 64);
    write_file_bytes(path, truncated);
  }
  auto recovered = LocalFabric::start(path);
  ISF_REQUIRE_OK(recovered);
  auto client = recovered->get()->client();
  ISF_REQUIRE_OK(client);
  auto paths = client.value().list_paths();
  ISF_REQUIRE_OK(paths);
  for (const auto& path_record : paths.value()) {
    auto ledger = client.value().ledger(path_record.id);
    ISF_REQUIRE_OK(ledger);
    ISF_CHECK(ledger.value().authoritative_usable <= 1000);
    ISF_REQUIRE_EQ(ledger.value().verify_closure(), Status::Ok);
    ISF_CHECK_EQ(ledger.value().oversubscribed, Amount{0});
  }
  auto grants = client.value().list_grants();
  ISF_REQUIRE_OK(grants);
  for (const auto& grant : grants.value()) {
    ISF_CHECK(grant.historical);
  }
}

ISF_TEST(adversarial, incompatible_store_format_is_refused) {
  ScratchDir scratch("adv-format");
  const std::string path = scratch.file("state.isfstore");
  {
    auto fabric = LocalFabric::start(path);
    ISF_REQUIRE_OK(fabric);
    fabric->get()->stop();
  }
  std::vector<Byte> bytes;
  {
    std::FILE* fp = std::fopen(path.c_str(), "rb");
    ISF_REQUIRE(fp != nullptr);
    std::array<Byte, 4096> buffer{};
    std::size_t got = 0;
    while ((got = std::fread(buffer.data(), 1, buffer.size(), fp)) > 0) {
      bytes.insert(bytes.end(), buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(got));
    }
    std::fclose(fp);
  }
  ISF_REQUIRE(bytes.size() >= 128);
  // Bump the format version and repair the header checksum so that only the
  // version check can reject the file.
  bytes[4] = 9;
  const std::uint32_t checksum = crc32c(ByteSpan(bytes.data(), 124));
  for (unsigned i = 0; i < 4; ++i) {
    bytes[124 + i] = static_cast<Byte>((checksum >> (i * 8U)) & 0xFFU);
  }
  {
    std::FILE* fp = std::fopen(path.c_str(), "wb");
    ISF_REQUIRE(fp != nullptr);
    (void)std::fwrite(bytes.data(), 1, bytes.size(), fp);
    std::fclose(fp);
  }
  auto fabric = LocalFabric::start(path);
  ISF_REQUIRE(!fabric.ok());
  ISF_REQUIRE_EQ(static_cast<int>(fabric.status()), static_cast<int>(Status::Corrupt));
}

ISF_TEST(adversarial, oversized_container_counts_are_refused) {
  Writer writer;
  writer.u32(0xFFFFFFFFU);
  Reader reader(writer.span());
  auto count = reader.container_count();
  ISF_REQUIRE(!count.ok());
  ISF_REQUIRE_EQ(static_cast<int>(count.status()), static_cast<int>(Status::LimitExceeded));

  // A list filter that asks for more elements than the protocol allows.
  Writer filter;
  filter.boolean(true);
  filter.u32(1U << 30);
  filter.id128(Id128{});
  filter.id128(Id128{});
  auto decoded = decode_list_filter(filter.span());
  ISF_REQUIRE(!decoded.ok());
  ISF_REQUIRE_EQ(static_cast<int>(decoded.status()), static_cast<int>(Status::LimitExceeded));
}

ISF_TEST(adversarial, connection_flood_is_bounded_and_recoverable) {
  ScratchDir scratch("adv-flood");
  LocalFabric::Options options;
  options.max_connections = 4;
  options.io_timeout_ms = 1500;
  auto fabric = LocalFabric::start(scratch.file("state.isfstore"), options);
  ISF_REQUIRE_OK(fabric);

  // Open far more connections than the daemon admits. Each one is either
  // accepted or explicitly refused; none of them may take the daemon down.
  std::vector<Socket> sockets;
  for (int i = 0; i < 24; ++i) {
    Socket socket;
    const Status connected = isf::connect(fabric->get()->endpoint(), 5000, socket);
    ISF_REQUIRE_EQ(connected, Status::Ok);
    (void)socket.set_timeouts(200, 200);
    sockets.push_back(std::move(socket));
  }

  // The daemon keeps running and keeps answering, even while over its bound.
  const ServerStats stats = fabric->get()->server().stats();
  ISF_CHECK(stats.connections_accepted >= 4);
  ISF_CHECK(stats.connections_rejected >= 1);
  ISF_CHECK(stats.connections_accepted + stats.connections_rejected <= 24);

  for (auto& socket : sockets) {
    socket.close();
  }

  // Once the load is released, well behaved clients are served again.
  std::size_t served = 0;
  for (int attempt = 0; attempt < 200 && served == 0; ++attempt) {
    auto fresh = fabric->get()->client();
    if (fresh.ok()) {
      auto fresh_status = fresh.value().status();
      if (fresh_status.ok()) {
        ++served;
      }
    }
    sleep_ms(25);
  }
  ISF_REQUIRE(served > 0);
}

ISF_TEST(adversarial, zero_length_and_partial_payloads_are_refused) {
  ScratchDir scratch("adv-partial");
  auto fabric = LocalFabric::start(scratch.file("state.isfstore"));
  ISF_REQUIRE_OK(fabric);
  auto socket = handshake(**fabric);
  ISF_REQUIRE_OK(socket);

  // A status request with a non-empty body is invalid (trailing bytes).
  Request request;
  request.type = MessageType::StatusRequest;
  request.session_seq = 1;
  request.id = RequestId::from_seed(11, 11);
  request.payload = {0xFF, 0xFF, 0xFF};
  const std::vector<Byte> frame = encode_frame(encode_request(request));
  send_raw(socket.value(), ByteSpan(frame.data(), frame.size()));
  auto reply = read_frame(socket.value(), kDefaultMaxFrameBytes, 5000);
  ISF_REQUIRE_OK(reply);
  auto response = decode_response(ByteSpan(reply.value().data(), reply.value().size()));
  ISF_REQUIRE_OK(response);
  ISF_CHECK(response.value().status != Status::Ok);
  socket.value().close();
  expect_server_alive(**fabric);
}