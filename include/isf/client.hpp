// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#ifndef ISF_CLIENT_HPP
#define ISF_CLIENT_HPP

#include "isf/net.hpp"
#include "isf/protocol.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace isf {

struct ClientOptions {
  Endpoint endpoint{};
  std::uint64_t connect_timeout_ms{5000};
  std::uint64_t io_timeout_ms{30000};
  std::size_t max_frame_bytes{kDefaultMaxFrameBytes};
  std::string client_kind{"isf-client"};
};

/// A synchronous protocol client. One outstanding request at a time, which is
/// what the session sequence check on the server assumes.
class FabricClient {
 public:
  FabricClient() = default;
  ~FabricClient();
  FabricClient(FabricClient&&) noexcept = default;
  FabricClient& operator=(FabricClient&&) noexcept = default;
  FabricClient(const FabricClient&) = delete;
  FabricClient& operator=(const FabricClient&) = delete;

  [[nodiscard]] static Expected<FabricClient> connect(const ClientOptions& options);

  [[nodiscard]] Expected<Response> call(MessageType type, ByteSpan body);

  // ---- typed operations --------------------------------------------------

  [[nodiscard]] Expected<MutationReport> register_site(const SiteDescriptor& descriptor,
                                                       const Incarnation& incarnation,
                                                       const Epoch& epoch, std::uint64_t now);
  [[nodiscard]] Expected<MutationReport> heartbeat(const SiteHeartbeat& heartbeat);
  [[nodiscard]] Expected<MutationReport> set_site_state(const SiteId& site, SiteState state,
                                                        std::string_view reason, std::uint64_t now);
  [[nodiscard]] Expected<MutationReport> register_path(const PathRegistration& registration);
  [[nodiscard]] Expected<MutationReport> set_path_state(const PathId& path, PathState state,
                                                        std::string_view reason, std::uint64_t now);
  [[nodiscard]] Expected<MutationReport> attest_capacity(const CapacityAttestation& attestation);
  [[nodiscard]] Expected<MutationReport> issue_oversubscription(
      const OversubscriptionAuthority& authority);
  [[nodiscard]] Expected<MutationReport> install_policy(const Policy& policy,
                                                        const PrincipalId& principal);
  [[nodiscard]] Expected<MutationReport> bump_epoch(const Epoch& epoch,
                                                    const PrincipalId& principal);
  [[nodiscard]] Expected<MutationReport> propose_grant(const GrantProposal& proposal);
  [[nodiscard]] Expected<MutationReport> evaluate_grant(const GrantOperation& op);
  [[nodiscard]] Expected<MutationReport> reserve_grant(const GrantOperation& op);
  [[nodiscard]] Expected<MutationReport> activate_grant(const GrantOperation& op);
  [[nodiscard]] Expected<MutationReport> degrade_grant(const GrantOperation& op);
  [[nodiscard]] Expected<MutationReport> withdraw_grant(const GrantOperation& op);
  [[nodiscard]] Expected<MutationReport> retire_grant(const GrantOperation& op);
  [[nodiscard]] Expected<MutationReport> cancel_grant(const GrantOperation& op);
  [[nodiscard]] Expected<MutationReport> acknowledge_grant(const GrantAcknowledgement& ack);
  [[nodiscard]] Expected<MutationReport> verify_grant(const GrantVerification& verification);
  [[nodiscard]] Expected<MutationReport> reconcile_grant(const GrantOperation& op,
                                                         GrantState target,
                                                         const PrincipalId& principal);
  [[nodiscard]] Expected<MutationReport> tick(std::uint64_t now);

  [[nodiscard]] Expected<StatusReport> status();
  [[nodiscard]] Expected<std::vector<SiteRecord>> list_sites();
  [[nodiscard]] Expected<std::vector<PathRecord>> list_paths();
  [[nodiscard]] Expected<std::vector<GrantRecord>> list_grants(const ListFilter& filter = {});
  [[nodiscard]] Expected<CapacityLedger> ledger(const PathId& path);
  [[nodiscard]] Expected<DigestReport> digest();
  [[nodiscard]] Expected<AuthoritySnapshot> snapshot();
  [[nodiscard]] Status request_shutdown();

  [[nodiscard]] const HelloReply& hello() const noexcept { return hello_; }
  [[nodiscard]] const Endpoint& endpoint() const noexcept { return endpoint_; }
  [[nodiscard]] bool connected() const noexcept { return socket_.valid(); }
  void close();

 private:
  [[nodiscard]] Expected<Response> round_trip(MessageType type, ByteSpan body);
  [[nodiscard]] IoStatus pump();

  Socket socket_{};
  FrameDecoder decoder_{kDefaultMaxFrameBytes};
  ClientOptions options_{};
  Endpoint endpoint_{};
  HelloReply hello_{};
  std::uint64_t sequence_{0};
  std::vector<Byte> scratch_{};
  std::vector<Byte> pending_{};
};

/// Pull the grant record out of a mutation reply that created or changed one.
[[nodiscard]] Expected<GrantRecord> extract_grant(const MutationReport& report);

/// Pull the site record out of a mutation reply that created or changed one.
[[nodiscard]] Expected<SiteRecord> extract_site(const MutationReport& report);

/// Pull the path record out of a mutation reply that created or changed one.
[[nodiscard]] Expected<PathRecord> extract_path(const MutationReport& report);

}  // namespace isf

#endif  // ISF_CLIENT_HPP
