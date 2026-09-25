// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "isf/daemon.hpp"

#include "isf/clock.hpp"
#include "isf/log.hpp"

#include <chrono>
#include <string>
#include <utility>
#include <vector>

namespace isf {
namespace {

constexpr const char* kComponent = "daemon";

[[nodiscard]] bool is_mutation(MessageType type) noexcept {
  switch (type) {
    case MessageType::SiteRegister:
    case MessageType::SiteHeartbeat:
    case MessageType::SiteSetState:
    case MessageType::PathRegister:
    case MessageType::PathSetState:
    case MessageType::CapacityAttest:
    case MessageType::Oversubscribe:
    case MessageType::PolicyInstall:
    case MessageType::EpochBump:
    case MessageType::GrantPropose:
    case MessageType::GrantEvaluate:
    case MessageType::GrantReserve:
    case MessageType::GrantActivate:
    case MessageType::GrantDegrade:
    case MessageType::GrantWithdraw:
    case MessageType::GrantRetire:
    case MessageType::GrantCancel:
    case MessageType::GrantAcknowledge:
    case MessageType::GrantVerify:
    case MessageType::GrantReconcile:
    case MessageType::TickRequest:
      return true;
    default:
      return false;
  }
}

[[nodiscard]] MessageType reply_type_for(MessageType request) noexcept {
  switch (request) {
    case MessageType::StatusRequest:
      return MessageType::StatusReply;
    case MessageType::ListSites:
      return MessageType::SitesReply;
    case MessageType::ListPaths:
      return MessageType::PathsReply;
    case MessageType::ListGrants:
      return MessageType::GrantsReply;
    case MessageType::LedgerRequest:
      return MessageType::LedgerReply;
    case MessageType::DigestRequest:
      return MessageType::DigestReply;
    case MessageType::SnapshotRequest:
      return MessageType::SnapshotReply;
    case MessageType::ShutdownRequest:
      return MessageType::ShutdownReply;
    default:
      return MessageType::MutationReply;
  }
}

struct PrimaryKey {
  ObjectKind kind{ObjectKind::AuthorityMeta};
  Id128 key{};
  bool any{true};
};

[[nodiscard]] PrimaryKey primary_for(const Request& request) {
  PrimaryKey out;
  switch (request.type) {
    case MessageType::SiteRegister: {
      auto body = decode_site_registration(ByteSpan(request.payload.data(), request.payload.size()));
      if (body.ok()) {
        out.kind = ObjectKind::Site;
        out.key = body.value().descriptor.id.raw();
        out.any = false;
      }
      break;
    }
    case MessageType::SiteHeartbeat: {
      auto body = decode_heartbeat(ByteSpan(request.payload.data(), request.payload.size()));
      if (body.ok()) {
        out.kind = ObjectKind::Site;
        out.key = body.value().id.raw();
        out.any = false;
      }
      break;
    }
    case MessageType::SiteSetState: {
      auto body = decode_site_state_request(ByteSpan(request.payload.data(), request.payload.size()));
      if (body.ok()) {
        out.kind = ObjectKind::Site;
        out.key = std::get<0>(body.value()).raw();
        out.any = false;
      }
      break;
    }
    case MessageType::PathRegister: {
      auto body = decode_path_registration(ByteSpan(request.payload.data(), request.payload.size()));
      if (body.ok()) {
        out.kind = ObjectKind::Path;
        out.key = body.value().descriptor.id.raw();
        out.any = false;
      }
      break;
    }
    case MessageType::PathSetState: {
      auto body = decode_path_state_request(ByteSpan(request.payload.data(), request.payload.size()));
      if (body.ok()) {
        out.kind = ObjectKind::Path;
        out.key = std::get<0>(body.value()).raw();
        out.any = false;
      }
      break;
    }
    case MessageType::CapacityAttest: {
      Reader hint_reader(ByteSpan(request.payload.data(), request.payload.size()), WireLimits{});
      auto body = decode_attestation(hint_reader);
      if (body.ok()) {
        out.kind = ObjectKind::Path;
        out.key = body.value().path.raw();
        out.any = false;
      }
      break;
    }
    case MessageType::PolicyInstall: {
      out.kind = ObjectKind::Policy;
      out.key = Id128{};
      out.any = false;
      break;
    }
    case MessageType::EpochBump: {
      out.kind = ObjectKind::Epoch;
      out.key = Id128{};
      out.any = false;
      break;
    }
    case MessageType::GrantPropose:
    case MessageType::GrantEvaluate:
    case MessageType::GrantReserve:
    case MessageType::GrantActivate:
    case MessageType::GrantDegrade:
    case MessageType::GrantWithdraw:
    case MessageType::GrantRetire:
    case MessageType::GrantCancel:
    case MessageType::GrantAcknowledge:
    case MessageType::GrantVerify:
    case MessageType::GrantReconcile: {
      out.kind = ObjectKind::Grant;
      out.any = true;
      break;
    }
    default: {
      out.kind = ObjectKind::AuthorityMeta;
      out.any = true;
      break;
    }
  }
  return out;
}

[[nodiscard]] std::vector<Byte> encode_snapshot_body(const AuthoritySnapshot& snapshot) {
  Writer writer(WireLimits{kAbsoluteMaxFrameBytes, 4096, 1U << 20, 8});
  encode(writer, snapshot);
  return writer.buffer();
}

}  // namespace

Daemon::~Daemon() { stop(); }

Status Daemon::apply_replay(const ReplayResult& replay, std::string& detail) {
  AuthorityConfig config;
  config.policy = options_.policy;
  config.epoch = options_.epoch;
  config.incarnation = options_.incarnation;
  authority_ = Authority(config);

  std::size_t suppressed = 0;
  for (const auto& action : replay.actions) {
    if (action.kind == ReplayAction::Kind::Snapshot) {
      auto rebuilt = Authority::from_snapshot(config, action.snapshot);
      if (!rebuilt.ok()) {
        detail = "snapshot could not be reconstructed: " + rebuilt.detail();
        return rebuilt.status();
      }
      authority_ = std::move(rebuilt.value());
      continue;
    }
    std::vector<StateChange> effective;
    effective.reserve(action.changes.size());
    const bool ambiguous = action.ambiguous || action.aborted;
    for (const auto& change : action.changes) {
      if (ambiguous && change.releases_capacity) {
        // An ambiguous intent that would release capacity is deliberately not
        // applied: capacity is only released by a provably complete
        // transaction.
        ++suppressed;
        continue;
      }
      effective.push_back(change);
    }
    const Status applied = authority_.apply(effective, action.arbitration);
    if (applied != Status::Ok) {
      detail = "replayed change set could not be applied";
      return applied;
    }
    for (const auto& change : action.changes) {
      if (change.kind != ObjectKind::Grant) {
        continue;
      }
      const auto record = authority_.find_grant(GrantId::from_raw(change.key));
      if (!record.has_value()) {
        continue;
      }
      const Status marked =
          ambiguous
              ? authority_.mark_recovered(
                    GrantId::from_raw(change.key), Provenance::AmbiguousCommit, true,
                    "durable commit was ambiguous at restart; capacity retained conservatively")
              : authority_.mark_recovered(GrantId::from_raw(change.key),
                                          Provenance::RecoveredFromLog, false, {});
      if (marked != Status::Ok) {
        detail = "recovered grant could not be marked as historical";
        return marked;
      }
    }
  }

  (void)authority_.mark_all_historical();
  suppressed_releases_.store(suppressed, std::memory_order_relaxed);
  std::string why;
  const Status invariants = authority_.verify_invariants(&why);
  if (invariants != Status::Ok) {
    detail = "recovered state violates an invariant: " + why;
    return invariants;
  }
  return Status::Ok;
}

Expected<std::unique_ptr<Daemon>> Daemon::start(const DaemonOptions& options) {
  if (options.state_path.empty()) {
    return Outcome(Status::Invalid, "daemon requires a state path");
  }
  if (options.policy.validate() != Status::Ok) {
    return Outcome(Status::Invalid, "daemon was given an invalid policy");
  }
  auto daemon = std::unique_ptr<Daemon>(new Daemon());
  daemon->options_ = options;
  daemon->authority_ = Authority(AuthorityConfig{});

  ReplayResult replay;
  {
    std::lock_guard<std::mutex> guard(daemon->store_mutex_);
    auto opened = daemon->store_.open(options.state_path, options.store);
    if (!opened.ok()) {
      return Outcome(opened.status(), "store could not be opened: " + opened.detail());
    }
    replay = std::move(opened.value());
  }
  daemon->recovery_ = replay.report;
  if (!replay.report.servable()) {
    return Outcome(Status::Corrupt,
                   "durable state is " + std::string(recovery_fidelity_name(replay.report.fidelity)) +
                       ": " + replay.report.detail);
  }
  {
    std::lock_guard<std::mutex> guard(daemon->state_mutex_);
    std::string detail;
    const Status applied = daemon->apply_replay(replay, detail);
    if (applied != Status::Ok) {
      return Outcome(applied, "replay failed: " + detail);
    }
    daemon->arbitration_.store(daemon->authority_.last_arbitration().value,
                               std::memory_order_relaxed);
  }
  daemon->started_ms_ = now_ms();
  ISF_LOG_INFO(kComponent, "recovered store fidelity=%s records=%zu ambiguous=%zu",
               recovery_fidelity_name(replay.report.fidelity), replay.report.records_read,
               replay.report.ambiguous_intents);
  if (options.enable_ticker) {
    daemon->stopping_.store(false, std::memory_order_relaxed);
    daemon->ticker_ = std::thread([raw = daemon.get()] { raw->ticker_loop(); });
  }
  return daemon;
}

void Daemon::ticker_loop() {
  const std::uint64_t interval =
      options_.tick_interval_ms == 0 ? 250 : options_.tick_interval_ms;
  while (!stopping_.load(std::memory_order_relaxed)) {
    for (std::uint64_t slept = 0; slept < interval; slept += 25) {
      if (stopping_.load(std::memory_order_relaxed)) {
        return;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }
    const auto applied = tick_once(now_ms());
    if (!applied.ok() && applied.status() != Status::Unavailable &&
        applied.status() != Status::NotFound) {
      ISF_LOG_WARN(kComponent, "expiry tick failed: %s", applied.detail().c_str());
    }
  }
}

void Daemon::stop() {
  if (stopping_.exchange(true, std::memory_order_acq_rel)) {
    return;
  }
  if (ticker_.joinable()) {
    ticker_.join();
  }
  ISF_LOG_DEBUG(kComponent, "stop: ticker joined");
  std::lock_guard<std::mutex> guard(store_mutex_);
  if (store_.is_open()) {
    (void)store_.append_clean_shutdown(now_ms());
    (void)store_.flush();
    store_.close();
  }
  ISF_LOG_DEBUG(kComponent, "stop: durable store closed");
}

Status Daemon::maybe_compact(std::uint64_t now) {
  AuthoritySnapshot snapshot;
  std::size_t estimate = 0;
  {
    std::lock_guard<std::mutex> guard(store_mutex_);
    if (!options_.auto_compact || !store_.needs_compaction()) {
      return Status::Ok;
    }
    estimate = store_.log_bytes();
  }
  (void)estimate;
  {
    std::lock_guard<std::mutex> guard(state_mutex_);
    snapshot = authority_.snapshot();
  }
  std::lock_guard<std::mutex> guard(store_mutex_);
  const Status status = store_.compact(snapshot, now, options_.incarnation);
  if (status == Status::Ok) {
    ISF_LOG_DEBUG(kComponent, "compacted the durable log");
  }
  return status;
}

Expected<std::size_t> Daemon::tick_once(std::uint64_t now) {
  Request request;
  request.type = MessageType::TickRequest;
  request.session_seq = 0;
  request.id = RequestId::random();
  request.payload = encode_u64_body(now);
  const Response reply = handle(request);
  if (reply.status == Status::Ok) {
    auto body = decode_mutation_report(ByteSpan(reply.payload.data(), reply.payload.size()));
    if (body.ok()) {
      return body.value().total_changes;
    }
    return body.status();
  }
  if (reply.status == Status::Refused) {
    return std::size_t{0};
  }
  return reply.status;
}

MutationResult Daemon::plan_for(const Request& request, ArbSeq arb) {
  const ByteSpan payload(request.payload.data(), request.payload.size());
  switch (request.type) {
    case MessageType::SiteRegister: {
      auto body = decode_site_registration(payload);
      if (!body.ok()) return body.status();
      return authority_.plan_register_site(body.value(), arb);
    }
    case MessageType::SiteHeartbeat: {
      auto body = decode_heartbeat(payload);
      if (!body.ok()) return body.status();
      return authority_.plan_heartbeat(body.value(), arb);
    }
    case MessageType::SiteSetState: {
      auto body = decode_site_state_request(payload);
      if (!body.ok()) return body.status();
      return authority_.plan_set_site_state(std::get<0>(body.value()), std::get<1>(body.value()),
                                            std::get<2>(body.value()), std::get<3>(body.value()), arb);
    }
    case MessageType::PathRegister: {
      auto body = decode_path_registration(payload);
      if (!body.ok()) return body.status();
      return authority_.plan_register_path(body.value(), arb);
    }
    case MessageType::PathSetState: {
      auto body = decode_path_state_request(payload);
      if (!body.ok()) return body.status();
      return authority_.plan_set_path_state(std::get<0>(body.value()), std::get<1>(body.value()),
                                            std::get<2>(body.value()), std::get<3>(body.value()), arb);
    }
    case MessageType::CapacityAttest: {
      Reader reader(payload, WireLimits{});
      auto body = decode_attestation(reader);
      if (!body.ok()) return body.status();
      if (reader.require_end() != Status::Ok) {
        return Outcome(Status::Invalid, "attestation request has trailing bytes");
      }
      return authority_.plan_attest_capacity(body.value(), arb);
    }
    case MessageType::Oversubscribe: {
      Reader reader(payload, WireLimits{});
      auto body = decode_oversubscription(reader);
      if (!body.ok()) return body.status();
      if (reader.require_end() != Status::Ok) {
        return Outcome(Status::Invalid, "oversubscription request has trailing bytes");
      }
      return authority_.plan_issue_oversubscription(body.value(), arb);
    }
    case MessageType::PolicyInstall: {
      auto body = decode_policy_install_request(payload);
      if (!body.ok()) return body.status();
      return authority_.plan_install_policy(body.value().first, body.value().second, arb);
    }
    case MessageType::EpochBump: {
      auto body = decode_epoch_bump_request(payload);
      if (!body.ok()) return body.status();
      return authority_.plan_bump_epoch(body.value().first, body.value().second, arb);
    }
    case MessageType::GrantPropose: {
      auto body = decode_grant_proposal(payload);
      if (!body.ok()) return body.status();
      return authority_.plan_propose_grant(body.value(), arb);
    }
    case MessageType::GrantEvaluate:
    case MessageType::GrantReserve:
    case MessageType::GrantActivate:
    case MessageType::GrantDegrade:
    case MessageType::GrantWithdraw:
    case MessageType::GrantRetire:
    case MessageType::GrantCancel: {
      auto body = decode_grant_operation(payload);
      if (!body.ok()) return body.status();
      switch (request.type) {
        case MessageType::GrantEvaluate:
          return authority_.plan_evaluate_grant(body.value(), arb);
        case MessageType::GrantReserve:
          return authority_.plan_reserve_grant(body.value(), arb);
        case MessageType::GrantActivate:
          return authority_.plan_activate_grant(body.value(), arb);
        case MessageType::GrantDegrade:
          return authority_.plan_degrade_grant(body.value(), arb);
        case MessageType::GrantWithdraw:
          return authority_.plan_withdraw_grant(body.value(), arb);
        case MessageType::GrantRetire:
          return authority_.plan_retire_grant(body.value(), arb);
        default:
          return authority_.plan_cancel_grant(body.value(), arb);
      }
    }
    case MessageType::GrantAcknowledge: {
      auto body = decode_acknowledgement(payload);
      if (!body.ok()) return body.status();
      return authority_.plan_acknowledge_grant(body.value(), arb);
    }
    case MessageType::GrantVerify: {
      auto body = decode_verification_message(payload);
      if (!body.ok()) return body.status();
      return authority_.plan_verify_grant(body.value(), arb);
    }
    case MessageType::GrantReconcile: {
      auto body = decode_reconcile_request(payload);
      if (!body.ok()) return body.status();
      return authority_.plan_reconcile_grant(std::get<0>(body.value()), std::get<1>(body.value()),
                                             std::get<2>(body.value()), arb);
    }
    case MessageType::TickRequest: {
      auto now = decode_u64_body(payload);
      if (!now.ok()) return now.status();
      return authority_.plan_tick(now.value(), arb);
    }
    default:
      return Status::Unsupported;
  }
}

Status Daemon::commit(const Mutation& mutation, ArbSeq arb, std::string& detail) {
  const std::uint64_t intent = intent_counter_.fetch_add(1, std::memory_order_relaxed) + 1;
  const std::uint64_t now = now_ms();
  {
    std::lock_guard<std::mutex> guard(store_mutex_);
    Status status = store_.append_intent(intent, arb, mutation.changes, now, options_.incarnation);
    if (status == Status::Ok) {
      status = store_.flush();
    }
    if (status != Status::Ok) {
      durability_failed_.store(true, std::memory_order_relaxed);
      detail = "the durable intent record could not be written; refusing further mutations";
      return Status::Unavailable;
    }
  }
  if (options_.commit_stage_hook) {
    options_.commit_stage_hook("intent-durable");
  }
  {
    std::lock_guard<std::mutex> guard(state_mutex_);
    const Status applied = authority_.apply(mutation.changes, arb);
    if (applied != Status::Ok) {
      durability_failed_.store(true, std::memory_order_relaxed);
      detail = "the planned change set could not be applied";
      return Status::Corrupt;
    }
    if (options_.verify_after_mutation) {
      std::string why;
      const Status invariants = authority_.verify_invariants(&why);
      if (invariants != Status::Ok) {
        durability_failed_.store(true, std::memory_order_relaxed);
        detail = "post-mutation invariant violation: " + why;
        return invariants;
      }
    }
  }
  if (options_.commit_stage_hook) {
    options_.commit_stage_hook("applied");
  }
  {
    std::lock_guard<std::mutex> guard(store_mutex_);
    Status status = store_.append_commit(intent, now);
    if (status == Status::Ok) {
      status = store_.flush();
    }
    if (status != Status::Ok) {
      durability_failed_.store(true, std::memory_order_relaxed);
      detail =
          "the durable completion record could not be written; the change survives only as an "
          "intent and is ambiguous across a restart";
      return Status::Indeterminate;
    }
  }
  if (options_.commit_stage_hook) {
    options_.commit_stage_hook("commit-durable");
  }
  const Status compacted = maybe_compact(now);
  if (compacted != Status::Ok) {
    ISF_LOG_WARN(kComponent, "log compaction failed with %s", status_name(compacted));
  }
  return Status::Ok;
}

Response Daemon::handle_mutation(const Request& request) {
  Response reply;
  reply.type = reply_type_for(request.type);
  reply.session_seq = request.session_seq;
  reply.id = request.id;

  std::lock_guard<std::mutex> guard(commit_mutex_);
  if (!recovery_.servable()) {
    reply.status = Status::Corrupt;
    reply.detail = "durable state is not servable";
    mutations_failed_.fetch_add(1, std::memory_order_relaxed);
    return reply;
  }
  if (durability_failed_.load(std::memory_order_relaxed)) {
    reply.status = Status::Unavailable;
    reply.detail = "durability was lost earlier in this incarnation; restart to recover";
    mutations_failed_.fetch_add(1, std::memory_order_relaxed);
    return reply;
  }

  const ArbSeq arb{arbitration_.fetch_add(1, std::memory_order_relaxed) + 1};
  MutationResult planned = Status::Unsupported;
  {
    std::lock_guard<std::mutex> state_guard(state_mutex_);
    planned = plan_for(request, arb);
  }
  if (!planned.ok()) {
    if (planned.status() == Status::NotFound && request.type == MessageType::TickRequest) {
      reply.status = Status::Refused;
      reply.detail = "nothing to expire";
      return reply;
    }
    mutations_refused_.fetch_add(1, std::memory_order_relaxed);
    reply.status = planned.status();
    reply.detail = planned.detail();
    if (reply.detail.empty()) {
      reply.detail = "mutation was refused";
    }
    return reply;
  }
  if (planned.value().changes.empty()) {
    mutations_refused_.fetch_add(1, std::memory_order_relaxed);
    reply.status = Status::Refused;
    reply.detail = "the plan produced no state change";
    return reply;
  }

  std::string detail;
  const Status committed = commit(planned.value(), arb, detail);
  if (committed != Status::Ok) {
    mutations_failed_.fetch_add(1, std::memory_order_relaxed);
    reply.status = committed;
    reply.detail = detail;
    return reply;
  }

  const PrimaryKey primary = primary_for(request);
  MutationReport report;
  report.arbitration = arb;
  report.primary_kind = primary.kind;
  report.primary_key = primary.key;
  report.total_changes = static_cast<std::uint32_t>(planned.value().changes.size());
  const std::size_t limit = options_.max_changes_in_reply == 0 ? 1 : options_.max_changes_in_reply;
  for (const auto& change : planned.value().changes) {
    if (report.changes.size() >= limit) {
      report.truncated = true;
      break;
    }
    report.changes.push_back(change);
  }
  if (!primary.any) {
    for (const auto& change : report.changes) {
      if (change.kind == primary.kind && change.key == primary.key) {
        report.primary_kind = change.kind;
        report.primary_key = change.key;
        break;
      }
    }
  }
  reply.status = Status::Ok;
  reply.payload = encode_mutation_report(report);
  mutations_applied_.fetch_add(1, std::memory_order_relaxed);
  return reply;
}

Response Daemon::handle_read(const Request& request) {
  Response reply;
  reply.type = reply_type_for(request.type);
  reply.session_seq = request.session_seq;
  reply.id = request.id;
  const ByteSpan payload(request.payload.data(), request.payload.size());

  // Read-only messages carry either no body or one that is fully consumed by
  // the decoder below. Any other shape is rejected rather than ignored.
  const bool body_expected = request.type == MessageType::ListGrants ||
                             request.type == MessageType::LedgerRequest;
  if (!body_expected && !request.payload.empty()) {
    reply.status = Status::Invalid;
    reply.detail = "this request must not carry a body";
    return reply;
  }

  switch (request.type) {
    case MessageType::StatusRequest: {
      reply.payload = encode_status_report(status_report());
      return reply;
    }
    case MessageType::ListSites: {
      (void)payload;
      std::lock_guard<std::mutex> guard(state_mutex_);
      reply.payload = encode_site_list(authority_.sites());
      return reply;
    }
    case MessageType::ListPaths: {
      std::lock_guard<std::mutex> guard(state_mutex_);
      reply.payload = encode_path_list(authority_.paths());
      return reply;
    }
    case MessageType::ListGrants: {
      auto filter = decode_list_filter(payload);
      if (!filter.ok()) {
        reply.status = filter.status();
        reply.detail = filter.detail();
        return reply;
      }
      std::lock_guard<std::mutex> guard(state_mutex_);
      std::vector<GrantRecord> grants = authority_.grants();
      std::vector<GrantRecord> filtered;
      for (auto& grant : grants) {
        if (!filter.value().include_terminal && is_terminal(grant.state)) {
          continue;
        }
        if (!filter.value().path.is_nil() && !(grant.binding.path == filter.value().path)) {
          continue;
        }
        if (!filter.value().site.is_nil() && !(grant.binding.holder == filter.value().site)) {
          continue;
        }
        if (filtered.size() >= filter.value().limit) {
          break;
        }
        filtered.push_back(std::move(grant));
      }
      reply.payload = encode_grant_list(filtered);
      return reply;
    }
    case MessageType::LedgerRequest: {
      auto id = decode_id_body(payload);
      if (!id.ok()) {
        reply.status = id.status();
        return reply;
      }
      std::lock_guard<std::mutex> guard(state_mutex_);
      auto ledger = authority_.ledger(PathId::from_raw(id.value()));
      if (!ledger.ok()) {
        reply.status = ledger.status();
        reply.detail = ledger.detail();
        return reply;
      }
      LedgerReport report;
      report.path = PathId::from_raw(id.value());
      report.ledger = ledger.value();
      reply.payload = encode_ledger_report(report);
      return reply;
    }
    case MessageType::DigestRequest: {
      std::lock_guard<std::mutex> guard(state_mutex_);
      DigestReport report;
      report.state_digest = authority_.state_digest();
      report.policy_digest = policy_digest_hex(authority_.policy());
      report.last_arbitration = authority_.last_arbitration().value;
      report.sites = authority_.sites().size();
      report.paths = authority_.paths().size();
      report.grants = authority_.grants().size();
      reply.payload = encode_digest_report(report);
      return reply;
    }
    case MessageType::SnapshotRequest: {
      std::lock_guard<std::mutex> guard(state_mutex_);
      reply.payload = encode_snapshot_body(authority_.snapshot());
      return reply;
    }
    case MessageType::ShutdownRequest: {
      reply.payload.clear();
      reply.detail = "shutdown accepted";
      return reply;
    }
    default: {
      reply.status = Status::Unsupported;
      reply.detail = "message type is not readable";
      return reply;
    }
  }
}

Response Daemon::handle(const Request& request) {
  if (request.protocol_version != kWireProtocolVersion) {
    Response reply;
    reply.type = MessageType::ErrorReply;
    reply.session_seq = request.session_seq;
    reply.id = request.id;
    reply.status = Status::VersionMismatch;
    reply.detail = "wire protocol version mismatch";
    return reply;
  }
  if (!message_type_is_request(request.type)) {
    Response reply;
    reply.type = MessageType::ErrorReply;
    reply.session_seq = request.session_seq;
    reply.id = request.id;
    reply.status = Status::Invalid;
    reply.detail = "message type is not a request";
    return reply;
  }
  if (durability_failed_.load(std::memory_order_relaxed) && is_mutation(request.type)) {
    Response reply;
    reply.type = reply_type_for(request.type);
    reply.session_seq = request.session_seq;
    reply.id = request.id;
    reply.status = Status::Unavailable;
    reply.detail = "durability was lost earlier in this incarnation";
    return reply;
  }
  if (is_mutation(request.type)) {
    return handle_mutation(request);
  }
  return handle_read(request);
}

Digest256 Daemon::state_digest() const {
  std::lock_guard<std::mutex> guard(state_mutex_);
  return authority_.state_digest();
}

StatusReport Daemon::status_report() const {
  StatusReport report;
  report.version = runtime_version();
  report.wire_protocol = kWireProtocolVersion;
  report.store_fidelity = recovery_.fidelity;
  report.store_id = recovery_.store_id;
  report.store_format_version = recovery_.format_version;
  report.store_servable = recovery_.servable();
  report.store_truncated_on_open = recovery_.truncated_on_open;
  report.ambiguous_intents = recovery_.ambiguous_intents;
  report.detail = recovery_.detail;
  {
    std::lock_guard<std::mutex> guard(store_mutex_);
    report.store_records = store_.record_count();
    report.store_bytes = store_.log_bytes();
  }
  {
    std::lock_guard<std::mutex> guard(state_mutex_);
    report.incarnation = authority_.incarnation();
    report.epoch = authority_.epoch();
    report.policy = authority_.policy();
    report.sites = authority_.sites().size();
    report.paths = authority_.paths().size();
    report.grants = authority_.grants().size();
    report.aggregate = authority_.aggregate_ledger();
    report.state_digest = authority_.state_digest();
  }
  report.uptime_ms = now_ms() - started_ms_;
  report.mutations_applied = mutations_applied_.load(std::memory_order_relaxed);
  report.mutations_refused = mutations_refused_.load(std::memory_order_relaxed);
  report.mutations_failed = mutations_failed_.load(std::memory_order_relaxed);
  return report;
}

}  // namespace isf
