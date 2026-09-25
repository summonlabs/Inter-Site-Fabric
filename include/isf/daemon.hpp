// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// The daemon binds an Authority to a durable Store and a request pipeline.
//
// Concurrency and lock ownership
// ------------------------------
// Three locks exist, with a strict global order:
//
//   L1 commit_mutex_   serialises the whole "plan, record intent, apply,
//                      record commit" pipeline. Exactly one mutating request
//                      is in flight at a time, which is what makes the
//                      arbitration sequence a total order and therefore makes
//                      concurrent reservation outcomes deterministic.
//   L2 state_mutex_    guards the in-memory Authority.
//   L3 store_mutex_    guards the Store.
//
// L1 may be held while acquiring L2 or L3. L2 and L3 are never held at the same
// time, so there is no L2/L3 cycle and no lock-order inversion. No callback,
// no socket operation, and no log sink is ever invoked while L2 or L3 is held:
// replies are serialised after the locks are released. Worker threads never
// acquire L1, so stopping the daemon can join them without deadlock.

#ifndef ISF_DAEMON_HPP
#define ISF_DAEMON_HPP

#include "isf/authority.hpp"
#include "isf/protocol.hpp"
#include "isf/store.hpp"

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

namespace isf {

struct DaemonOptions {
  std::string state_path{};
  Policy policy{Policy::conservative_default()};
  Epoch epoch{1};
  Incarnation incarnation{Incarnation::random()};
  StoreOptions store{};
  /// Bound on the number of state changes returned in one mutation reply.
  std::size_t max_changes_in_reply{512};
  /// Verify every structural invariant after each applied mutation. Costs one
  /// pass over authoritative state per mutation; on by default.
  bool verify_after_mutation{true};
  /// Run a background ticker that expires site leases and grant leases.
  bool enable_ticker{true};
  std::uint64_t tick_interval_ms{250};
  /// Compact the log when it crosses a configured threshold.
  bool auto_compact{true};
  /// Optional fail-stop hook invoked between durable-commit stages. It is
  /// called with the store and state mutexes both released, so a hook that
  /// terminates the process (as the crash-consistency tests do) leaves no lock
  /// held and no callback under a lock. Stages, in order:
  ///   "intent-durable"  - the write-ahead intent record is on disk
  ///   "applied"         - the change set is in memory
  ///   "commit-durable"  - the completion record is on disk
  std::function<void(const char* stage)> commit_stage_hook{};
};

class Daemon {
 public:
  Daemon(const Daemon&) = delete;
  Daemon& operator=(const Daemon&) = delete;
  ~Daemon();

  /// Open the store, replay it conservatively, and construct the daemon.
  /// Returns Status::Corrupt when authoritative state cannot be proven from the
  /// durable image; the caller must not serve in that case.
  [[nodiscard]] static Expected<std::unique_ptr<Daemon>> start(const DaemonOptions& options);

  /// Handle one request. Thread-safe.
  [[nodiscard]] Response handle(const Request& request);

  [[nodiscard]] StatusReport status_report() const;

  /// Current authoritative digest, for differential comparison.
  [[nodiscard]] Digest256 state_digest() const;

  [[nodiscard]] const RecoveryReport& recovery() const noexcept { return recovery_; }

  /// Run one expiry tick synchronously. Returns the number of changes applied.
  [[nodiscard]] Expected<std::size_t> tick_once(std::uint64_t now);

  /// Stop the background ticker and write a clean-shutdown marker.
  void stop();

 private:
  Daemon() = default;

  [[nodiscard]] Response handle_read(const Request& request);
  [[nodiscard]] Response handle_mutation(const Request& request);
  [[nodiscard]] MutationResult plan_for(const Request& request, ArbSeq arb);
  [[nodiscard]] Status commit(const Mutation& mutation, ArbSeq arb, std::string& detail);
  void ticker_loop();
  [[nodiscard]] Status maybe_compact(std::uint64_t now);
  [[nodiscard]] Status apply_replay(const ReplayResult& replay, std::string& detail);

  DaemonOptions options_{};
  mutable std::mutex state_mutex_{};
  Authority authority_{AuthorityConfig{}};
  mutable std::mutex store_mutex_{};
  Store store_{};
  std::mutex commit_mutex_{};
  std::atomic<bool> durability_failed_{false};
  std::atomic<bool> stopping_{false};
  std::atomic<std::uint64_t> intent_counter_{0};
  std::atomic<std::uint64_t> arbitration_{0};
  std::atomic<std::uint64_t> mutations_applied_{0};
  std::atomic<std::uint64_t> mutations_refused_{0};
  std::atomic<std::uint64_t> mutations_failed_{0};
  std::atomic<std::uint64_t> suppressed_releases_{0};
  RecoveryReport recovery_{};
  std::uint64_t started_ms_{0};
  std::thread ticker_{};
};

}  // namespace isf

#endif  // ISF_DAEMON_HPP
