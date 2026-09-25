// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Bounded, versioned, integrity-chained persistence with conservative recovery.
//
// The log is a sequence of records. Each record carries a CRC-32C over its
// payload and a SHA-256 chain hash over (previous chain, header, payload). The
// chain makes a spliced, reordered, duplicated, or middle-truncated record
// stream detectable: repairing one CRC is not enough to make the stream
// self-consistent.
//
// Every mutation is written as an Intent record followed by a Commit record.
// An Intent without a matching Commit is ambiguous: it may or may not have taken
// effect. Recovery treats an ambiguous intent conservatively: changes that would
// release capacity are not applied, and changes that acquire or retain capacity
// are applied and flagged. Capacity is therefore never silently freed by a
// crash, and never silently created either.

#ifndef ISF_STORE_HPP
#define ISF_STORE_HPP

#include "isf/authority.hpp"
#include "isf/digest.hpp"
#include "isf/ids.hpp"
#include "isf/status.hpp"

#include <cstdint>
#include <cstdio>
#include <optional>
#include <string>
#include <vector>

namespace isf {

/// On-disk record kinds.
enum class RecordType : std::uint8_t {
  Intent = 1,
  Commit = 2,
  Snapshot = 3,
  CleanShutdown = 4,
  EpochMarker = 5,
  /// Closes an intent whose durable completion record was never written. The
  /// intent's capacity-releasing changes are suppressed, exactly as they are
  /// when the log is first replayed, so the decision is recorded rather than
  /// re-derived on every restart.
  Abort = 6,
};

[[nodiscard]] const char* record_type_name(RecordType t) noexcept;

/// How faithfully the store was recovered.
enum class RecoveryFidelity : std::uint8_t {
  Exact = 0,             ///< every record validated
  TornTailTruncated,     ///< an incomplete trailing record was discarded
  DegradedTruncated,     ///< an unreadable zero-filled tail was discarded
  AmbiguousIntentResolved,  ///< the log ended with an uncommitted intent, now closed
  Corrupt,               ///< integrity failure; authoritative state cannot be proven
  Incompatible,          ///< format version or endianness mismatch
  Missing,               ///< no store file existed; a fresh one was created
};

[[nodiscard]] const char* recovery_fidelity_name(RecoveryFidelity f) noexcept;

/// Outcome of opening and replaying a store.
struct RecoveryReport {
  RecoveryFidelity fidelity{RecoveryFidelity::Missing};
  StoreId store_id{};
  std::uint32_t format_version{0};
  std::size_t records_read{0};
  std::size_t bytes_read{0};
  std::size_t dropped_tail_bytes{0};
  std::size_t ambiguous_intents{0};
  std::size_t suppressed_releases{0};
  std::size_t snapshots_seen{0};
  std::size_t aborted_intents{0};
  Digest256 chain_head{};
  bool truncated_on_open{false};
  bool resolution_written_on_open{false};
  std::string detail{};

  /// True when authoritative state derived from this store may be served.
  [[nodiscard]] bool servable() const noexcept {
    return fidelity != RecoveryFidelity::Corrupt &&
           fidelity != RecoveryFidelity::Incompatible;
  }
};

/// Limits applied to a store.
struct StoreOptions {
  std::size_t max_log_bytes{64U << 20};         ///< 64 MiB
  std::size_t max_records{1U << 20};
  std::size_t max_record_bytes{16U << 20};      ///< 16 MiB
  std::size_t compact_threshold_bytes{8U << 20};
  std::size_t compact_threshold_records{1U << 16};
  bool truncate_unreadable_tail{true};
  bool durable_writes{true};

  static StoreOptions for_tests();
};

/// One replayed unit of the log.
struct ReplayAction {
  enum class Kind : std::uint8_t { Snapshot, Changes } kind{Kind::Changes};
  /** Set when kind == Snapshot. */
  AuthoritySnapshot snapshot{};
  /** Set when kind == Changes. */
  std::vector<StateChange> changes{};
  ArbSeq arbitration{};
  std::uint64_t at_ms{0};
  std::uint64_t intent_id{0};
  Incarnation origin{};
  /** True when the intent was followed by a matching completion record. */
  bool committed{false};
  /** True when an intent had no matching commit record. */
  bool ambiguous{false};
  /** True when the intent was closed by an abort resolution record, which
   *  suppresses its capacity-releasing changes on every future replay. */
  bool aborted{false};
};

/// Result of replaying a store.
struct ReplayResult {
  RecoveryReport report{};
  std::vector<ReplayAction> actions{};
  Epoch epoch{};
  Incarnation last_incarnation{};
};

/// A bounded, integrity-chained append log with snapshot compaction.
class Store {
 public:
  Store() = default;
  Store(const Store&) = delete;
  Store& operator=(const Store&) = delete;
  Store(Store&& other) noexcept;
  Store& operator=(Store&& other) noexcept;
  ~Store();

  /// Open (creating if absent) and replay a store. The returned ReplayResult
  /// carries every action in log order. When the store is not servable the
  /// caller must refuse to publish authoritative state. On success the store is
  /// left open for appending at the end of the validated region.
  [[nodiscard]] Expected<ReplayResult> open(const std::string& path, const StoreOptions& options);

  /// Append a durable intent describing a set of changes.
  [[nodiscard]] Status append_intent(std::uint64_t intent_id, ArbSeq arbitration,
                                     const std::vector<StateChange>& changes, std::uint64_t at_ms,
                                     Incarnation origin);

  /// Append the completion marker for an intent.
  [[nodiscard]] Status append_commit(std::uint64_t intent_id, std::uint64_t at_ms);

  /// Append a full state snapshot record without rewriting the log. Recovery
  /// rebuilds the authority from the most recent snapshot and replays the
  /// changes that follow it.
  [[nodiscard]] Status append_snapshot(const AuthoritySnapshot& snapshot, std::uint64_t at_ms,
                                       Incarnation origin);

  /// Append a clean-shutdown marker.
  [[nodiscard]] Status append_clean_shutdown(std::uint64_t at_ms);

  /// Close an intent whose completion record was never written.
  [[nodiscard]] Status append_abort(std::uint64_t intent_id, std::uint64_t at_ms);

  /// Flush userspace buffers and, when durable_writes is set, the platform
  /// buffers as well.
  [[nodiscard]] Status flush();

  /// True when the log has grown past a compaction threshold.
  [[nodiscard]] bool needs_compaction() const noexcept;

  /// Rewrite the log as a single snapshot record. On success the previous log
  /// has been replaced atomically.
  [[nodiscard]] Status compact(const AuthoritySnapshot& snapshot, std::uint64_t at_ms,
                               Incarnation origin);

  /// Close the store. Safe to call more than once.
  void close();

  [[nodiscard]] bool is_open() const noexcept { return file_ != nullptr; }
  [[nodiscard]] std::size_t log_bytes() const noexcept { return log_bytes_; }
  [[nodiscard]] std::size_t record_count() const noexcept { return record_count_; }
  [[nodiscard]] std::uint64_t next_sequence() const noexcept { return sequence_; }
  [[nodiscard]] const StoreOptions& options() const noexcept { return options_; }
  [[nodiscard]] const std::string& path() const noexcept { return path_; }

 private:
  friend struct StoreTestAccess;

  [[nodiscard]] Status write_record(RecordType type, std::uint64_t intent_id, std::uint64_t at_ms,
                                    Incarnation origin, ByteSpan payload, bool count_toward_limits);

  std::FILE* file_{nullptr};
  std::string path_{};
  StoreOptions options_{};
  std::uint64_t sequence_{1};
  std::size_t log_bytes_{0};
  std::size_t record_count_{0};
  std::array<Byte, 32> chain_{};
  bool durable_{true};
};

/// Serialize a set of state changes into an intent payload.
[[nodiscard]] std::vector<Byte> encode_intent_payload(std::uint64_t intent_id, ArbSeq arbitration,
                                                      const std::vector<StateChange>& changes);
[[nodiscard]] Expected<std::vector<StateChange>> decode_intent_payload(ByteSpan payload,
                                                                       std::uint64_t& intent_id,
                                                                       ArbSeq& arbitration);

/// Compute the chain hash of a record.
[[nodiscard]] Digest256 chain_hash(const std::array<Byte, 32>& previous, ByteSpan header,
                                   ByteSpan payload);

/// Number of bytes in the fixed on-disk file header.
inline constexpr std::size_t kStoreFileHeaderBytes = 128;
/// Number of bytes in one record header.
inline constexpr std::size_t kStoreRecordHeaderBytes = 56;
/// Number of bytes of chain hash that follow each record payload.
inline constexpr std::size_t kStoreChainBytes = 32;

}  // namespace isf

#endif  // ISF_STORE_HPP
