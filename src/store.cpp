// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "isf/store.hpp"

#include "isf/checked.hpp"
#include "isf/version.hpp"
#include "isf/wire.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <limits>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#if defined(_WIN32)
#include <io.h>
#else
#include <unistd.h>
#endif

namespace isf {
namespace {

constexpr std::uint32_t kFileMagic = 0x4953464CU;    // 'ISFL' little endian
constexpr std::uint32_t kRecordMagic = 0x49534652U;  // 'ISFR' little endian
constexpr std::uint16_t kRecordHeaderVersion = 1;
constexpr std::uint32_t kEndianMarker = 0x01020304U;

constexpr std::size_t kFileMagicOffset = 0;
constexpr std::size_t kFileVersionOffset = 4;
constexpr std::size_t kFileHeaderBytesOffset = 8;
constexpr std::size_t kFileEndianOffset = 12;
constexpr std::size_t kFileCreatedOffset = 16;
constexpr std::size_t kFileStoreIdOffset = 24;
constexpr std::size_t kFileCrcOffset = 124;

constexpr std::size_t kRecMagicOffset = 0;
constexpr std::size_t kRecVersionOffset = 4;
constexpr std::size_t kRecTypeOffset = 6;
constexpr std::size_t kRecFlagsOffset = 7;
constexpr std::size_t kRecLengthOffset = 8;
constexpr std::size_t kRecCrcOffset = 12;
constexpr std::size_t kRecSequenceOffset = 16;
constexpr std::size_t kRecIntentOffset = 24;
constexpr std::size_t kRecAtOffset = 32;
constexpr std::size_t kRecIncHiOffset = 40;
constexpr std::size_t kRecIncLoOffset = 48;

void put_u16(Byte* out, std::uint16_t value) {
  out[0] = static_cast<Byte>(value & 0xFFU);
  out[1] = static_cast<Byte>((value >> 8) & 0xFFU);
}

void put_u32(Byte* out, std::uint32_t value) {
  for (unsigned i = 0; i < 4; ++i) {
    out[i] = static_cast<Byte>((value >> (i * 8U)) & 0xFFU);
  }
}

void put_u64(Byte* out, std::uint64_t value) {
  for (unsigned i = 0; i < 8; ++i) {
    out[i] = static_cast<Byte>((value >> (i * 8U)) & 0xFFU);
  }
}

[[nodiscard]] std::uint16_t get_u16(const Byte* in) {
  return static_cast<std::uint16_t>(static_cast<std::uint16_t>(in[0]) |
                                    (static_cast<std::uint16_t>(in[1]) << 8));
}

[[nodiscard]] std::uint32_t get_u32(const Byte* in) {
  std::uint32_t out = 0;
  for (unsigned i = 0; i < 4; ++i) {
    out |= static_cast<std::uint32_t>(in[i]) << (i * 8U);
  }
  return out;
}

[[nodiscard]] std::uint64_t get_u64(const Byte* in) {
  std::uint64_t out = 0;
  for (unsigned i = 0; i < 8; ++i) {
    out |= static_cast<std::uint64_t>(in[i]) << (i * 8U);
  }
  return out;
}

[[nodiscard]] bool all_zero(ByteSpan data) {
  for (const Byte b : data) {
    if (b != 0) {
      return false;
    }
  }
  return true;
}

[[nodiscard]] std::string describe_errno(const char* what) {
  return std::string(what) + " failed with code " + std::to_string(errno);
}

[[nodiscard]] Status sync_file(std::FILE* fp) {
  if (std::fflush(fp) != 0) {
    return Outcome(Status::Unavailable, describe_errno("fflush"));
  }
#if defined(_WIN32)
  if (_commit(_fileno(fp)) != 0) {
    return Outcome(Status::Unavailable, describe_errno("_commit"));
  }
#else
  if (::fsync(fileno(fp)) != 0) {
    return Outcome(Status::Unavailable, describe_errno("fsync"));
  }
#endif
  return Status::Ok;
}

[[nodiscard]] bool read_whole_file(const std::string& path, std::vector<Byte>& out,
                                   std::size_t max_bytes, bool& existed) {
  std::error_code ec;
  existed = std::filesystem::exists(path, ec);
  if (ec || !existed) {
    existed = false;
    return true;
  }
  const auto size = std::filesystem::file_size(path, ec);
  if (ec) {
    return false;
  }
  if (size > max_bytes) {
    return false;
  }
  std::FILE* fp = std::fopen(path.c_str(), "rb");
  if (fp == nullptr) {
    return false;
  }
  out.assign(static_cast<std::size_t>(size), 0);
  std::size_t read_total = 0;
  while (read_total < out.size()) {
    const std::size_t got = std::fread(out.data() + read_total, 1, out.size() - read_total, fp);
    if (got == 0) {
      break;
    }
    read_total += got;
  }
  std::fclose(fp);
  out.resize(read_total);
  return true;
}

[[nodiscard]] Status truncate_file(const std::string& path, std::uint64_t new_size) {
  std::error_code ec;
  std::filesystem::resize_file(path, new_size, ec);
  if (ec) {
    return Outcome(Status::Unavailable, "could not truncate the log at the last valid record");
  }
  return Status::Ok;
}

[[nodiscard]] std::string sibling_path(const std::string& path, const char* suffix) {
  return path + suffix;
}

/// Resolve leftover compaction artifacts so that the primary path is the
/// authoritative generation.
[[nodiscard]] Status settle_compaction_artifacts(const std::string& path) {
  std::error_code ec;
  const std::string fresh = sibling_path(path, ".new");
  const std::string previous = sibling_path(path, ".old");
  const bool has_fresh = std::filesystem::exists(fresh, ec) && !ec;
  const bool has_previous = std::filesystem::exists(previous, ec) && !ec;
  const bool has_primary = std::filesystem::exists(path, ec) && !ec;

  if (!has_primary && has_fresh) {
    // The new log was fully written and synced, but the swap did not finish.
    std::filesystem::rename(fresh, path, ec);
    if (ec) {
      return Outcome(Status::Unavailable, "could not promote a completed compaction artifact");
    }
    std::error_code cleanup;
    std::filesystem::remove(previous, cleanup);
    return Status::Ok;
  }
  if (has_primary && has_fresh) {
    // The old log was never moved aside, so the compaction was not committed.
    std::error_code cleanup;
    std::filesystem::remove(fresh, cleanup);
  }
  if (has_primary && has_previous) {
    std::error_code cleanup;
    std::filesystem::remove(previous, cleanup);
  } else if (!has_primary && has_previous) {
    std::filesystem::rename(previous, path, ec);
    if (ec) {
      return Outcome(Status::Unavailable, "could not restore the previous log generation");
    }
  }
  return Status::Ok;
}

}  // namespace

const char* record_type_name(RecordType t) noexcept {
  switch (t) {
    case RecordType::Intent:
      return "INTENT";
    case RecordType::Commit:
      return "COMMIT";
    case RecordType::Snapshot:
      return "SNAPSHOT";
    case RecordType::CleanShutdown:
      return "CLEAN_SHUTDOWN";
    case RecordType::EpochMarker:
      return "EPOCH_MARKER";
    case RecordType::Abort:
      return "ABORT";
  }
  return "INVALID";
}

const char* recovery_fidelity_name(RecoveryFidelity f) noexcept {
  switch (f) {
    case RecoveryFidelity::Exact:
      return "EXACT";
    case RecoveryFidelity::TornTailTruncated:
      return "TORN_TAIL_TRUNCATED";
    case RecoveryFidelity::DegradedTruncated:
      return "DEGRADED_TRUNCATED";
    case RecoveryFidelity::AmbiguousIntentResolved:
      return "AMBIGUOUS_INTENT_RESOLVED";
    case RecoveryFidelity::Corrupt:
      return "CORRUPT";
    case RecoveryFidelity::Incompatible:
      return "INCOMPATIBLE";
    case RecoveryFidelity::Missing:
      return "MISSING";
  }
  return "INVALID";
}

StoreOptions StoreOptions::for_tests() {
  StoreOptions options;
  options.max_log_bytes = 1U << 20;
  options.max_records = 8192;
  options.max_record_bytes = 1U << 20;
  options.compact_threshold_bytes = 1U << 18;
  options.compact_threshold_records = 1024;
  options.truncate_unreadable_tail = true;
  options.durable_writes = true;
  return options;
}

// ---------------------------------------------------------------------------
// Payload codecs
// ---------------------------------------------------------------------------

std::vector<Byte> encode_intent_payload(std::uint64_t intent_id, ArbSeq arbitration,
                                        const std::vector<StateChange>& changes) {
  Writer writer(WireLimits{16U << 20, 4096, 1U << 20, 8});
  writer.u64(intent_id);
  writer.u64(arbitration.value);
  writer.u32(static_cast<std::uint32_t>(changes.size()));
  for (const auto& change : changes) {
    encode(writer, change);
  }
  return writer.buffer();
}

Expected<std::vector<StateChange>> decode_intent_payload(ByteSpan payload, std::uint64_t& intent_id,
                                                         ArbSeq& arbitration) {
  Reader reader(payload, WireLimits{16U << 20, 4096, 1U << 20, 8});
  auto id = reader.u64();
  if (!id.ok()) return id.status();
  intent_id = id.value();
  auto arb = reader.u64();
  if (!arb.ok()) return arb.status();
  arbitration = ArbSeq{arb.value()};
  auto count = reader.u32();
  if (!count.ok()) return count.status();
  if (count.value() > (1U << 20)) {
    return Outcome(Status::LimitExceeded, "intent change count exceeds the hard bound");
  }
  std::vector<StateChange> changes;
  changes.reserve(count.value());
  for (std::uint32_t i = 0; i < count.value(); ++i) {
    auto change = decode_state_change(reader);
    if (!change.ok()) return change.status();
    changes.push_back(std::move(change.value()));
  }
  if (reader.require_end() != Status::Ok) {
    return Outcome(Status::Invalid, "intent payload has trailing bytes");
  }
  return changes;
}

Digest256 chain_hash(const std::array<Byte, 32>& previous, ByteSpan header, ByteSpan payload) {
  Sha256 hasher;
  hasher.update(ByteSpan(previous.data(), previous.size()));
  hasher.update(header);
  hasher.update(payload);
  return hasher.finish();
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

Store::Store(Store&& other) noexcept
    : file_(other.file_),
      path_(std::move(other.path_)),
      options_(other.options_),
      sequence_(other.sequence_),
      log_bytes_(other.log_bytes_),
      record_count_(other.record_count_),
      chain_(other.chain_),
      durable_(other.durable_) {
  other.file_ = nullptr;
}

Store& Store::operator=(Store&& other) noexcept {
  if (this != &other) {
    close();
    file_ = other.file_;
    path_ = std::move(other.path_);
    options_ = other.options_;
    sequence_ = other.sequence_;
    log_bytes_ = other.log_bytes_;
    record_count_ = other.record_count_;
    chain_ = other.chain_;
    durable_ = other.durable_;
    other.file_ = nullptr;
  }
  return *this;
}

Store::~Store() { close(); }

void Store::close() {
  if (file_ != nullptr) {
    (void)sync_file(file_);
    std::fclose(file_);
    file_ = nullptr;
  }
}

Expected<ReplayResult> Store::open(const std::string& path, const StoreOptions& options) {
  if (path.empty()) {
    return Outcome(Status::Invalid, "store path must not be empty");
  }
  if (options.max_record_bytes == 0 || options.max_log_bytes == 0 || options.max_records == 0) {
    return Outcome(Status::Invalid, "store bounds must be non-zero");
  }
  if (file_ != nullptr) {
    return Outcome(Status::Busy, "store is already open");
  }

  const Status settled = settle_compaction_artifacts(path);
  if (settled != Status::Ok) {
    return settled;
  }

  ReplayResult result;
  std::vector<Byte> data;
  bool existed = false;
  const std::size_t read_cap = options.max_log_bytes + options.max_record_bytes + 4096;
  if (!read_whole_file(path, data, read_cap, existed)) {
    return Outcome(Status::Unavailable,
                   "store file is unreadable or larger than its configured bound");
  }

  path_ = path;
  options_ = options;
  durable_ = options.durable_writes;
  chain_.fill(0);

  if (!existed || data.size() < kStoreFileHeaderBytes) {
    result.report.fidelity = RecoveryFidelity::Missing;
    result.report.detail = existed ? "store file was shorter than its header" : "no store file";
    std::array<Byte, kStoreFileHeaderBytes> header{};
    put_u32(header.data() + kFileMagicOffset, kFileMagic);
    put_u32(header.data() + kFileVersionOffset, kStoreFormatVersion);
    put_u32(header.data() + kFileHeaderBytesOffset,
            static_cast<std::uint32_t>(kStoreFileHeaderBytes));
    put_u32(header.data() + kFileEndianOffset, kEndianMarker);
    put_u64(header.data() + kFileCreatedOffset, 0);
    const StoreId store_id = StoreId::random();
    put_u64(header.data() + kFileStoreIdOffset, store_id.raw().hi);
    put_u64(header.data() + kFileStoreIdOffset + 8, store_id.raw().lo);
    put_u32(header.data() + kFileCrcOffset, crc32c(ByteSpan(header.data(), kFileCrcOffset)));
    std::FILE* fp = std::fopen(path.c_str(), "wb");
    if (fp == nullptr) {
      return Outcome(Status::Unavailable, "could not create the store file");
    }
    const bool wrote = std::fwrite(header.data(), 1, header.size(), fp) == header.size();
    const Status synced = wrote ? sync_file(fp) : Status::Unavailable;
    std::fclose(fp);
    if (!wrote) {
      return Outcome(Status::Unavailable, "could not write the store header");
    }
    if (synced != Status::Ok) {
      return synced;
    }
    file_ = std::fopen(path.c_str(), "r+b");
    if (file_ == nullptr) {
      return Outcome(Status::Unavailable, "could not reopen the freshly created store");
    }
    if (std::fseek(file_, 0, SEEK_END) != 0) {
      close();
      return Outcome(Status::Unavailable, "could not seek the freshly created store");
    }
    result.report.store_id = store_id;
    result.report.format_version = kStoreFormatVersion;
    sequence_ = 1;
    log_bytes_ = kStoreFileHeaderBytes;
    record_count_ = 0;
    return result;
  }

  if (get_u32(data.data() + kFileMagicOffset) != kFileMagic) {
    result.report.fidelity = RecoveryFidelity::Corrupt;
    result.report.detail = "store file magic does not match";
    return result;
  }
  if (get_u32(data.data() + kFileEndianOffset) != kEndianMarker) {
    result.report.fidelity = RecoveryFidelity::Incompatible;
    result.report.detail = "store endianness marker does not match";
    return result;
  }
  const std::uint32_t version = get_u32(data.data() + kFileVersionOffset);
  result.report.format_version = version;
  if (version != kStoreFormatVersion) {
    result.report.fidelity = RecoveryFidelity::Incompatible;
    result.report.detail = "store format version " + std::to_string(version) +
                           " is not understood by this build";
    return result;
  }
  if (get_u32(data.data() + kFileHeaderBytesOffset) != kStoreFileHeaderBytes) {
    result.report.fidelity = RecoveryFidelity::Incompatible;
    result.report.detail = "store header length is not the expected size";
    return result;
  }
  if (crc32c(ByteSpan(data.data(), kFileCrcOffset)) != get_u32(data.data() + kFileCrcOffset)) {
    result.report.fidelity = RecoveryFidelity::Corrupt;
    result.report.detail = "store header checksum does not match";
    return result;
  }
  result.report.store_id = StoreId::from_raw(
      Id128{get_u64(data.data() + kFileStoreIdOffset), get_u64(data.data() + kFileStoreIdOffset + 8)});

  std::array<Byte, 32> chain{};
  chain.fill(0);
  std::size_t offset = kStoreFileHeaderBytes;
  std::uint64_t expected_sequence = 1;
  std::uint64_t open_intent = 0;
  bool have_open_intent = false;
  std::size_t last_valid_offset = offset;
  RecoveryFidelity fidelity = RecoveryFidelity::Exact;
  std::string detail;
  bool stop = false;

  const auto drop_tail = [&](RecoveryFidelity candidate, const std::string& why) {
    fidelity = candidate;
    detail = why;
    result.report.dropped_tail_bytes = data.size() - last_valid_offset;
    stop = true;
  };

  while (!stop && offset < data.size()) {
    const std::size_t remaining = data.size() - offset;
    if (remaining < kStoreRecordHeaderBytes) {
      const ByteSpan tail(data.data() + offset, remaining);
      if (all_zero(tail)) {
        drop_tail(RecoveryFidelity::DegradedTruncated, "zero-filled trailing bytes discarded");
      } else {
        drop_tail(RecoveryFidelity::TornTailTruncated, "incomplete trailing record header");
      }
      break;
    }
    const Byte* header = data.data() + offset;
    if (get_u32(header + kRecMagicOffset) != kRecordMagic) {
      const ByteSpan tail(data.data() + offset, remaining);
      if (all_zero(tail)) {
        drop_tail(RecoveryFidelity::DegradedTruncated, "zero-filled trailing bytes discarded");
      } else {
        fidelity = RecoveryFidelity::Corrupt;
        detail = "record magic mismatch at offset " + std::to_string(offset);
        stop = true;
      }
      break;
    }
    if (get_u16(header + kRecVersionOffset) != kRecordHeaderVersion) {
      fidelity = RecoveryFidelity::Incompatible;
      detail = "record header version mismatch at offset " + std::to_string(offset);
      break;
    }
    const std::uint8_t type_value = header[kRecTypeOffset];
    if (type_value < static_cast<std::uint8_t>(RecordType::Intent) ||
        type_value > static_cast<std::uint8_t>(RecordType::Abort)) {
      fidelity = RecoveryFidelity::Corrupt;
      detail = "unknown record type at offset " + std::to_string(offset);
      break;
    }
    const RecordType type = static_cast<RecordType>(type_value);
    const std::uint32_t payload_len = get_u32(header + kRecLengthOffset);
    if (payload_len > options.max_record_bytes) {
      fidelity = RecoveryFidelity::Corrupt;
      detail = "record length exceeds the configured bound at offset " + std::to_string(offset);
      break;
    }
    const std::size_t record_bytes = kStoreRecordHeaderBytes + payload_len + kStoreChainBytes;
    if (record_bytes > remaining) {
      const ByteSpan tail(data.data() + offset, remaining);
      if (all_zero(tail)) {
        drop_tail(RecoveryFidelity::DegradedTruncated, "zero-filled trailing bytes discarded");
      } else {
        drop_tail(RecoveryFidelity::TornTailTruncated, "incomplete trailing record payload");
      }
      break;
    }
    const ByteSpan payload(data.data() + offset + kStoreRecordHeaderBytes, payload_len);
    const ByteSpan stored_chain(data.data() + offset + kStoreRecordHeaderBytes + payload_len,
                                kStoreChainBytes);
    const bool last_record = (offset + record_bytes) == data.size();
    if (crc32c(payload) != get_u32(header + kRecCrcOffset)) {
      const ByteSpan tail(data.data() + offset, remaining);
      if (all_zero(tail) || last_record) {
        drop_tail(RecoveryFidelity::TornTailTruncated,
                  "trailing record payload checksum mismatch");
      } else {
        fidelity = RecoveryFidelity::Corrupt;
        detail = "record payload checksum mismatch at offset " + std::to_string(offset) +
                 " with further records present";
      }
      break;
    }
    const Digest256 computed = chain_hash(chain, ByteSpan(header, kStoreRecordHeaderBytes), payload);
    if (std::memcmp(computed.bytes().data(), stored_chain.data(), kStoreChainBytes) != 0) {
      fidelity = RecoveryFidelity::Corrupt;
      detail = "record chain hash mismatch at offset " + std::to_string(offset);
      break;
    }
    const std::uint64_t sequence = get_u64(header + kRecSequenceOffset);
    if (sequence != expected_sequence) {
      fidelity = RecoveryFidelity::Corrupt;
      detail = "record sequence " + std::to_string(sequence) + " where " +
               std::to_string(expected_sequence) + " was required at offset " +
               std::to_string(offset);
      break;
    }

    const std::uint64_t intent_id = get_u64(header + kRecIntentOffset);
    const std::uint64_t at_ms = get_u64(header + kRecAtOffset);
    const Incarnation origin = Incarnation::from_raw(
        Id128{get_u64(header + kRecIncHiOffset), get_u64(header + kRecIncLoOffset)});
    if (!origin.is_nil()) {
      result.last_incarnation = origin;
    }

    switch (type) {
      case RecordType::Intent: {
        if (have_open_intent) {
          fidelity = RecoveryFidelity::Corrupt;
          detail = "intent record while a previous intent was still open";
          stop = true;
          break;
        }
        std::uint64_t decoded_intent = 0;
        ArbSeq arbitration{};
        auto changes = decode_intent_payload(payload, decoded_intent, arbitration);
        if (!changes.ok()) {
          fidelity = RecoveryFidelity::Corrupt;
          detail = "intent payload could not be decoded: " + changes.detail();
          stop = true;
          break;
        }
        if (decoded_intent != intent_id) {
          fidelity = RecoveryFidelity::Corrupt;
          detail = "intent identity in the header and payload disagree";
          stop = true;
          break;
        }
        ReplayAction action;
        action.kind = ReplayAction::Kind::Changes;
        action.changes = std::move(changes.value());
        action.arbitration = arbitration;
        action.at_ms = at_ms;
        action.intent_id = intent_id;
        action.origin = origin;
        result.actions.push_back(std::move(action));
        open_intent = intent_id;
        have_open_intent = true;
        break;
      }
      case RecordType::Commit: {
        if (!have_open_intent || open_intent != intent_id) {
          fidelity = RecoveryFidelity::Corrupt;
          detail = "commit record does not match the open intent";
          stop = true;
          break;
        }
        result.actions.back().committed = true;
        have_open_intent = false;
        break;
      }
      case RecordType::Snapshot: {
        Reader reader(payload, WireLimits{options.max_record_bytes, 4096, 1U << 20, 8});
        auto snapshot = decode_snapshot(reader);
        if (!snapshot.ok() || reader.require_end() != Status::Ok) {
          fidelity = RecoveryFidelity::Corrupt;
          detail = "snapshot record could not be decoded";
          stop = true;
          break;
        }
        ReplayAction action;
        action.kind = ReplayAction::Kind::Snapshot;
        action.snapshot = std::move(snapshot.value());
        action.at_ms = at_ms;
        action.intent_id = intent_id;
        action.origin = origin;
        action.committed = true;
        result.actions.push_back(std::move(action));
        result.report.snapshots_seen += 1;
        break;
      }
      case RecordType::Abort: {
        if (!have_open_intent || open_intent != intent_id) {
          fidelity = RecoveryFidelity::Corrupt;
          detail = "abort record does not match the open intent";
          stop = true;
          break;
        }
        result.actions.back().committed = true;
        result.actions.back().aborted = true;
        have_open_intent = false;
        break;
      }
      case RecordType::CleanShutdown:
      case RecordType::EpochMarker: {
        Reader reader(payload, WireLimits{4096, 4096, 4096, 8});
        auto value = reader.u64();
        if (!value.ok()) {
          fidelity = RecoveryFidelity::Corrupt;
          detail = "marker record payload could not be decoded";
          stop = true;
          break;
        }
        if (type == RecordType::EpochMarker) {
          result.epoch = Epoch{value.value()};
        }
        break;
      }
    }
    if (stop) {
      break;
    }

    chain = computed.bytes();
    offset += record_bytes;
    last_valid_offset = offset;
    ++expected_sequence;
    result.report.records_read += 1;
    result.report.bytes_read += record_bytes;
  }

  std::size_t ambiguous = 0;
  for (auto& action : result.actions) {
    if (action.kind != ReplayAction::Kind::Changes || action.committed) {
      continue;
    }
    action.ambiguous = true;
    ++ambiguous;
  }
  result.report.ambiguous_intents = ambiguous;
  if (have_open_intent) {
    detail = detail.empty() ? "final intent had no completion record" : detail;
    if (fidelity == RecoveryFidelity::Exact) {
      fidelity = RecoveryFidelity::AmbiguousIntentResolved;
    }
  }
  result.report.fidelity = fidelity;
  result.report.detail = detail;
  result.report.chain_head = Digest256(chain);

  if (!result.report.servable()) {
    // Authoritative state can not be proven from this store. Leave it closed so
    // that nothing can be appended to a log we do not understand.
    return result;
  }

  if (last_valid_offset < data.size()) {
    if (!options.truncate_unreadable_tail) {
      return Outcome(Status::Unavailable, "store has a damaged tail and truncation is disabled");
    }
    const Status truncated = truncate_file(path, last_valid_offset);
    if (truncated != Status::Ok) {
      return truncated;
    }
    result.report.truncated_on_open = true;
  }

  if (last_valid_offset > static_cast<std::size_t>(std::numeric_limits<long>::max())) {
    return Outcome(Status::LimitExceeded, "recovered log offset does not fit the file seek type");
  }
  file_ = std::fopen(path.c_str(), "r+b");
  if (file_ == nullptr) {
    return Outcome(Status::Unavailable, "could not reopen the store for appending");
  }
  if (std::fseek(file_, static_cast<long>(last_valid_offset), SEEK_SET) != 0) {
    close();
    return Outcome(Status::Unavailable, "could not seek to the end of the recovered log");
  }
  chain_ = chain;
  sequence_ = expected_sequence;
  log_bytes_ = last_valid_offset;
  record_count_ = result.report.records_read;

  if (have_open_intent) {
    // The log ended with an intent whose completion record never reached disk.
    // Record the conservative resolution now, so that a later restart sees a
    // complete transaction history and a subsequent append cannot produce two
    // consecutive intents.
    const Status closed = append_abort(open_intent, 0);
    if (closed != Status::Ok) {
      close();
      return Outcome(Status::Unavailable,
                     "an uncommitted trailing intent could not be closed in the log");
    }
    const Status flushed = flush();
    if (flushed != Status::Ok) {
      close();
      return flushed;
    }
    result.report.aborted_intents += 1;
    result.report.resolution_written_on_open = true;
  }
  return result;
}

Status Store::write_record(RecordType type, std::uint64_t intent_id, std::uint64_t at_ms,
                           Incarnation origin, ByteSpan payload, bool count_toward_limits) {
  if (file_ == nullptr) {
    return Outcome(Status::Unavailable, "store is not open");
  }
  if (payload.size() > options_.max_record_bytes) {
    return Outcome(Status::LimitExceeded, "record payload exceeds the configured bound");
  }
  const std::size_t record_bytes = kStoreRecordHeaderBytes + payload.size() + kStoreChainBytes;
  if (count_toward_limits) {
    if (log_bytes_ > options_.max_log_bytes ||
        record_bytes > options_.max_log_bytes - log_bytes_) {
      return Outcome(Status::LimitExceeded, "log would exceed its configured byte bound");
    }
    if (record_count_ >= options_.max_records) {
      return Outcome(Status::LimitExceeded, "log would exceed its configured record bound");
    }
  }

  std::array<Byte, kStoreRecordHeaderBytes> header{};
  put_u32(header.data() + kRecMagicOffset, kRecordMagic);
  put_u16(header.data() + kRecVersionOffset, kRecordHeaderVersion);
  header[kRecTypeOffset] = static_cast<Byte>(type);
  header[kRecFlagsOffset] = 0;
  put_u32(header.data() + kRecLengthOffset, static_cast<std::uint32_t>(payload.size()));
  put_u32(header.data() + kRecCrcOffset, crc32c(payload));
  put_u64(header.data() + kRecSequenceOffset, sequence_);
  put_u64(header.data() + kRecIntentOffset, intent_id);
  put_u64(header.data() + kRecAtOffset, at_ms);
  put_u64(header.data() + kRecIncHiOffset, origin.raw().hi);
  put_u64(header.data() + kRecIncLoOffset, origin.raw().lo);

  const Digest256 chain = chain_hash(chain_, ByteSpan(header.data(), header.size()), payload);

  if (std::fwrite(header.data(), 1, header.size(), file_) != header.size()) {
    return Outcome(Status::Unavailable, "short write of a record header");
  }
  if (!payload.empty() && std::fwrite(payload.data(), 1, payload.size(), file_) != payload.size()) {
    return Outcome(Status::Unavailable, "short write of a record payload");
  }
  if (std::fwrite(chain.bytes().data(), 1, chain.bytes().size(), file_) != chain.bytes().size()) {
    return Outcome(Status::Unavailable, "short write of a record chain hash");
  }

  chain_ = chain.bytes();
  sequence_ += 1;
  log_bytes_ += record_bytes;
  record_count_ += 1;
  return Status::Ok;
}

Status Store::append_intent(std::uint64_t intent_id, ArbSeq arbitration,
                            const std::vector<StateChange>& changes, std::uint64_t at_ms,
                            Incarnation origin) {
  const std::vector<Byte> payload = encode_intent_payload(intent_id, arbitration, changes);
  return write_record(RecordType::Intent, intent_id, at_ms, origin,
                      ByteSpan(payload.data(), payload.size()), true);
}

Status Store::append_commit(std::uint64_t intent_id, std::uint64_t at_ms) {
  std::array<Byte, 8> payload{};
  put_u64(payload.data(), intent_id);
  return write_record(RecordType::Commit, intent_id, at_ms, Incarnation{},
                      ByteSpan(payload.data(), payload.size()), true);
}

Status Store::append_clean_shutdown(std::uint64_t at_ms) {
  std::array<Byte, 8> payload{};
  put_u64(payload.data(), at_ms);
  return write_record(RecordType::CleanShutdown, 0, at_ms, Incarnation{},
                      ByteSpan(payload.data(), payload.size()), true);
}

Status Store::append_snapshot(const AuthoritySnapshot& snapshot, std::uint64_t at_ms,
                              Incarnation origin) {
  Writer writer(WireLimits{options_.max_record_bytes, 4096, 1U << 20, 8});
  encode(writer, snapshot);
  return write_record(RecordType::Snapshot, 0, at_ms, origin, writer.span(), true);
}

Status Store::append_abort(std::uint64_t intent_id, std::uint64_t at_ms) {
  std::array<Byte, 8> payload{};
  put_u64(payload.data(), intent_id);
  return write_record(RecordType::Abort, intent_id, at_ms, Incarnation{},
                      ByteSpan(payload.data(), payload.size()), true);
}

Status Store::flush() {
  if (file_ == nullptr) {
    return Outcome(Status::Unavailable, "store is not open");
  }
  if (!durable_) {
    if (std::fflush(file_) != 0) {
      return Outcome(Status::Unavailable, describe_errno("fflush"));
    }
    return Status::Ok;
  }
  return sync_file(file_);
}

bool Store::needs_compaction() const noexcept {
  return log_bytes_ >= options_.compact_threshold_bytes ||
         record_count_ >= options_.compact_threshold_records;
}

Status Store::compact(const AuthoritySnapshot& snapshot, std::uint64_t at_ms, Incarnation origin) {
  if (path_.empty()) {
    return Outcome(Status::Unavailable, "store has no path");
  }
  Writer writer(WireLimits{options_.max_record_bytes, 4096, 1U << 20, 8});
  encode(writer, snapshot);
  const std::vector<Byte>& payload = writer.buffer();
  if (payload.size() > options_.max_record_bytes) {
    return Outcome(Status::LimitExceeded, "snapshot image exceeds the configured record bound");
  }

  const std::string fresh = sibling_path(path_, ".new");
  std::error_code ec;
  std::filesystem::remove(fresh, ec);

  std::FILE* out = std::fopen(fresh.c_str(), "wb");
  if (out == nullptr) {
    return Outcome(Status::Unavailable, "could not create the compaction artifact");
  }
  std::array<Byte, kStoreFileHeaderBytes> header{};
  put_u32(header.data() + kFileMagicOffset, kFileMagic);
  put_u32(header.data() + kFileVersionOffset, kStoreFormatVersion);
  put_u32(header.data() + kFileHeaderBytesOffset,
          static_cast<std::uint32_t>(kStoreFileHeaderBytes));
  put_u32(header.data() + kFileEndianOffset, kEndianMarker);
  const StoreId store_id = StoreId::random();
  put_u64(header.data() + kFileStoreIdOffset, store_id.raw().hi);
  put_u64(header.data() + kFileStoreIdOffset + 8, store_id.raw().lo);
  put_u32(header.data() + kFileCrcOffset, crc32c(ByteSpan(header.data(), kFileCrcOffset)));
  bool ok = std::fwrite(header.data(), 1, header.size(), out) == header.size();

  std::array<Byte, kStoreRecordHeaderBytes> record{};
  put_u32(record.data() + kRecMagicOffset, kRecordMagic);
  put_u16(record.data() + kRecVersionOffset, kRecordHeaderVersion);
  record[kRecTypeOffset] = static_cast<Byte>(RecordType::Snapshot);
  put_u32(record.data() + kRecLengthOffset, static_cast<std::uint32_t>(payload.size()));
  put_u32(record.data() + kRecCrcOffset, crc32c(ByteSpan(payload.data(), payload.size())));
  put_u64(record.data() + kRecSequenceOffset, 1);
  put_u64(record.data() + kRecIntentOffset, 0);
  put_u64(record.data() + kRecAtOffset, at_ms);
  put_u64(record.data() + kRecIncHiOffset, origin.raw().hi);
  put_u64(record.data() + kRecIncLoOffset, origin.raw().lo);
  std::array<Byte, 32> zero_chain{};
  zero_chain.fill(0);
  const Digest256 chain = chain_hash(zero_chain, ByteSpan(record.data(), record.size()),
                                     ByteSpan(payload.data(), payload.size()));
  if (ok) {
    ok = std::fwrite(record.data(), 1, record.size(), out) == record.size();
  }
  if (ok && !payload.empty()) {
    ok = std::fwrite(payload.data(), 1, payload.size(), out) == payload.size();
  }
  if (ok) {
    ok = std::fwrite(chain.bytes().data(), 1, chain.bytes().size(), out) == chain.bytes().size();
  }
  const Status synced = ok ? sync_file(out) : Status::Unavailable;
  std::fclose(out);
  if (!ok) {
    std::error_code cleanup;
    std::filesystem::remove(fresh, cleanup);
    return Outcome(Status::Unavailable, "compaction artifact could not be written");
  }
  if (synced != Status::Ok) {
    std::error_code cleanup;
    std::filesystem::remove(fresh, cleanup);
    return synced;
  }

  close();
  const std::string previous = sibling_path(path_, ".old");
  std::filesystem::remove(previous, ec);
  const bool had_primary = std::filesystem::exists(path_, ec) && !ec;
  if (had_primary) {
    std::filesystem::rename(path_, previous, ec);
    if (ec) {
      return Outcome(Status::Unavailable, "could not move the previous log generation aside");
    }
  }
  std::filesystem::rename(fresh, path_, ec);
  if (ec) {
    if (had_primary) {
      std::error_code restore_ec;
      std::filesystem::rename(previous, path_, restore_ec);
    }
    return Outcome(Status::Unavailable, "could not promote the compaction artifact");
  }
  std::filesystem::remove(previous, ec);

  file_ = std::fopen(path_.c_str(), "r+b");
  if (file_ == nullptr) {
    return Outcome(Status::Unavailable, "could not reopen the store after compaction");
  }
  if (std::fseek(file_, 0, SEEK_END) != 0) {
    close();
    return Outcome(Status::Unavailable, "could not seek the compacted log");
  }
  chain_ = chain.bytes();
  sequence_ = 2;
  log_bytes_ = kStoreFileHeaderBytes + kStoreRecordHeaderBytes + payload.size() + kStoreChainBytes;
  record_count_ = 1;
  return Status::Ok;
}

}  // namespace isf
