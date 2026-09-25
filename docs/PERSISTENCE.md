# Durable state

## File layout

```
128-byte file header
record 1
record 2
...
```

### File header

```
offset  size  field
0       4     magic 0x4953464C ('I' 'S' 'F' 'L') little endian
4       4     format version
8       4     header length (128)
12      4     endianness marker 0x01020304
16      8     creation time (currently zero)
24      16    store identity
40      84    reserved, zero filled
124     4     CRC-32C of bytes 0..123
```

A magic mismatch is `CORRUPT`; an endianness-marker or header-length mismatch is
`INCOMPATIBLE`; a format version this build does not understand is
`INCOMPATIBLE`; a header checksum mismatch is `CORRUPT`.

### Record

```
offset  size  field
0       4     magic 0x49534652 ('I' 'S' 'F' 'R')
4       2     record header version (1)
6       1     record type
7       1     flags (zero)
8       4     payload length
12      4     CRC-32C of the payload
16      8     sequence number (1-based, strictly consecutive)
24      8     intent identity
32      8     timestamp
40      8     originating incarnation, high half
48      8     originating incarnation, low half
56      N     payload
56+N    32    SHA-256 chain hash
```

The chain hash is `SHA-256(previous chain || record header || payload)`, with an
all-zero previous chain for the first record. CRC-32C detects accidental damage;
the chain detects splicing, reordering, duplication, and middle truncation,
because repairing one checksum is not enough to make the stream self-consistent.
Sequence numbers must be strictly consecutive, which is a second, independent
check against reordering and duplication.

## Record types

| Type | Payload | Meaning |
| --- | --- | --- |
| `INTENT` | intent identity, arbitration sequence, change list | A mutation is about to be applied. |
| `COMMIT` | intent identity | The mutation completed. |
| `ABORT` | intent identity | The mutation's completion record never reached disk; its capacity-releasing changes are suppressed on every future replay. |
| `SNAPSHOT` | a full authoritative snapshot | Recovery starts here instead of at the beginning of time. |
| `CLEAN_SHUTDOWN` | timestamp | Informational marker written by a graceful stop. |
| `EPOCH_MARKER` | epoch | Informational marker. |

Exactly one intent may be open at a time. A second `INTENT` while one is open, a
`COMMIT` or `ABORT` that does not match the open intent, or an intent whose
header and payload identities disagree, are all `CORRUPT`.

## Recovery

Replay is forward-only and conservative.

* **Clean file** — every record validates: fidelity `EXACT`.
* **Torn tail** — the trailing region is incomplete (a short header, a short
  payload, or a checksum failure on the final record), or is entirely zero
  filled: the region is discarded from the last valid record boundary, the file
  is truncated there, and fidelity is `TORN_TAIL_TRUNCATED` or
  `DEGRADED_TRUNCATED`.
* **Uncommitted trailing intent** — the file ends with a complete intent and no
  completion record: fidelity `AMBIGUOUS_INTENT_RESOLVED`, the conservative
  resolution is recorded as an `ABORT` record so the log stays well formed, and
  the intent is reported as ambiguous.
* **Corruption in the middle** — a checksum or chain failure with further records
  present, a sequence discontinuity, a bad magic, an unknown record type, or an
  oversized declared length: fidelity `CORRUPT`. The store is left **closed** and
  the daemon refuses to serve authoritative state. Damage in the middle is never
  truncated away, because it cannot be distinguished from a deliberately edited
  log.
* **Incompatible** — format version, record header version, or endianness marker
  the build does not understand: the store is not served.

A daemon started against a store that is not servable exits with a non-zero code
and publishes no readiness file.

## Ambiguity handling

An intent without a completion record may or may not have taken effect. Recovery
resolves it in the only safe direction:

* changes that **release** capacity (grants reaching RETIRED, CANCELLED, or
  EXPIRED) are **not** applied;
* changes that acquire or retain capacity are applied, and the resulting grants
  are marked ambiguous with provenance `AMBIGUOUS_COMMIT`;
* applying a suppressed release is never silent: the count is reported in the
  recovery report and the affected grants remain in a withdrawing state until an
  operator or the holder reconciles them.

The result is that a crash can only ever leave capacity **more** consumed than
the caller was told, never less. Overcommit is therefore impossible to produce by
crashing.

## Recovered evidence is historical

Every recovered grant is marked `historical`, its verification state is reset to
`UNVERIFIED`, and its provenance becomes `RECOVERED_FROM_LOG`,
`RECOVERED_FROM_SNAPSHOT`, or `AMBIGUOUS_COMMIT`. Recovered dynamic evidence is
never silently treated as fresh.

## Compaction

When the log crosses a configured byte or record threshold the daemon writes a
snapshot of authoritative state and swaps the file:

1. write `<path>.new` containing a header and one `SNAPSHOT` record, then fsync;
2. rename `<path>` to `<path>.old`;
3. rename `<path>.new` to `<path>`;
4. remove `<path>.old`.

On open, leftover artifacts are settled deterministically: if the primary file is
missing and `<path>.new` exists, the new generation is promoted (it was fully
synced before the swap began); if the primary exists alongside `<path>.new`, the
compaction had not been committed and the artifact is discarded; a stale
`<path>.old` is removed, or restored if the primary went missing.

## Bounds

`StoreOptions` caps log bytes, record count, and single-record bytes. An append
that would exceed a bound fails with `LIMIT_EXCEEDED` instead of growing without
limit. Compaction thresholds and a recovery read cap prevent an oversized or
hostile file from being read into memory.
