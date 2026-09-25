# Testing

## Policy

**There are no test timeouts in this project.**

* No CTest `TIMEOUT` property is set anywhere.
* No shell `timeout` wrapper is used.
* No watchdog declares a test successful.
* A child process that is expected to exit is observed with a bound, and a bound
  that expires is reported as a **failure**, after which the child is terminated
  so the suite can continue. It is never counted as a pass.

A hang is a defect to diagnose and fix, not something to mask.

## Running

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

Each suite is also a program:

```sh
./build/tests/isf_unit_tests --seed 12345 --verbose
./build/tests/isf_property_tests --seed 20260101 --iterations 500
./build/tests/isf_adversarial_tests --filter framing
./build/tests/isf_multiprocess_tests --list
```

Flags: `--seed N`, `--iterations N`, `--filter SUBSTR`, `--list`,
`--verbose`. The selected seed is printed in the summary line, and a failing run
prints a copy-pasteable reproduction command. `ISF_TEST_SEED` supplies a seed
when `--seed` is absent. `ISF_TEST_BINARY_DIR` tells the harness where to put
scratch state; `ISF_KEEP_SCRATCH=1` preserves it for inspection.

## Suites

### `isf_unit_tests`

Identities (hex and canonical round trips, malformed input rejection, seeded
determinism), SHA-256 against published vectors including the million-character
case, CRC-32C against its check vector, canonical wire encoding for every field
type with truncation and trailing-byte rejection, strict UTF-8 validation, container
count rejection, checked arithmetic, the capacity closure identity, the lifecycle
transition table, policy validation, record codecs, the full grant lifecycle with
exact ledger values at every step, overcommit refusal, the protected floor,
oversubscription authority, epoch and policy generation invalidation,
incarnation fencing, partition degradation, duplicate request rejection, lease
expiry, and the store's create, replay, torn tail, corrupt middle, splice, zero
tail, version, ambiguity, compaction, and bound behaviour.

### `isf_property_tests`

* **Determinism** — two authorities fed byte-identical requests produce identical
  state digests after every step.
* **Accounting closure** — after every operation the ledger closes, the
  oversubscribed figure is zero, and the buckets equal sums computed
  independently from the grant table.
* **Allocation ceiling** — obligations plus floor plus unavailable capacity never
  exceed the authoritative basis.
* **Differential model** — an independent `ReferenceLedger` class that shares no
  code with the authority predicts the allocatable headroom exactly, operation
  for operation.
* **Encoding stability** — random records survive encode → decode → encode with
  identical bytes.
* **Frame corruption** — a single-byte mutation of a valid frame is never
  accepted as a different payload.
* **Store prefix property** — truncating a log at a random offset yields either a
  conservative refusal or a strict prefix of the original transactions; a
  truncated log never yields more records than were written.
* **Store round trip** — a random mutation stream replayed from the log alone
  reproduces the authoritative digest and ledger exactly.
* **Arithmetic** — checked addition, subtraction, and multiplication never wrap.

### `isf_adversarial_tests`

Hostile framing over a real socket (bad magic, absurd declared length, corrupted
checksum, truncated frame, non-envelope payload), protocol version mismatch,
replayed and rewound session sequences, invalid UTF-8 and oversized names,
extreme amounts, duplicated request identities, stale generations and epochs,
attestations without evidence, epoch invalidation of live grants, damaged logs in
the middle and at the tail, incompatible format versions, oversized container
counts, connection floods, and trailing bytes on bodyless requests.

### `isf_concurrency_tests`

Sixteen threads competing for a finite path: exactly the number that fits
succeed, no more. Arbitration sequences are unique and the observed order is
replayed against a fresh authority, which must reproduce the daemon's decision
sequence. Four reader threads continuously verify the closure identity while a
writer mutates. Eight threads register the same site with the same incarnation
and converge on a single record at generation one. Repeated start/stop, ticker
running alongside mutations, and concurrent connect during shutdown.

### `isf_multiprocess_tests`

Real operating system processes over loopback TCP, never threads standing in for
processes:

* six independent `isfsited` processes competing for one path — exactly three
  succeed, the ledger closes, and nothing is overcommitted;
* `isfctl` driving the whole lifecycle as separate processes, including
  probe, register, attest, propose, evaluate, reserve, activate, acknowledge,
  verify, withdraw, and retire;
* hard kills at each durable-commit boundary
  (`intent-durable`, `applied`, `commit-durable`) followed by a restart that
  must recover conservatively, mark the grant ambiguous, refuse to advance it,
  and accept an explicit reconciliation;
* a crash during a capacity-releasing operation, after which the capacity must
  still be accounted for;
* a site agent hard-killed and replaced with a new incarnation, after which the
  old grant is withdrawing, historical, and fenced, the old incarnation's
  heartbeats are refused, and the capacity stays accounted for until reconciled;
* a clean restart that preserves the digest and ledger exactly while marking the
  recovered grant historical and unverified;
* a corrupt log that makes the daemon exit non-zero without publishing readiness.

## Sanitizers

`-DISF_SANITIZE=ON` builds with AddressSanitizer (and UndefinedBehaviorSanitizer
where the compiler provides it).

Verified on Windows x64 with MSVC 19.44 (Visual Studio 2022 Build Tools) and
`CMAKE_MSVC_RUNTIME_LIBRARY=MultiThreadedDLL`: the whole tree builds
warning-clean under `/W4 /WX` with `/fsanitize=address`, and all five suites
pass under AddressSanitizer in a RelWithDebInfo build.

AddressSanitizer found exactly one defect in this codebase while it was being
written: a unit test that stored `c_str()` pointers into temporaries and then
read freed memory. That test now owns its inputs. No memory error has been
reported in the library itself.

ThreadSanitizer is not available for this toolchain, so no data-race claim is
made. The concurrency suite instead proves behaviour: deterministic concurrent
reservation winners, readers that never observe a torn ledger, and clean
start/stop under load.

## What these tests do not prove

* Anything about real optical, switch, or fabric hardware.
* Multi-host behaviour. Everything measured here runs on one machine over
  loopback TCP.
* Authenticated or encrypted transport. The protocol has no authentication; the
  principal identities it records are audit labels supplied by the caller.
