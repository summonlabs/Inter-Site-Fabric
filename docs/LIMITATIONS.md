# Limitations

This document states what the runtime does **not** do, and what has not been
verified. It exists so that no claim is made beyond the evidence.

## Not implemented

* **Authentication and encryption.** The protocol has no authentication,
  no authorization check, and no transport security. Any client that can reach
  the listening socket can issue any request. The `PrincipalId` values in
  attestations, verifications, oversubscription authorities, and policy installs
  are audit labels supplied by the caller; the authority records them, it does
  not verify them.
* **Multi-daemon federation.** One daemon is authoritative for the sites and
  paths registered with it. There is no consensus protocol, no leader election,
  no replication between daemons, and no global federation authority.
* **Route computation.** The fabric consumes inter-site paths; it does not
  compute, discover, or repair them.
* **Physical or optical control.** There is no transceiver control, no optical
  power management, no switch or ASIC programming, and no vendor SDK integration.
* **Hardware acceleration.** No RDMA, InfiniBand, RoCE, NVLink, GPUDirect,
  CUDA, or SmartNIC path exists. The only transport is loopback TCP.
* **Workload placement or migration.** The runtime issues and revokes capacity
  authority. It does not move, replicate, or restart workloads.
* **Time synchronization.** Timestamps come from the local system clock. The
  runtime does not synchronize clocks and does not reason about clock skew. Lease
  and heartbeat decisions assume a single authoritative clock, which is the
  daemon's.
* **Remote listening by default.** The daemon binds `127.0.0.1` unless the
  operator names another host. It has not been tested over a real network and
  makes no claim about doing so safely.

## Verified only on

* **Windows x64 with MSVC 19.44 (Visual Studio 2022 Build Tools)**, building
  warning-clean under `/W4 /WX` in Release, RelWithDebInfo, and Debug, and with
  the full test suite passing under AddressSanitizer.
* **No ThreadSanitizer run.** It is not available for this toolchain, so no
  data-race claim is made; the concurrency suite proves behaviour instead.
* The POSIX code paths (BSD sockets, `fork`/`execv`, `fsync`, `waitpid`,
  `SIGKILL`) exist and are written to compile, but they have **not** been built,
  run, or tested in this environment. They are not claimed as verified.

## Measurement boundaries

* All throughput and latency figures come from the machine that ran the
  benchmark, over loopback TCP. They are not extrapolated to any other machine,
  network, or workload.
* No test asserts anything about physical link behaviour: no packet loss, no
  jitter, no congestion, no MTU effects, no hardware failure injection.
* Process kills are simulated with deliberate process termination
  (`TerminateProcess` on Windows, `SIGKILL` on POSIX) and with an in-process
  fail-stop hook that aborts between durable-commit stages. No power loss or
  storage-device failure is injected.

## Design constraints worth knowing

* **Acknowledgement is not verification.** A holder acknowledging a grant does
  not make it verified. Only an independent verification record does, and the
  runtime does not perform one on its own.
* **Recovered evidence is historical.** After any restart, recovered grants are
  marked historical, their verification is reset, and their provenance records
  where they came from. They are never silently treated as fresh.
* **Capacity is only released by a complete transaction.** A crash between the
  write-ahead intent and the completion record leaves releasing changes
  suppressed. The observable consequence is that a crash can make capacity
  *more* consumed than the caller expected, never less, and clearing that
  requires an explicit reconciliation.
* **A shortfall is reported, not hidden.** If the authoritative basis shrinks
  below what is already committed, or a policy floor rises above it, the ledger
  reports the shortfall as `oversubscribed` and the authority refuses new
  allocations. The authority's own invariant check treats a non-zero
  `oversubscribed` value as a violation, which fail-stops the daemon rather than
  serving a state it cannot justify.
* **One daemon, one store.** A store file must be used by exactly one daemon
  process at a time. There is no file locking and no multi-writer support.

## Unsupported statuses

`Status::UNSUPPORTED` is returned for message types a build does not implement,
rather than silently succeeding. No part of the runtime fabricates a positive
answer for an unimplemented request.
