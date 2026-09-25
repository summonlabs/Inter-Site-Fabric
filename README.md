# Inter-Site Fabric

Inter-Site Fabric is a C++20 runtime for **controlled connectivity and capacity
authority between physical sites**. It answers one question, and refuses to guess
at the answer:

> Given authoritative site states, inter-site edges and paths, available
> capacity, reservations, failure domains, policy, and exact generations — which
> site-to-site connectivity is legal **now**, how much capacity is
> **authoritative**, and when must it be **reduced, fenced, or refused**?

It is an open-source project of Summon Software Labs, licensed under the Apache
License 2.0. It has no third-party runtime dependencies, no network egress of its
own, and no telemetry.

## What this runtime owns

* **Site-to-site connectivity authority.** Which endpoint pairs may hold
  capacity on which path, bound to exact site incarnations and generations.
* **Capacity authority.** The single number a path may be committed against, and
  the exact accounting of committed, reserved, withdrawing, protected,
  unavailable, and free capacity.
* **Lifecycle.** proposed → eligible → reserved → active → degraded →
  withdrawing → retired, with refusals, cancellations, and expiries as distinct
  terminal outcomes.
* **Fencing and recovery.** Stale site incarnations, superseded generations,
  ambiguous durable commits, and damaged logs.

## What this runtime deliberately does not own

* Each site's internals: scheduling, workloads, local storage, local networking.
* Generic route computation. The fabric consumes inter-site paths; it does not
  compute them.
* Optical hardware, transceivers, switch or ASIC configuration, and any vendor
  SDK integration.
* Workload migration and application replication policy.
* Global federation authority. One daemon is authoritative for the sites and
  paths registered with it; it does not form a federation with peers.

See [docs/LIMITATIONS.md](docs/LIMITATIONS.md) for the precise, verified boundary
of what is and is not implemented.

## Concepts

| Concept | Meaning |
| --- | --- |
| `SiteId` | A 128-bit identity for a physical site. |
| `Incarnation` | A 128-bit identity for one run of one site agent process. A new process gets a new incarnation; the previous one is fenced. |
| `Generation` | A monotonic counter on a site, a path, a capacity basis, or a policy document. Every grant records the generations it was issued against. |
| `Epoch` | A monotonic authority epoch. An epoch bump invalidates every live grant at once. |
| `PathId` / `EdgeId` | An inter-site path and the physical edge it runs over. |
| `DomainId` | A shared-risk domain: paths that can fail together. |
| `LeaseId` | The lease identity carried by one grant. |
| `ArbSeq` | The arbitration sequence assigned to a mutating request when it enters the authority. It is the total order that makes concurrent outcomes deterministic. |
| `Grant` | The authoritative answer to "may this site use this much capacity on this path, right now". |
| `Attestation` | Evidence that a path really has the capacity the authority will commit against. |

### Advertised, observed, and authoritative capacity

A path records three numbers. **Advertised** and **observed** capacity are
informational and are never allocatable. **Authoritative usable** capacity starts
at zero and only changes when a capacity attestation carrying an evidence digest
is accepted for the exact path and capacity generation. Nothing can be committed
against a path that has never been attested.

### Capacity accounting

The ledger for a path is derived, never incrementally maintained, and satisfies
one structural identity:

```
free + committed + reserved + protected_headroom + unavailable
  == authoritative_usable + authorized_extension + oversubscribed
```

* `committed` — grants in ACTIVE or DEGRADED: authorised obligations in force.
* `reserved` — grants in RESERVED.
* `protected_headroom` — the part of the policy floor not yet taken by
  protected obligations. Protected grants count in `committed`/`reserved`, so
  reporting the whole floor here would double count them.
* `unavailable` — capacity removed by maintenance, drain, or failure.
* `free` — the structural remainder.
* `allocatable` — what a new grant may actually consume. It is `free` minus
  capacity held by grants that are **withdrawing**: that capacity is no longer
  authorised but must not be reallocated until the holder has released it.
* `oversubscribed` — the derived shortfall when obligations plus the floor plus
  unavailable capacity exceed the basis. It is a *report*, never a permission,
  and the authority's own invariant check requires it to be zero.

Capacity is **never overbooked without explicit adjacent oversubscription
authority**. A live `OversubscriptionAuthority` record, bound to the exact path,
capacity, policy generations and epoch, raises the allocatable ceiling for
general capacity only. Protected obligations are never oversubscribed under any
circumstances, because general allocation can never dip into the protected floor.

### Acknowledgement is not verification

A holder acknowledging a grant records that the holder received it. It does not
change the grant's verification state and it is not evidence that connectivity
works. Only an `IndependentVerification` record, carrying a verifier identity
and an evidence digest, sets verification.

### Durable commit and ambiguity

Every mutation is written as a write-ahead **intent** record followed by a
**completion** record, each fsynced before the caller is told the mutation
succeeded. If the process dies between the two:

* changes that would **release** capacity are **not** applied — capacity is only
  released by a provably complete transaction;
* changes that acquire or retain capacity are applied and the resulting grants
  are marked `AMBIGUOUS` with provenance `AMBIGUOUS_COMMIT`, and they must be
  reconciled explicitly before they can advance.

On the next open, the store records that resolution as an explicit abort record,
so a later restart sees a complete history rather than re-deriving the decision.

## Building

Requirements: CMake 3.20 or newer, a C++20 compiler, and (for the test suite)
nothing else.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

Useful options:

| Option | Default | Meaning |
| --- | --- | --- |
| `ISF_BUILD_APPS` | ON | Build `isfd`, `isfsited`, `isfctl`. |
| `ISF_BUILD_TESTS` | ON | Build the unit, property, adversarial, concurrency, and multiprocess suites. |
| `ISF_BUILD_EXAMPLES` | ON | Build the embedded-authority and connectivity-probe examples. |
| `ISF_BUILD_BENCHMARKS` | ON | Build the completed-work benchmark program. |
| `ISF_WERROR` | ON | Promote warnings to errors. |
| `ISF_SANITIZE` | OFF | Build with AddressSanitizer (and UndefinedBehaviorSanitizer on GCC/Clang). |

## Installing and consuming

```sh
cmake --install build --prefix /path/to/prefix
```

```cmake
find_package(isf CONFIG REQUIRED)
target_link_libraries(my_target PRIVATE isf::daemon)
```

Exported targets: `isf::core`, `isf::store`, `isf::net`, `isf::daemon`.

A complete, independent downstream consumer lives in
[`examples/downstream_consumer`](examples/downstream_consumer). It is a separate
CMake project that is not part of this build; it is configured against an
installed prefix only.

## Running

```sh
# Start the daemon.
isfd --state ./fabric-state/daemon.isfstore --listen 127.0.0.1:7900 --ready-file ./ready.txt

# Inspect it.
isfctl --daemon 127.0.0.1:7900 status
isfctl --daemon 127.0.0.1:7900 site-register --name site-a --capacity 100000
isfctl --daemon 127.0.0.1:7900 path-register --path <PATH-ID> --name a-to-b \
       --a <SITE-A-ID> --b <SITE-B-ID>
isfctl --daemon 127.0.0.1:7900 attest --path <PATH-ID> --usable 100000
isfctl --daemon 127.0.0.1:7900 verify

# Run a site agent.
isfsited --daemon 127.0.0.1:7900 --site-name site-a --path <PATH-ID> \
         --reserve 10000 --heartbeat-ms 1000
```

`isfctl` also drives the whole grant lifecycle
(`grant-propose`, `grant-evaluate`, `grant-reserve`, `grant-activate`,
`grant-degrade`, `grant-withdraw`, `grant-retire`, `grant-cancel`,
`grant-ack`, `grant-verify`, `grant-reconcile`) and every authority
operation (`policy-install`, `epoch-bump`, `oversubscribe`, `site-state`,
`path-state`, `tick`, `shutdown`).

## Tests

Five suites, all built from the same in-tree harness with no external test
dependency:

| Suite | What it covers |
| --- | --- |
| `isf_unit_tests` | Identities, integrity primitives, canonical encoding, capacity arithmetic, lifecycle, policy, the authority state machine, and the durable store. |
| `isf_property_tests` | Seeded properties and differential models: determinism, accounting closure, allocation ceilings, encoding stability, frame corruption rejection, store prefix and round-trip properties. |
| `isf_adversarial_tests` | Hostile framing over a real socket, version mismatch, replay, invalid UTF-8, extreme values, duplicated identities, stale generations and epochs, damaged and incompatible durable state, connection floods. |
| `isf_concurrency_tests` | Deterministic concurrent reservation winners, arbitration-order determinism, reader consistency under a writer, repeated start/stop, ticker plus mutations, connect during shutdown. |
| `isf_multiprocess_tests` | Real independent OS processes over loopback TCP: competing site agents, hard process kills at each durable-commit boundary, crash-during-release, stale-incarnation fencing after an agent restart, clean restart, and a corrupt log refusing to serve. |

Every suite accepts `--seed N`, `--iterations N`, `--filter SUBSTR`, and
`--list`. A failing run prints the seed needed to reproduce it.

**There are no test timeouts anywhere in this project.** No CTest `TIMEOUT`
property is set, no shell timeout wrapper is used, and a hung child is reported
as a test failure rather than being killed and declared a pass. See
[docs/TESTING.md](docs/TESTING.md).

## Benchmarks

```sh
./build/benchmarks/isf_benchmarks --scale 1
```

Reports nanoseconds per operation and operations per second for authority
lifecycle steps, ledger derivation, canonical digesting, invariant verification,
wire encoding, framing, SHA-256, durable append and replay, log compaction, and
loopback round trips. Every number is measured on the machine that runs the
benchmark; none are extrapolated, and the transport measured is loopback TCP.

## Documentation

* [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — components, threading and lock
  ownership, determinism, invariants.
* [docs/PROTOCOL.md](docs/PROTOCOL.md) — framing, envelopes, message catalogue,
  replay protection, versioning.
* [docs/PERSISTENCE.md](docs/PERSISTENCE.md) — on-disk layout, integrity chain,
  recovery rules, compaction and ambiguity handling.
* [docs/TESTING.md](docs/TESTING.md) — what each suite proves and how to
  reproduce a failure.
* [docs/LIMITATIONS.md](docs/LIMITATIONS.md) — verified boundaries, unsupported
  claims, and honest constraints.

## Platform support

| Platform | Compiler | Status |
| --- | --- | --- |
| Windows x64 | MSVC 19.44 (Visual Studio 2022), `/W4 /WX` | Built, tested, and benchmarked here. |
| Linux | GCC 12+ / Clang 15+ | Source-level support; the build and tests are written portably, and POSIX sockets, `fork`/`execv`, and `fsync` paths exist. Not built or run as part of the verification recorded in this repository. |

The transport is loopback TCP only. There is no RDMA, InfiniBand, NVLink, or
switch/ASIC integration, and no claim is made about physical network behaviour.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Contributions are accepted under the
Apache License 2.0; no Contributor License Agreement is required.

## License

Apache License 2.0. Copyright 2026 Summon Software Labs. No telemetry transmission.
