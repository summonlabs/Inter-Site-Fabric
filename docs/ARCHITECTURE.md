# Architecture

## Layering

```
apps/isfd          apps/isfsited        apps/isfctl
        \               |                  /
         +--------------+-----------------+
                        |
                   isf::daemon      (Daemon, FabricServer, FabricClient)
                    /        \
             isf::store     isf::net   (Store, framing, loopback TCP)
                    \        /
                     isf::core          (identity, capacity, lifecycle,
                                         policy, authority, canonical encoding)
```

`isf::core` performs no I/O, takes no locks, and reads no clock. Time is a
parameter everywhere. That is what makes the authority testable as a pure state
machine and what makes the property tests meaningful.

## The authority

`Authority` is a deterministic state machine over sites, paths, shared-risk
domains, capacity attestations, grants, verifications, oversubscription
authorities, a policy, and an epoch.

Every mutation is a two-stage **plan then apply** pair:

* `plan_*(...)` computes the post-images of the records that would change, using
  current state, **without modifying anything**;
* `Authority::apply(changes, arb)` inserts those post-images into the record
  maps.

Because a plan is a list of complete record post-images, replay and live mutation
share exactly one code path. There is no separate "recovery logic" that could
drift from the live path.

## Request pipeline and lock ownership

Three locks exist, with a strict global order:

| Lock | Rank | Guards |
| --- | --- | --- |
| `commit_mutex_` | L1 | The whole plan → write intent → apply → write completion pipeline. |
| `state_mutex_` | L2 | The in-memory `Authority`. |
| `store_mutex_` | L3 | The `Store`. |

Rules that the implementation follows and the audit checked:

* L1 may be held while acquiring L2 or L3.
* **L2 and L3 are never held at the same time**, so no L2/L3 cycle exists and no
  lock-order inversion is possible.
* No callback, no socket operation, and no log sink is invoked while L2 or L3 is
  held. Replies are serialised after the locks are released.
* The only callback the daemon invokes, `commit_stage_hook`, is documented as a
  fail-stop injection point and is called with both L2 and L3 released.
* Server worker threads never acquire L1, which is why `stop()` can hold the
  connection registry mutex while joining them.
* The accept thread never joins a worker while that worker could need the
  registry mutex; workers never touch the registry at all.
* Mutating a container is never done through an iterator that a later step
  invalidates: plans are built into fresh vectors, and `apply` decodes every
  change before writing any of them, so an undecodable change set cannot apply
  partially.

## Determinism

A mutating request is assigned an `ArbSeq` (arbitration sequence) at the moment
it enters the pipeline under L1. Because L1 serialises the entire pipeline, the
sequence is a total order. The authority's resulting state is a pure function of
`(initial state, request order)`, which is why two runs that observe the same
arbitration order produce byte-identical state digests.

Where an operation must shed capacity — a policy floor rise, a capacity
reduction, a path going down — grants are withdrawn in **descending arbitration
order**, so even the choice of which obligations to shed is deterministic.
Protected obligations are shed last.

## Invariants

`Authority::verify_invariants` is checked after every applied mutation (the
daemon does this by default) and returns the first violation with an
explanation:

1. Every path's derived ledger satisfies the closure identity.
2. `unavailable <= authoritative_usable` for every path.
3. `oversubscribed == 0` for every path: obligations plus the floor plus
   unavailable capacity fit inside the authority ceiling. A shortfall here means
   capacity was promised that does not exist.
4. Protected obligations never exceed the policy protected floor.
5. Every live grant's recorded epoch, site incarnation, policy generation, path
   generation, and capacity generation still match live state.
6. Grant identities are non-nil; every grant carries a non-zero arbitration
   sequence; arbitration sequences and lease identities are unique.
7. Every grant references an existing path and an existing holder.
8. The installed policy is structurally valid and every configured container
   bound holds.

If any check fails after a mutation, the daemon marks its durability as lost and
refuses further mutations until it is restarted and recovered.

## Server ownership and shutdown

One accept thread owns the listener. Each accepted connection gets one worker
thread that owns that connection's socket and frame decoder.

`stop()`:

1. sets the stopping flag (so `accept` failures are not retried);
2. closes the listener and joins the accept thread;
3. shuts down every live socket so blocked receives return immediately;
4. joins the workers.

Steps 3 and 4 hold the registry mutex, which is safe precisely because workers
never acquire it. The worker is started **before** the connection becomes
reachable from the registry, so a concurrent `stop()` can never observe a
joinable-but-unset thread object.

## Error vocabulary

`Status` keeps failure modes distinct and no missing evidence is ever turned
into success:

`OK`, `UNKNOWN`, `UNSUPPORTED`, `STALE`, `CONFLICTING`, `INCOMPLETE`,
`INDETERMINATE`, `REFUSED`, `CANCELLED`, `INVALID`, `NOT_FOUND`,
`DUPLICATE`, `EXHAUSTED`, `DENIED`, `LIMIT_EXCEEDED`,
`INVALID_TRANSITION`, `CORRUPT`, `VERSION_MISMATCH`, `UNAUTHORIZED`,
`BUSY`, `EXPIRED`, `FENCED`, `UNAVAILABLE`, `AMBIGUOUS`.

## Bounds

Every unbounded quantity has a configured ceiling that is validated before use:
frame bytes, buffer bytes, record bytes, log bytes, record count, connections,
wire string length, repeated-field count, nesting depth, grants per path, grants
per site, sites, paths, domains, attestations, verifications, oversubscription
authorities, retries, and lease durations. All capacity arithmetic is checked;
overflow is reported, never wrapped.
