# Wire protocol

## Transport

Loopback TCP. The client connects, performs one handshake, and then issues
requests strictly one at a time (the server's session-sequence check assumes
this). Every connection is independent; there is no multiplexing and no shared
state between connections other than the authority itself.

## Framing

```
offset  size  field
0       4     magic   0x31465349 ('I' 'S' 'F' '1') little endian
4       4     payload length
8       4     CRC-32C of the payload
12      4     flags, must be zero
16      N     payload
```

The decoder validates the declared length against the negotiated maximum
**before allocating anything**. A frame whose checksum does not match fails the
connection. A length above the bound fails the connection with
`LIMIT_EXCEEDED`. A non-zero flags word is rejected. The decoder's own buffer is
bounded, so a peer that sends a header and then nothing cannot make it grow
without limit.

## Handshake

The first frame on a connection must be a `HELLO`:

* `u16` protocol version, `Id128` client nonce, `u32` client's maximum frame
  size, `string` client kind.

The server answers `HELLO_ACK` carrying the negotiated version, a session
identity, its own incarnation, the current epoch, the negotiated frame bound, the
durable-store recovery fidelity, whether the store is servable, whether writes
are durable, and the store format version.

A version mismatch is answered with an `ERROR` frame whose status is
`VERSION_MISMATCH` and the connection is closed. The server never serves a
request on a connection that has not completed a handshake.

## Envelopes

Request:

```
u16      protocol version
u16      message type
u64      session sequence
Id128    request identity
bytes    body (u32 length prefix + payload)
```

Reply:

```
u16      protocol version
u16      message type
u64      session sequence (echoed)
Id128    request identity (echoed)
u8       status ordinal
string   detail
bytes    body
```

The client checks that the reply's identity and sequence match the outstanding
request; a mismatch is reported as `CONFLICTING` rather than accepted.

## Replay protection

Each connection carries a monotonically increasing session sequence starting at
one. A request whose sequence is less than or equal to the last accepted one is
answered with `DUPLICATE` and is **not** dispatched. The daemon additionally
rejects a grant proposal whose request identity already exists, so a replayed
proposal cannot create a second grant even on a fresh connection.

## Message catalogue

| Direction | Message | Body |
| --- | --- | --- |
| C→S | `HELLO` | protocol version, nonce, kind, frame bound |
| S→C | `HELLO_ACK` | version, session, incarnation, epoch, frame bound, store state |
| S→C | `ERROR` | empty body; status and detail in the envelope |
| C→S | `STATUS_REQUEST` | empty |
| C→S | `SITE_REGISTER` | descriptor, incarnation, epoch, time |
| C→S | `SITE_HEARTBEAT` | site, incarnation, generation, epoch, advertised capacity, time |
| C→S | `SITE_SET_STATE` | site, state, reason, time |
| C→S | `PATH_REGISTER` | descriptor, path generation, state, advertised, observed, time |
| C→S | `PATH_SET_STATE` | path, state, reason, time |
| C→S | `CAPACITY_ATTEST` | full attestation record |
| C→S | `OVERSUBSCRIBE` | full oversubscription authority record |
| C→S | `POLICY_INSTALL` | policy document, principal |
| C→S | `EPOCH_BUMP` | epoch, principal |
| C→S | `GRANT_PROPOSE` | full proposal |
| C→S | `GRANT_EVALUATE` / `GRANT_RESERVE` / `GRANT_ACTIVATE` / `GRANT_DEGRADE` / `GRANT_WITHDRAW` / `GRANT_RETIRE` / `GRANT_CANCEL` | grant operation (grant, actor, incarnation, epoch, generations, lease, time, reason) |
| C→S | `GRANT_ACKNOWLEDGE` | grant, actor, incarnation, epoch, time |
| C→S | `GRANT_VERIFY` | verification identity, grant, verifier, result, evidence digest, time, detail |
| C→S | `GRANT_RECONCILE` | grant operation, target state, principal |
| C→S | `LIST_SITES` / `LIST_PATHS` | empty |
| C→S | `LIST_GRANTS` | filter: include terminal, limit, path, site |
| C→S | `LEDGER_REQUEST` | path identity |
| C→S | `DIGEST_REQUEST` | empty |
| C→S | `SNAPSHOT_REQUEST` | empty |
| C→S | `TICK_REQUEST` | current time |
| C→S | `SHUTDOWN_REQUEST` | empty |
| S→C | `MUTATION_REPLY` | arbitration sequence, primary object, change list |
| S→C | `STATUS_REPLY` | full status report |
| S→C | `SITES_REPLY` / `PATHS_REPLY` / `GRANTS_REPLY` | record list |
| S→C | `LEDGER_REPLY` | path and derived ledger |
| S→C | `DIGEST_REPLY` | state digest, policy digest, counters |
| S→C | `SNAPSHOT_REPLY` | full authoritative snapshot |
| S→C | `SHUTDOWN_REPLY` | empty |

A mutation reply carries the post-images the mutation produced, capped at a
configured count. The reply's primary object identity identifies the record the
operation was about, so a client never has to parse the change list to find its
grant.

## Encoding rules

* Little-endian fixed-width integers, no padding, no field elision.
* Strings and byte fields are `u32` length prefixed.
* Strings must be valid UTF-8: overlong forms, surrogate halves, code points
  above U+10FFFF, truncated sequences, and lone continuation bytes are rejected.
* Repeated fields are `u32` count prefixed and validated against a bound and
  against the remaining payload before the reader reserves anything.
* A decoder requires the payload to be fully consumed; trailing bytes are
  `INVALID`.

The same encoder produces the canonical byte image used for the authoritative
state digest, so there is exactly one encoding of any record.
