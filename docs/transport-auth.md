# Transport identity and records: OLEP4

Identity protection was implemented for A03 on 2026-10-26; A04 added record replay
protection and bounded queues in OLEP3. A05 introduces OLEP4 with a bounded binary
UDP encoding and authenticated fragmentation. DIRECT and RELAY share
`internal/transportauth`; UDP-advertised keys are never a trust source.

## Trust and authorization

The authenticated endpoint `GET /api/v1/peers/{peerId}/transport-identities`
returns an envelope containing `networkId`, `local`, `peers` and
`expiresAtUnix`. Each identity contains `peerId`, `deviceId`, `publicKey`
(Base64 Ed25519 public key). The response has `Cache-Control: no-store`.

The requester must own the local peer. Local and remote identities must satisfy
all of these current repository checks:

- active user with permission to request a tunnel in the network;
- online peer in that network;
- active device owned by that peer's user, with a valid Ed25519 public key;
- device approval where the network requires it, including the existing owner exception.

An ineligible local identity rejects the request. Ineligible remote identities
are omitted; storage failures fail the whole request. The user repository is
required for identity snapshots even though older non-transport callers can
still construct a `PeerDirectory` without it.

The agent verifies that the local identity matches its enrollment and private
key. Private keys stay in local state and transport memory. They are not sent
to the endpoint or included in the handshake. A snapshot is accepted only from
HTTPS with the normal certificate checks, or HTTP on explicit loopback / localhost
for local development. Redirects are rejected. The authority is the configured
control plane; this does not protect against a compromised control plane/account
or a compromised local private key.

## Lifetime and changes

Server snapshots expire after 30 seconds. The client also caps the deadline at
30 seconds from the start of its request and retains a monotonic local deadline.
The agent refreshes at 10 seconds; a failed refresh immediately removes its
cached grant and retries at 5 seconds. The transports check expiration themselves
when starting a handshake, using a session and draining received packets, so a
stalled lifecycle cannot authorize new operations indefinitely.

Revocation, membership/role changes, device approval changes and key replacement
are enforced on refresh, with a maximum 30-second snapshot lease. This is bounded
revocation rather than synchronous revocation of all in-flight work. A same-key
refresh preserves sessions. Local or remote key changes invalidate affected
sessions and pending attempts. Queued packets are tied to their original identity
proof and session ID and cannot move into a replacement session.

Rotation is tested by updating the authoritative device repository and the
agent's corresponding private key, then refreshing and negotiating again. A
separate user-facing key-rotation workflow is not part of this change.

## Wire and transcript

DIRECT uses the logical `OLEP4` envelope, encoded on UDP with the binary `OLP4`
header. RELAY uses the logical `OLER2` carrier, encoded with the binary `OLR2`
header and an embedded `OLP4` message. Logical text is an internal representation;
the UDP listeners do not accept that text or older OLEP/OLER wire versions.
Update participating clients and relay servers together. An older server without
the identity endpoint cannot supply transport credentials.

The logical handshake envelope is:

```text
OLEP4|kind|sourcePeerId|targetPeerId|sessionId|Base64(JSON transcript)
```

The JSON fields are `n` (network), `s` (session ID), `i`/`r` (initiator/responder
peer IDs), `id`/`rd` (their device IDs), `ik`/`rk` (Base64 ephemeral X25519 public
keys) and `sig` (Base64 Ed25519 signature). The session ID is a random 16-byte
nonce encoded as 32 hex characters. Each ephemeral key is freshly generated.

Ed25519 signs the UTF-8 JSON string array produced by Go `json.Marshal`, in this
exact order, without the signature field:

```text
["OLEP4", path, kind, network, sessionId, initiatorPeerId, responderPeerId,
 initiatorDeviceId, responderDeviceId, initiatorEphemeralKey, responderEphemeralKey]
```

`path` is `DIRECT` or `RELAY`. It prevents moving a signed handshake between
transports. Identities must match the current trusted snapshot and outer routing
fields. A WELCOME must also match the initiator's saved peer, nonce and ephemeral
key; an invalid response does not consume the pending attempt.

1. **HELLO:** initiator signs its identity, intended responder and ephemeral key;
   the responder key is empty. No session is installed.
2. **WELCOME:** responder verifies HELLO and signs the complete transcript with
   its fresh ephemeral key. No session is installed.
3. **FINISH:** initiator verifies the expected responder and signs the same complete
   transcript. Only then does the responder install a session and send READY.
4. **READY:** responder signs the complete transcript with the READY message type.
   The initiator verifies it, installs its session and completes the caller's wait.

Repeated HELLO during a pending attempt resends the same challenge instead of
resetting it. A completed HELLO replay can only solicit a new challenge; an old
FINISH cannot answer that challenge. Unknown or consumed WELCOME/FINISH/READY
messages do not install sessions. Simultaneous attempts select the initiator
with the lexicographically smaller peer ID, and completion cancels other pending
attempts for that remote peer before notifying callers.

The shared X25519 result is bound to the full transcript using
`HMAC-SHA256(shared, signedBytes("session", transcript))`. The existing directional
AEAD subkey derivation then uses that result with `OLEP4`, the session ID and the
initiator/responder direction labels. DIRECT and RELAY derive different keys.

There are at most 64 pending authenticated attempts per local transport identity;
pending entries expire after 5 seconds. A lost handshake datagram can still cause
the current attempt to time out; a subsequent negotiation can reconnect.

## UDP budget and fragmentation

Every DIRECT and RELAY UDP payload is limited to **1200 bytes**, including its
carrier and routing metadata. Encoders reject larger datagrams. Listeners use a
1201-byte receive buffer and discard oversized datagrams, including Windows
`WSAEMSGSIZE` errors, while continuing to receive later traffic.

The binary encoding uses byte-sized message types, length-prefixed peer IDs
(at most **64 bytes**), and raw fixed-width session IDs, ephemeral keys and
signatures. Network and device IDs are each limited to **128 bytes**. RELAY
bearer tokens have a two-byte length prefix and a **512-byte** limit. Multi-byte
numbers are big-endian. The relay's embedded-transport mode obtains source and
target IDs from the inner envelope; they cannot disagree with separate outer
routing fields. Opaque relay payloads also count their complete carrier toward
the same 1200-byte limit.

Plaintext `packet` and `data` records are limited to **1500 bytes**. `dataack`
permits **1504 bytes** so the default Exchange response can add `ack:` to a
1500-byte request. Size checks run before allocating a send counter. The whole
record is encrypted once with AES-GCM, including its 16-byte tag. Ciphertexts
over 448 bytes are split into **448-byte slices**, with at most **four fragments**
per record; the final slice may be shorter.

Each fragment carries its original record kind, counter, request reference,
index, count and total ciphertext length, plus a **16-byte HMAC-SHA256 tag**.
Directional fragment keys are derived separately from the record AEAD keys.
The tag binds the record AAD, fragment metadata and slice bytes. Metadata and the
tag are checked before reassembly allocation. A read-only replay check can reject
already consumed counters at that point; fragments never advance the replay
window. After complete reassembly, the whole-record AEAD must authenticate before
the receiver consumes the counter and delivers one record. Reordering and repeated
slices do not deliver partial or duplicate application payloads.

One reassembly pool is shared by every remote peer on a local transport listener.
It permits **32 incomplete records** and **48,640 bytes of reserved ciphertext**,
excluding metadata and allocator overhead. An incomplete record expires **two
seconds after its first accepted fragment**; later slices do not extend that
deadline. Receive-loop timeouts prune idle pools. Disabling or replacing a session
drops its incomplete records. DIRECT and RELAY listeners have separate pools.

With peer IDs of 64 bytes, network/device IDs of 128 bytes and a 512-byte relay
token, the largest full-transcript handshake and full-size fragment occupy:

| Message | DIRECT UDP | RELAY send UDP | RELAY deliver UDP |
| --- | ---: | ---: | ---: |
| WELCOME / FINISH / READY | 666 bytes | 1186 bytes | 672 bytes |
| Fragment with 448-byte slice | 636 bytes | 1156 bytes | 642 bytes |

The adapter MTU defaults to **1280**, with an accepted range of **576–1500**.
Persisted values below 576 reset to 1280; older values above 1500 clamp to 1500
when loaded. The transport fragments these overlay packets within its UDP budget;
this does not provide path-MTU discovery or reliable fragment retransmission.

## File dataplane application blocks

A06 replaces the former 32 KiB application chunks with requests for at most
**768 raw payload bytes** per file block. Request JSON must fit the **1500-byte**
data-record limit. Response JSON, including Base64 payload and escaped metadata,
must fit the **1504-byte** dataack limit. The sender shortens a block further when
needed, recomputing `nextOffsetBytes` and clearing `complete`; oversized metadata
or error text becomes a bounded error response. A short block is partial progress,
not an implicit end of file. The UDP protocol versions and MTU limits are unchanged.

Each block gets at most **three Exchange attempts**, each allocating a fresh
transport counter. Reads at the same file offset are idempotent; replaying the
previous encrypted UDP record is not the retry mechanism. An Exchange timeout is
capped at **one second** and the remaining phase deadline. RELAY accounts for
both bind and ACK waits by splitting that budget between its two stages.
Source-download and
receiver-cache phases each share a **five-second dataplane deadline** across their
candidate connections. One connection read processes at most **2048 blocks** and
returns at most **1 MiB** of aggregate payload. These bounds cover dataplane work,
not subsequent control-plane HTTP bookkeeping.

The receiver requires the requested offset, advertised total, returned byte count
and next offset to agree. `complete` must exactly match `nextOffsetBytes == total`.
Source reads must make progress before EOF; a partial receiver cache may return an
empty incomplete block while awaiting more bytes. Empty completed files remain
complete. SHA-256 metadata must agree with the expected transfer value when known;
content type, upload time and SHA-256 metadata must remain stable across blocks.
An already validated prefix can be returned after retry exhaustion or deadline
expiry, so the next call resumes at its exact next offset.

This validates ranges and metadata rather than computing a runtime whole-file
digest. The sender checks source size, but same-size edits to the source file are
not detected by that check. Whole-file integrity verification remains separate
from the bounded transport work.

## Record AAD and receive window

`internal/transportauth/records.go` implements the shared record cipher. Each
direction has one monotonically increasing counter across **packet, data and
dataack**, starting at 1. The 12-byte GCM nonce is four zero bytes followed by the
counter as an unsigned 64-bit big-endian integer. Counter zero is rejected;
after `MaxUint64`, sending fails with a rekey-required error instead of wrapping.
A new cipher state must come from a new authenticated handshake with fresh keys.

Record AAD is the UTF-8 JSON string array, in this order:

```text
["OLEP4", "record", path, kind, sourcePeerId, targetPeerId, sessionId,
 counterDecimal, requestCounterDecimal]
```

The request reference is `"0"` for packet/data. For dataack it is the original
request counter, so an ACK cannot be moved to another waiting request. The
network/device identities are also bound through the authenticated session key.

After AEAD authentication succeeds, the receiver atomically checks and updates
a **256-counter** bitmap window. A fresh high counter advances it; unseen records
in `[highest - 255, highest]` may arrive out of order and are delivered in arrival
order. Duplicates and older records are rejected. Invalid tags, changed fields or
forged high counters cannot advance the window. One window is shared across all
three message kinds, not a separate window per kind.

A duplicate data request does not execute its handler again or generate a fresh
ACK. There is no cached-response/retransmission protocol: after loss, a caller
can time out and retry with a fresh counter. Application idempotency is separate.

## Queue budget and diagnostics

Each local transport listener has one fixed FIFO shared by its remote peers,
with limits of **256 packets** and **256 KiB of queued payload**. When either
limit would be exceeded, the new packet is dropped; older accepted entries keep
their order. That record is still consumed by the receive window and replaying it
later cannot bypass the overflow policy. Queue slots are zeroed on removal;
expired/revoked/replaced-session packets are pruned. Peer IDs use session-owned
strings rather than retaining an entire received wire message per queued packet.
The payload budget excludes the fixed slot metadata and allocator overhead.

Managers expose `DataPlaneStats(localPeerId)` and the exported diagnostics bundle
includes `transportDataPlane`, grouped by network/local peer, with DIRECT/RELAY:

- `records.accepted`, `duplicates`, `tooOld`, `invalid`, `counterExhaustions`;
- `queue.packets`, `bytes`, `peakPackets`, `peakBytes`, `overflowPackets`,
  `overflowBytes`, `purgedPackets`;
- `wire.oversizedInbound`, `rejectedOutbound`, `malformedInbound`;
- `assembly.pending`, `bytes`, `completed`, `expired`, `overflow`, `duplicates`,
  `conflicts`.

Record counters describe processing after a current session is selected, not all
malformed UDP traffic. They include authenticated records dropped by a full queue.
Counters survive session rekey but reset when the listener is recreated. These
are diagnostic counters; no key material or bearer credentials are included.

## Verification and remaining boundaries

Permanent tests cover real UDP peer-ID impersonation, a forged RELAY delivery,
transcript/target/device/ephemeral-key tampering, wrong signatures, replayed
HELLO/FINISH, missing/expired/rotated grants, bounded pending state, simultaneous
initiation, and the API → agent → DIRECT/RELAY path with rotation and revocation.
The original DIRECT attack established an impostor session, delivered its payload
and broke the legitimate connection; the regression now rejects it while keeping
the legitimate connection usable.

Record tests cover real UDP duplicate delivery for both paths, repeated Exchange
handlers, ACK correlation, cross-kind substitution, in-window reordering, too-old
records, invalid AEAD without window advancement, concurrent duplicate opens,
send-counter exhaustion and fixed FIFO count/byte limits with released references.
Queue-byte boundary tests use synthetic enqueue operations rather than large
application records.

A06 regression tests exercise source and receiver-cache downloads through real
authenticated DIRECT and RELAY UDP managers, including 64 KiB + 137-byte content,
offset resume, escaped metadata, partial-cache growth, empty files and bounded
retry/recovery. The loss wrapper discards selected responses after a real Exchange
has completed; it verifies application retries with new authenticated requests,
rather than simulating a network dropping individual UDP fragments. The source
test writes the assembled receiver artifact and compares its bytes and SHA-256
with the original; the cache test also compares the assembled bytes and digest.

A05 bounds datagrams, reassembly and the adapter MTU; A06 bounds file application
blocks and retry/resume behavior. Fragmentation does not turn the transport into
an arbitrary-size message channel. A12 remains open: packet forwarding still
depends on the agent's HTTP lifecycle.

The outer OLER2 relay carrier still sends its bearer credential in plaintext over
UDP; OLEP4 authenticates the inner peers and does not add confidentiality to that
carrier credential. That channel needs separate hardening before deployment over
an untrusted underlay.

SQL integration was not rerun against PostgreSQL, and no multi-host Windows/NAT
acceptance or external cryptographic protocol review has been performed.
