# Architecture

This document captures the `Ole` architecture, including A05's bounded UDP transport.
It is meant to be a quick orientation map for future feature work, not a speculative target design.

Primary package anchors:

- server entry point: `cmd/server`
- application wiring: `internal/app`
- HTTP control plane: `internal/httpapi`
- Windows agent/service: `internal/clientagent`, `internal/agentservice`
- direct transport: `internal/directprobe`
- relay dataplane: `internal/relay`, `internal/relaytransport`
- adapter and local DNS: `internal/virtualadapter`, `internal/overlaydns`
- persistence: `internal/store/postgres`

## Control Plane

```mermaid
flowchart LR
    GUI["Windows GUI\ncmd/client\ninternal/clientgui"] -->|localhost HTTP IPC| AGENT["Ole Agent\ncmd/agent\ninternal/clientagent"]
    AGENT -->|REST API| API["HTTP Router\ninternal/httpapi"]
    API --> APP["App Wiring\ninternal/app"]
    APP --> AUTH["AuthService"]
    APP --> DEV["DeviceService"]
    APP --> NET["NetworkService"]
    APP --> PEER["PeerDirectory"]
    APP --> SIG["SignalingService"]
    APP --> TUN["TunnelCoordinator"]
    AUTH --> DB[(PostgreSQL)]
    DEV --> DB
    NET --> DB
    PEER --> DB
    SIG --> DB
    TUN --> DB
    APP --> CLEAN["Cleanup Loop\nexpired sessions\nstale invites\nexpired candidates"]
    CLEAN --> DB
    SERVER["cmd/server"] --> API
    SERVER --> STUN["Built-in STUN listener\ninternal/stun"]
    SERVER --> RELAY["Built-in UDP relay\ninternal/relay"]
```

Notes:

- The control plane is still the system of record for users, devices, sessions, networks, peers, signaling candidates, tunnels, and audit events.
- The Windows GUI does not talk to the server directly anymore; it goes through the local agent over localhost IPC.
- `cmd/server` exposes three server-side surfaces today: HTTP API, STUN, and relay.
- OLEP4 transport handshakes authenticate Ed25519 device identities from short-lived
  control-plane snapshots. DIRECT/RELAY share `internal/transportauth`; see
  [transport-auth.md](transport-auth.md) for trust, wire format, typed record AAD,
  the shared replay window, bounded inbound queues and reassembly limits.
- UDP uses binary `OLP4` messages and the binary `OLR2` relay carrier, with a
  1200-byte payload budget including metadata. The logical internal envelopes are
  `OLEP4` and `OLER2`; older wire formats have no fallback.
- Packet/data plaintext is limited to 1500 bytes; dataack permits 1504 bytes for
  the default `ack:` response. Larger ciphertext is sent in at most four
  authenticated 448-byte slices. Each local listener shares a reassembly pool
  across its peers: 32 records, 48,640 ciphertext bytes, a two-second lifetime.
  Fragment HMAC verification precedes allocation; whole-record AEAD verification
  precedes replay-window advancement and delivery.
- File-dataplane application blocks contain at most 768 raw bytes and shrink
  further to keep JSON/Base64 responses within 1504 bytes. Requests fit 1500
  bytes. At most three fresh-counter Exchange attempts are made per block;
  source/cache phases each share a five-second dataplane deadline, with a
  one-second Exchange timeout ceiling. One connection read is bounded by 2048
  blocks and 1 MiB of aggregate payload. Validated partial progress can resume
  by offset. See [transport-auth.md](transport-auth.md) for EOF/metadata checks
  and the separate runtime whole-file digest limitation.

## Signaling And Negotiation

```mermaid
sequenceDiagram
    participant GUI as Windows GUI
    participant Agent as Ole Agent
    participant API as HTTP API
    participant DB as PostgreSQL
    participant Direct as directprobe
    participant Relay as relaytransport

    GUI->>Agent: Login / Restore / Reconnect
    Agent->>API: refresh compatibility + restore session
    API->>DB: sessions, devices, users
    GUI->>Agent: Register Peer / Rejoin Selected
    Agent->>API: register peer(endpoint, deviceId)
    API->>DB: peers + virtual IP pool
    Agent->>API: publish signaling candidates\nHOST / SRFLX / RELAY
    API->>DB: signal_candidates
    Agent->>API: heartbeat + peer discovery loop
    API->>DB: peers + candidates + tunnels
    GUI->>Agent: Create Tunnel
    Agent->>API: create or reconcile tunnel record
    API->>DB: tunnel NEGOTIATING or RELAY_READY

    alt direct candidates available
        Agent->>Direct: bounded UDP probes + encrypted handshake
        Direct-->>Agent: direct session established
        Agent->>API: promote tunnel to P2P / OPEN
    else direct path fails
        Agent->>Relay: encrypted relay session
        Relay-->>Agent: relay session established
        Agent->>API: promote tunnel to RELAY / OPEN
    end
```

Notes:

- Signaling is server-mediated and persistence-backed.
- The direct path is attempted first, with bounded retry/backoff and later failback from relay.
- The tunnel record in PostgreSQL is a coordination artifact; the path is only considered truly connected after encrypted transport is live.

## Relay Dataplane

```mermaid
flowchart LR
    A["Agent A"] -->|bind + send\naccess token + source peer + target peer| RS["Relay Server\ninternal/relay"]
    RS -->|AuthorizeBind / AuthorizeSend| CP["Control Plane\nAuthService + PeerRepo + TunnelRepo"]
    CP --> DB[(PostgreSQL)]
    RS --> QA["Quota / accounting\nper-peer packets + bytes"]
    RS -->|forward encrypted payload| B["Agent B"]
    B -->|encrypted replies| RS
```

Notes:

- Relay traffic is not open forwarding; every bind/send is authorized against access token, peer ownership, and tunnel mode/state.
- The OLR2 carrier still sends its bearer token in plaintext over UDP. Inner peer
  encryption does not protect that credential from the underlay.
- Relay accounting is in-memory today, but it already exposes health snapshots and configurable quotas.
- Relay is a fallback path, not the primary design target.

## Client Service

```mermaid
flowchart TB
    GUI["Windows GUI\ninternal/clientgui"] -->|IPC| IPC["Agent HTTP Handler\ninternal/clientagent/http.go"]
    IPC --> AGENT["Agent Core\ninternal/clientagent/agent.go"]

    AGENT --> STATE["Persistent State Store\nlong-term device keypair\nsession + enrollment cache"]
    AGENT --> CONTROL["controlclient\nREST control plane client"]
    AGENT --> ADAPTER["virtualadapter\nWintun + IP/route/MTU reconcile"]
    AGENT --> DNS["overlaydns\nlocal peer-name resolver"]
    AGENT --> DIRECT["directprobe\nUDP direct path + encrypted transport"]
    AGENT --> RELAYT["relaytransport\nencrypted relay path"]
    AGENT --> LIFECYCLE["Lifecycle loops\nrefresh\nheartbeat\ndiscovery\nSTUN\nreconnect\nfailback"]
    AGENT --> DIAG["Diagnostics bundle\nservice health\nsecurity + usage summaries"]

    ADAPTER --> OS["Windows network stack"]
    DNS --> OS
    DIRECT --> PEER["Remote peer agent"]
    RELAYT --> RELAY["Server relay listener"]
```

Notes:

- The agent is the long-running owner of networking responsibilities; the GUI is now an operator shell on top of it.
- The local agent is also where reconnect, roaming, signaling publication, relay failover, transport quality tracking, and diagnostics collection live.
- The local overlay DNS and virtual adapter are both driven from discovered peer state, so the Windows machine sees stable overlay names and routes without the GUI staying open.
- Adapter MTU defaults to 1280 and accepts 576–1500. Persisted values below the
  range reset to 1280; legacy values above it clamp to 1500 when loaded.

## Current Boundaries

- The control plane remains authoritative for membership, sessions, devices, candidates, and tunnels.
- The agent owns runtime orchestration, local persistence, adapter state, and transport decisions.
- The relay server stays deliberately thin: authorize, account, forward.
- A06's file-dataplane blocks now fit the bounded transport. Runtime whole-file
  digest validation is not added; same-size source edits are not detected by the
  size check. A12 remains open: packet forwarding still depends on the HTTP lifecycle.
- The remaining large gap to a "real Hamachi analog" is not CRUD; it is more overlay semantics hardening, NAT hardening, packaging, and operational maturity.
