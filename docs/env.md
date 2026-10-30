# Environment

`Ole` loads variables from `.env` and `.env.local` automatically at startup.
Priority is **process environment > `.env.local` > `.env` > defaults**.
A defined empty process variable also blocks dotenv values. An empty JWT secret
is rejected rather than replaced with a development value.

## Bootstrap

```powershell
Copy-Item .env.example .env
```

Generate a private signing secret once, including for local development:

```powershell
$jwtBytes = New-Object byte[] 32
$jwtRng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$jwtRng.GetBytes($jwtBytes)
$jwtRng.Dispose()
$env:OLE_JWT_SECRET = [Convert]::ToBase64String($jwtBytes)
```

Keep that value in your private environment configuration across restarts and
use the same value on API instances sharing sessions. Changing the signing key
invalidates existing access tokens. For Docker, set `OLE_JWT_SECRET` in the private
`.env` consumed by `--env-file` / Compose; the host shell variable alone is not
forwarded by the current Compose service definition. Do not commit the value.

Then edit the other values if needed and start the database and server:

```powershell
docker compose up -d postgres
go run .\cmd\server
```

To bring up the optional local monitoring stack too:

```powershell
docker compose up -d postgres ole-server prometheus grafana
```

For a production-oriented local server image build and the GHCR publishing workflow, see [deployment.md](deployment.md).

For OLEP4 transport identity, a non-loopback server URL must use HTTPS. Localhost
and loopback HTTP remain available for local development. All participating clients
and relay servers need the current protocol: logical `OLEP4` / `OLER2`, binary
UDP `OLP4` / `OLR2`. Older wire versions cannot connect. Each UDP payload is capped
at 1200 bytes, including routing and carrier metadata; peer IDs are limited to
64 bytes, network/device IDs to 128 bytes, and relay bearer tokens to 512 bytes.
The relay carrier still sends its bearer token in plaintext over UDP.
See [transport-auth.md](transport-auth.md).

Adapter MTU is persisted through the agent/GUI rather than an environment
variable. The default is 1280 and the accepted range is 576–1500. On state load,
values below 576 reset to 1280 and legacy values above 1500 clamp to 1500.
Bounded transport fragmentation accommodates these overlay packets within the
UDP budget. File-dataplane reads use at most 768 raw bytes per application block,
with adaptive JSON responses capped at 1504 bytes and requests at 1500 bytes.
These limits are runtime constants rather than environment settings. Each block
has at most three fresh-counter Exchange attempts, with a one-second timeout
ceiling and a five-second deadline per source/cache dataplane phase. A connection
read is also bounded by 2048 blocks and 1 MiB of aggregate payload; validated
partial progress can resume by offset. Runtime whole-file digest validation is
not added. A12's lifecycle-dependent packet forwarding remains separate work.

Important variables:

- `OLE_JWT_SECRET` - required random HMAC secret for Bearer access tokens, at least 32 bytes after trimming. Missing, blank, short and the former built-in development value are rejected with exit code 1 before database/listener setup. There is no implicit development mode. Length validation cannot measure randomness. `cmd/migrate` does not require this setting.
- `OLE_JWT_ISSUER` - issuer embedded into JWT access tokens
- `OLE_STUN_LISTEN_ADDR` - UDP bind address for the built-in STUN listener in `cmd/server`, default `:3478`
- `OLE_RELAY_LISTEN_ADDR` - UDP bind address for the built-in relay listener carrying encrypted peer payloads in `cmd/server`, default `:3479`; the carrier bearer token remains plaintext
- `OLE_RELAY_QUOTA_WINDOW` - optional relay accounting window such as `1m`; when empty or `0`, per-peer relay quotas are disabled
- `OLE_RELAY_QUOTA_PACKETS` - optional per-peer forwarded-packet quota inside `OLE_RELAY_QUOTA_WINDOW`, default `0` meaning unlimited
- `OLE_RELAY_QUOTA_BYTES` - optional per-peer forwarded-payload-byte quota inside `OLE_RELAY_QUOTA_WINDOW`, default `0` meaning unlimited; embedded transport uses its binary message size, excluding the relay carrier
- `OLE_RELAY_ABUSE_WINDOW` - rolling window used for relay abuse tracking by source IP, default `1m`
- `OLE_RELAY_ABUSE_THRESHOLD` - number of malformed, unauthorized, or quota-denied relay requests from one source IP before the relay blocks that source temporarily, default `3`
- `OLE_RELAY_ABUSE_BLOCK_DURATION` - temporary block duration applied after a source crosses `OLE_RELAY_ABUSE_THRESHOLD`, default `5m`
- `OLE_AGENT_ADDR` - local listen address for the Windows Ole Agent IPC server, default `127.0.0.1:5858`
- `OLE_AGENT_STUN_SERVER_ADDR` - optional `host:port` for NAT discovery from the Windows agent; when empty, STUN probing is disabled on the client side
- `OLE_AGENT_RELAY_SERVER_ADDR` - optional relay dataplane address or comma-separated relay pool such as `relay-a.example.com:3479,relay-b.example.com:3479`; when set, the agent publishes `RELAY` candidates and can switch encrypted sessions from failed direct paths onto the active relay
- `OLE_AGENT_RELAY_FAILBACK_PERIOD` - how often a relay-backed connection re-tests direct encrypted transport so it can switch back to `P2P` when a direct path later becomes available, default `30s`
- `OLE_AGENT_TRANSPORT_KEEPALIVE` - idle interval before the agent sends an encrypted keepalive over the current direct or relay session, default `20s`
- `OLE_AGENT_TRANSPORT_LOSS_LIMIT` - consecutive keepalive losses tolerated before the agent drops the current transport session and renegotiates it, default `3`
- `OLE_AGENT_RECONNECT_RETRY_BASE` - initial exponential backoff delay before the agent retries restoring a persisted session after a temporary reconnect failure, default `1s`
- `OLE_AGENT_RECONNECT_RETRY_MAX` - upper bound for persisted-session reconnect backoff, default `1m`
- `OLE_UPDATE_CHANNEL` - selected desktop update channel for the local agent, `stable` or `beta`, default `stable`
- `OLE_UPDATE_MANIFEST_URL` - legacy single-channel manifest URL; still treated as the `stable` feed when the newer channel-specific variables are not set
- `OLE_UPDATE_STABLE_MANIFEST_URL` - optional HTTP(S) manifest URL for the `stable` desktop update channel
- `OLE_UPDATE_BETA_MANIFEST_URL` - optional HTTP(S) manifest URL for the `beta` desktop update channel
- `OLE_UPDATE_CHECK_PERIOD` - how often the local agent re-checks `OLE_UPDATE_MANIFEST_URL` automatically, default `6h`
- `OLE_UPDATE_DOWNLOAD_DIR` - optional directory where the local agent stores verified downloaded installers before the GUI launches them; defaults to the user's cache directory under `Ole\updates`
- `OLE_AGENT_DNS_LISTEN_ADDR` - optional `host:port` for the local overlay DNS listener that the Windows agent exposes to the virtual adapter, default `127.0.0.1:53`
- `OLE_AGENT_DNS_DOMAIN` - overlay DNS suffix published by the agent for managed peers, default `ole`
- `OLE_PEER_HEARTBEAT_TTL` - server-side peer heartbeat expiry window; managed peers that stop heartbeating for longer than this are marked `OFFLINE` and have their signaling state reset during the periodic cleanup cycle, default `2m`
- `OLE_AGENT_STUN_PROBE_PERIOD` - how often the agent re-runs NAT discovery for managed peers, default `60s`
- `OLE_AGENT_DIRECT_PROBE_TIMEOUT` - per-candidate timeout for the lightweight UDP direct-connect probe, default `300ms`; file-block Exchange also uses this value, capped at `1s` and the remaining dataplane phase deadline
- `OLE_AGENT_DIRECT_RETRY_BASE` - initial backoff between failed direct-connect attempts, default `1s`
- `OLE_AGENT_DIRECT_RETRY_MAX` - upper bound for direct-connect retry backoff, default `30s`
- `OLE_AGENT_DIRECT_MAX_ATTEMPTS` - bounded retry count before the agent marks a peer as relay-ready, default `5`
- `OLE_AGENT_STATE_PATH` - override path for persisted agent state (device keypair and enrollments); defaults to the user's config directory
- `OLE_GUI_LOCALE` - optional desktop GUI locale override for user-facing error dialogs; use `ru` for Russian or `en` for English, defaulting to host locale detection
- `OLE_WINTUN_ENABLED` - `auto`, `true`, or `false`; in `auto` mode the Windows agent enables Wintun provisioning only when `wintun.dll` is available next to the agent executable or in `System32`
- `OLE_WINTUN_DLL_PATH` - optional explicit path used only for availability checks and packaging diagnostics; the Wintun DLL itself still needs to be side-by-side with `ole-agent.exe` or installed in `System32`
- `OLE_ADAPTER_NAME` - cosmetic Windows adapter name for the Ole Wintun interface, default `Ole`
- `OLE_CLEANUP_INTERVAL` - how often the server runs cleanup jobs for expired sessions and stale invites, default `5m`
- `OLE_SERVER_VERSION` - version string reported by `/health` and server compatibility metadata, default `0.1.0`
- `OLE_MIN_CLIENT_VERSION` - minimum supported Ole client version; requests from older clients receive `426 Upgrade Required`, default `0.1.0`
- `GRAFANA_ADMIN_USER` - admin username for the local Grafana container in `docker-compose.yml`, default `admin`
- `GRAFANA_ADMIN_PASSWORD` - admin password for the local Grafana container in `docker-compose.yml`, default `admin`

Refresh tokens are persisted in PostgreSQL, so session refresh survives server restarts.

Refresh token rotation is one-time: once a refresh succeeds, the previous refresh token is invalidated.

When Wintun provisioning is active, the agent creates or opens a single `Ole` adapter, applies the managed peer's virtual IPv4 address, and installs an on-link route for that peer network's current `/24` overlay prefix.

When `OLE_AGENT_STUN_SERVER_ADDR` is configured, the agent performs UDP STUN probing before its direct-probe listener claims the managed peer port, records a coarse NAT type (`OPEN_INTERNET`, `NAT`, or `UDP_BLOCKED`), and publishes a `SRFLX` signaling candidate when the mapped public endpoint differs from the local host candidate.

The lightweight direct-connect phase now uses bounded UDP probe retries with exponential backoff. A successful direct probe moves the peer pair into the service-side `NEGOTIATING` state so the later encrypted transport phase has a real directly reachable endpoint to attach to.

When `OLE_AGENT_RELAY_SERVER_ADDR` is configured and direct probes exhaust their bounded retry budget, the agent now establishes the same encrypted session shape over the built-in UDP relay listener and promotes the tunnel to `OPEN` in `RELAY` mode once the encrypted handshake succeeds. When multiple relay addresses are configured, the agent publishes the full relay pool as signaling candidates, prefers the first relay by default, and fails over to the next relay when relay establishment or live relay transport starts failing. If direct candidates later become usable again, the agent re-tests them on the `OLE_AGENT_RELAY_FAILBACK_PERIOD` cadence and switches the live session back to `P2P`.

Long-lived transport quality is now tracked in the agent as well: idle sessions send encrypted keepalives on the `OLE_AGENT_TRANSPORT_KEEPALIVE` cadence, surface RTT/loss telemetry in agent status, and renegotiate the current path when keepalive loss crosses `OLE_AGENT_TRANSPORT_LOSS_LIMIT`.

Persisted service sessions now also reconnect automatically after temporary failures. When restore or compatibility discovery fails because the server is briefly unavailable, the agent keeps the stored session and retries restore on an exponential backoff controlled by `OLE_AGENT_RECONNECT_RETRY_BASE` and `OLE_AGENT_RECONNECT_RETRY_MAX`. Manual `Reconnect` from the GUI still bypasses the waiting window and retries immediately.

When one or more update-manifest URLs are configured, the local agent now tracks a selected update channel as well. `stable` and `beta` can point at different hosted manifests, the GUI can switch between those channels, and the selection is persisted in the local agent state so the same channel survives service restarts.
Those hosted manifests can also advertise compatibility policy and rollback metadata. When they do, the local agent surfaces whether the selected channel is compatible with the connected server version, blocks incompatible update downloads, and exposes a recommended rollback installer to the GUI when the release feed provides one.

When `OLE_AGENT_DNS_LISTEN_ADDR` and `OLE_AGENT_DNS_DOMAIN` are configured, the agent runs a small local UDP DNS server, points the Wintun adapter at that resolver, and publishes overlay names such as `peer-remote.ole` or `peer-remote.network-a.ole` to the peer's current virtual IP.

The relay server now also maintains per-peer usage accounting in memory. When `OLE_RELAY_QUOTA_WINDOW` is set together with packet and/or byte limits, the relay rejects sends that exceed the configured per-peer budget and reports aggregate relay accounting in `/health`.

The relay server now also applies basic abuse controls by source IP. Repeated malformed packets, authorization denials, or quota denials inside `OLE_RELAY_ABUSE_WINDOW` trigger a temporary block for that source and surface abuse counters in `/health`.

The HTTP API now also reports server compatibility metadata in `/health` and `/api/v1`. Ole clients send their own version in `X-Ole-Client-Version`, and the server rejects requests from clients older than `OLE_MIN_CLIENT_VERSION` while still allowing version discovery through the unauthenticated metadata endpoints.

Login and refresh throttling now use a shared PostgreSQL-backed store instead of per-process memory, so rate-limit state survives server restarts and is shared across multiple Ole API instances pointed at the same database.

The server now also derives shared auth-abuse alerts from that throttle state. Repeated failed login or refresh attempts emit server-side alert logs and show aggregate auth-abuse counts and severity in `/health`.

The cleanup loop now also expires stale managed peers. When a peer misses heartbeats for longer than `OLE_PEER_HEARTBEAT_TTL`, the server keeps the peer identity and overlay lease but marks that peer `OFFLINE` and resets its signaling state to `UNKNOWN` / `IDLE`.

The repository now also includes a local Prometheus + Grafana stack with provisioned dashboards for auth, signaling, NAT traversal, relay, and DB health. Prometheus scrapes `ole-server:8080/metrics` from Docker and, when the Windows agent is running locally, also scrapes `host.docker.internal:5858/metrics`. See [observability.md](observability.md).
