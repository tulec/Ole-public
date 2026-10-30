# Desktop Client

The Windows GUI client lives in `cmd/client` and uses the native Windows `walk` toolkit.
The local background agent lives in `cmd/agent` and is the GUI's IPC target.

## Features

- local GUI-to-agent IPC over localhost HTTP
- configure server base URL through the local agent
- register and sign in through the local agent
- persistent device identity with a long-term keypair stored by the local agent
- persisted session restore in the local agent after service restart
- automatic background session refresh inside the local agent
- managed peer heartbeat and peer discovery loops inside the local agent
- automatic host/UDP signaling candidate publication for managed peers
- optional STUN-based NAT probing and server-reflexive (`SRFLX`) candidate publication for managed peers
- relay candidate publication when a relay server is configured
- lightweight UDP direct probes with bounded retry/backoff before relay fallback
- encrypted UDP handshake and validated payload exchange on successful direct paths
- encrypted relay handshake and packet forwarding after bounded direct-path failure
- bounded binary UDP transport with authenticated fragmentation and listener-wide reassembly limits
- relay pool publication, active-relay selection, and automatic relay failover across multiple configured relay endpoints
- automatic direct failback after relay when direct candidates later become usable again
- packet forwarding between the virtual adapter and encrypted direct transport
- automatic encrypted session rekey after age or packet-count thresholds
- keepalive-driven RTT/loss telemetry and idle-path recovery for direct and relay sessions
- local overlay DNS for peer names, with adapter DNS server/suffix wiring and `peer.ole` resolution to virtual IPs
- per-network routing policy controls with `SPLIT` or `FULL`, surfaced through the agent, adapter diagnostics, and desktop GUI
- per-network group-traffic policy controls with `BLOCKED` or `FLOOD` behavior for IPv4 multicast and broadcast
- runtime group-traffic diagnostics showing blocked packets, flood events, fanout copies, and broadcast-versus-multicast totals per network
- per-network name-resolution policy controls with `DEFAULT`, `NETWORK_ONLY`, or `DISABLED` behavior plus an optional DNS label
- selected-network role and permission summary for the current account, including a compact role matrix for admin/operator reference
- persisted adapter MTU tuning through the local agent with GUI controls and desired-versus-actual MTU diagnostics; default 1280, range 576–1500
- desktop diagnostics panes for NAT, adapter MTU/session state, route visibility, direct-vs-relay state, tunnel mode/state, encrypted session counters, and keepalive RTT/loss telemetry
- peer list hints for online/offline presence, path quality, and latency using live agent connection summaries
- overlay-neighbor diagnostics per network, including neighbor presence/state, overlay CIDR, candidate count, and transport readiness
- exportable diagnostics bundle from the desktop GUI with recent service logs, redacted session metadata, relay-versus-direct usage summaries, adapter rollups, and security alerts for session reuse or revoked devices
- filtered audit-event view and JSON export from the desktop GUI with actor/type/query/time-range controls
- administrative incident-report view and JSON export for auth-abuse, relay-abuse, and readiness incidents
- saved audit-filter presets in the desktop GUI, persisted by the local agent across restarts
- localized and more actionable GUI error dialogs with recovery guidance
- client/server version compatibility diagnostics with explicit minimum-supported-client reporting
- dedicated service-health pane with overall status, uptime, lifecycle freshness, and next-action guidance
- built-in client auto-update flow via the local agent, including `stable` / `beta` channel selection, manifest checks, verified installer downloads, and `Check Updates` / `Download Update` / `Install Update` actions in the GUI
- direct-connect success metrics in diagnostics, including attempts, success rate, relay fallback count, and successful failbacks
- dedicated getting-started onboarding pane with first-run and recovery guidance
- reconnect backoff diagnostics in service health and onboarding, including pending auto-retry timing and manual reconnect guidance
- trusted-devices pane with per-device trust labels, full device fingerprints, and clipboard copy for the selected device
- sensitive-network device approval controls in the GUI for approving or revoking the selected device on the selected network
- selected-network messages and file-transfer panes with local-peer/recipient pickers, live history filters, and friendlier peer labels instead of raw ID-only operator flow
- device-aware join guidance for sensitive networks, including current-device approval hints before peer registration
- suspicious-session recovery guidance with one-click `Revoke All Sessions` through the local agent when token reuse is detected
- service-side connection summaries with direct-vs-relay readiness derived from peer discovery
- control-plane tunnel negotiation records that track whether each managed path is currently aiming for `P2P` or `RELAY`
- Wintun-backed virtual adapter provisioning when `wintun.dll` is packaged with the agent
- automatic virtual IPv4 assignment and route reconciliation for managed peer networks
- list and inspect networks
- create networks
- create sensitive networks that require explicit device approval
- redeem invites
- generate invite codes
- register peers
- reconnect the local agent session from the GUI
- rejoin the selected network from the GUI using the stored or currently entered endpoint
- create tunnels
- reconnect GUI to an existing agent-held session state

## Transport size and compatibility

Clients and relay servers must be upgraded together for logical `OLEP4` / `OLER2`
and binary UDP `OLP4` / `OLR2`; older wire formats have no fallback. Each UDP
payload is limited to 1200 bytes including its metadata. Packet/data plaintext
can contain up to 1500 bytes; dataack allows 1504 bytes for the default `ack:`
reply. Ciphertext is split into at most four authenticated 448-byte slices.
Each local DIRECT or RELAY listener shares a pool of 32 incomplete records and
48,640 ciphertext bytes across its peers, with a two-second expiry. Fragment
authentication happens before allocation and whole-record AEAD authentication
before replay-window advancement and application delivery.

The adapter MTU defaults to 1280 and accepts 576–1500. Loading saved state resets
values below 576 to the default and clamps legacy values above 1500 to 1500.
The desired-versus-observed diagnostics still show whether Windows applied the
configured value.

File-dataplane reads now use application blocks of at most 768 raw bytes, shortened
further when JSON/Base64 and escaped metadata would exceed the 1504-byte response
budget. Requests fit the 1500-byte data-record limit. A short block preserves the
next resume offset rather than implying EOF. Size, offset, exact EOF and stable
checksum/content metadata are checked before appending a block; a partial receiver
cache can remain empty or stop before the complete file is available.

Each block permits at most three fresh-counter Exchange attempts with a one-second
timeout ceiling. Source/cache dataplane phases each have a five-second deadline;
one connection read handles at most 2048 blocks and 1 MiB of aggregate payload.
Already validated progress can be returned after an interruption and resumed by
offset. A06's loopback tests exercise real DIRECT/RELAY source and receiver-cache
downloads, including 64 KiB + 137-byte files, response loss after real Exchange,
resume and empty files, and compare reconstructed bytes/SHA-256.

Runtime whole-file digest validation is not added; same-size source edits are not
detected by the sender's size check. A12's forwarding dependency on the HTTP
lifecycle also remains. The relay's carrier bearer token is still plaintext on
UDP even though peer payloads are encrypted.

## Run

```powershell
go run .\cmd\agent
```

In a second terminal:

```powershell
go run .\cmd\client
```

## Build Windows executable

```powershell
go build -o .\bin\ole-client.exe .\cmd\client
go build -o .\bin\ole-agent.exe .\cmd\agent
```

## Build Windows installer

```powershell
.\deploy\windows\build-installer.ps1 -Version 0.1.0
```

This stages `ole-client.exe` and `ole-agent.exe`, optionally bundles `wintun.dll` when it is available locally, and then compiles an Inno Setup installer. If Inno Setup is not installed yet, use `-SkipInstaller` to produce only the staged binaries.

## Windows service commands

The agent can also run as a real Windows service:

```powershell
go run .\cmd\agent install
go run .\cmd\agent start
go run .\cmd\agent status
go run .\cmd\agent stop
go run .\cmd\agent uninstall
```

Installation configures the service for automatic startup with delayed auto-start and restart-on-failure recovery actions.
The service now also restores its persisted session state on startup and keeps peer presence alive even when the GUI is closed.
The service also publishes signaling candidates for managed peers and tracks per-peer connection summaries that will feed the later NAT traversal and encrypted transport phases.
If `OLE_AGENT_STUN_SERVER_ADDR` points at the built-in server STUN listener, the agent also probes its mapped UDP endpoint and publishes a `SRFLX` candidate when a NAT translation is detected.
When remote peers expose usable candidates, the agent now performs lightweight UDP direct probes with bounded retries, upgrades successful paths into an encrypted UDP session, and marks the path `CONNECTED` only after an encrypted payload round-trip succeeds.
Those connection states also drive idempotent tunnel records in the control plane, so the agent can promote a peer pair from `NEGOTIATING` to `OPEN` and surface tunnel mode/state after restart.
When the adapter exposes packets, the agent now routes outbound IPv4 payloads by overlay virtual IP into the encrypted direct session and writes inbound decrypted packets back to the adapter.
The agent also rolls encrypted sessions automatically when their age or packet count crosses the configured transport rekey threshold, then re-establishes the direct path in the background.
If `OLE_AGENT_RELAY_SERVER_ADDR` points at the built-in relay listener, the same encrypted transport can now fall back onto the relay server after bounded direct-path failure, continue forwarding adapter packets across that relay-backed session, and periodically re-test direct candidates so the tunnel can switch back to `P2P` automatically.
The agent now also sends encrypted keepalives on idle sessions, records RTT and consecutive loss counters in service status, and renegotiates a degraded path automatically when keepalive loss exceeds the configured threshold.
The desktop GUI now auto-refreshes those agent diagnostics so the operator can see NAT type, public endpoint, desired and observed adapter MTU, packet-session state, per-network IP and route visibility, direct-versus-relay state, relay pool and active relay selection, tunnel state, packet counters, and keepalive quality data without opening logs.
The desktop peer list now also folds those live connection summaries back into each peer row, so operators can immediately spot who is online, which peers are pending versus healthy, whether a peer is on direct or relay transport, and what latency the current session is reporting.
The connection diagnostics now also include an explicit overlay-neighbor section per network, which makes it easier to reason about neighbor discovery separately from the lower-level transport session details.
The GUI can now also export a JSON diagnostics bundle through the local agent. That bundle includes the current agent status, recent service-side log lines, sessions with tokens redacted, aggregate relay-versus-direct usage counters, current security diagnostics, device snapshots, and per-network peer/tunnel snapshots with their own usage summaries for support workflows.

The bundle also includes `transportDataPlane` counters per network/local peer for
DIRECT and RELAY: authenticated records, duplicates, too-old/invalid records,
counter exhaustion, current/peak queue packets and bytes, overflow and policy
purges, wire rejections, and pending/completed/expired/overflowed fragment
assemblies. See [transport-auth.md](transport-auth.md) for counter scope and limits.
Those recent service logs are now structured instead of message-only: each bundle entry can carry a `component`, `event`, and structured `fields`, which makes it easier to correlate reconnect, restore, and other lifecycle events without parsing free-form text.
The same local agent now also exposes a Prometheus-text `/metrics` endpoint alongside its GUI IPC routes. That exporter includes agent HTTP request metrics plus gauges and counters for current session state, peer counts, reconnect state, connection-state counts, and accumulated direct-connect outcomes, so local support tooling can scrape the agent directly when needed.
That exporter now also exposes dashboard-oriented NAT and transport gauges such as STUN configuration, last STUN probe time, public-endpoint availability, relay-pool size, active-relay presence, connection reachability mix, and connection transport-mode mix. The local Grafana stack in [observability.md](observability.md) uses those series directly.
The local agent now also exposes explicit `/livez` and `/readyz` probes. `/livez` answers whether the background service process and IPC server are alive at all, while `/readyz` also verifies that the persisted state layer loaded successfully, which makes it easier to separate “the agent is running” from “the agent is actually ready to recover session state.”
Those exported usage summaries now also include a derived transport rollup, so support tooling does not have to reconstruct transport quality from raw connection arrays. Each aggregate or per-network summary now carries a quality label plus healthy/degraded/pending/fallback-ready counts, connected direct-versus-relay totals, transport packet totals, and the most recent transport-packet timestamp.
The same export path now also carries gateway-change diagnostics explicitly instead of only inside the live status snapshot. Bundle consumers get the recent gateway event history both globally and per network, along with a small derived rollup showing how many gateway selections, failovers, losses, path changes, or local-gateway transitions happened and what the most recent event was.
Group-traffic diagnostics are now exported in the same style. Aggregate and per-network usage summaries in the bundle now carry a compact rollup for multicast/broadcast policy behavior, including blocked and flooded packet totals, fanout-copy totals, broadcast-versus-multicast counts, and the most recent action and packet timestamp.
Gateway exports now also include the current state, not just the recent event log. Bundle consumers can see whether `FULL` networks are currently active or still pending gateway, how many are acting as local gateways versus gateway clients, how many are on direct versus relay paths, and, for a specific network snapshot, which gateway peer/path/policy is active right now.
Adapter diagnostics are now exported in the same derived form as well. Aggregate and per-network usage summaries in the bundle carry a compact adapter rollup with binding counts, split-versus-full policy totals, active-versus-pending policy counts, IP/route visibility totals, MTU and DNS summary, and whether the adapter is currently surfacing an error.
Neighbor diagnostics are now exported in that same support-friendly shape too. Each per-network bundle snapshot includes its raw discovered neighbor list, while aggregate and per-network usage summaries now carry a neighbor rollup with presence counts, connected-versus-pending totals, direct-versus-relay reachability and transport counts, maximum candidate fan-in, and most recent seen/signaled timestamps.
Those bundle summaries now also correlate adapter and neighbor state directly. Support tooling can see whether a network is currently aligned, adapter-lagging, transport-lagging, or simply pending convergence, along with which network is affected, whether IP or route visibility is missing, whether a gateway is still pending, and a short hint about the likely next place to investigate.
Connection lifecycle is now exported in that same rollup-oriented form as well. Aggregate and per-network bundle usage summaries now show how many paths are connected, still at direct-candidate or negotiating state, relay-ready, retrying, or erroring, along with tunnel-open versus tunnel-negotiating counts, direct-versus-relay path totals, and a compact hint describing the current connection-state mix.
The aggregate diagnostics export now also includes a cross-network health rollup. That top-level summary classifies each exported network as healthy, degraded, pending, or idle and then tells support whether the snapshot points to one isolated overlay problem or to a broader service-wide degradation pattern.
Recent path errors are now exported in a similarly compact form. Aggregate and per-network usage summaries separate transient retry noise from persistent path failures, expose the most recent failing peer/state/error tuple, and surface the next retry time when a path is still inside a backoff window.
Transport session longevity is now exported in that same support-friendly style. Aggregate and per-network usage summaries now show how many live direct and relay sessions exist, which session is oldest, how old and idle the stalest session is, and whether any rekey deadline is scheduled, due soon, or already overdue.
The session view and agent diagnostics now also surface token-reuse alerts and whether the currently enrolled device is still active, revoked, or missing on the server.
That security path now also includes an explicit recovery workflow: when the current account shows token reuse, `Service Health`, onboarding, and session details all point the operator at `Revoke All Sessions`, and the GUI can trigger that action through the local agent so the service signs out and can be re-authenticated cleanly.
That same token-reuse path is now also reflected in the incident system: the local agent keeps a live incident summary in status, and the GUI can warn about active `TOKEN_REUSE` incidents in `Service Health` and `Agent Diagnostics` even before the operator manually refreshes the full `Incident Reports` panel.
The desktop GUI now also includes an audit-events panel with actor user ID, event type, text query, and unix-time range filters, plus an `Export Audit` action for dumping the currently filtered audit slice to JSON.
That audit panel now also supports saved filter presets. The local agent persists those presets per server and user, and the GUI can save the current filter, apply a selected preset back into the form, or delete it later without losing the rest of the local agent state.
The desktop GUI now also includes an `Incident Reports` pane for admin-style triage. It pulls the server's current derived incidents for auth abuse, relay abuse, and readiness problems through the local agent, and it can export that incident list to JSON for handoff or later review.
Common desktop errors now also render as localized, user-facing dialogs instead of raw backend strings. The GUI recognizes local-agent reachability problems, compatibility blocks, sign-in requirements, field-validation issues, invite failures, authorization problems, and not-yet-ready peer paths, then shows the operator what to do next. The dialog language defaults from the host locale and can be overridden with `OLE_GUI_LOCALE=ru` or `OLE_GUI_LOCALE=en`.
The GUI diagnostics now also show the local client version, the server-reported version, the minimum supported client version, and whether the current pairing is compatible, warning, or upgrade-blocked.
The desktop GUI now also breaks that data out into a dedicated `Service Health` pane, so the operator can immediately see whether the local agent is reachable, whether the current session is active, how old the service uptime and lifecycle timestamps are, and what action to take next when compatibility or lifecycle health is degraded.
The diagnostics views now also include runtime direct-connect metrics from the agent, so an operator can see how many direct attempts were made, how many succeeded or failed, what percentage succeeded, how often the agent fell back to relay, how often relay later failed back to direct, and which candidate most recently produced a successful direct path.
The desktop GUI now also includes a `Getting Started` pane that adapts to the current state of the local agent, session, networks, peers, and tunnels. On a first run it walks the user through starting the agent, choosing the server, registering or logging in, creating or joining the first network, registering the local peer, and then watching connection negotiation. In degraded states it also points the user at the right recovery action such as `Refresh Agent`, `Reconnect`, or `Rejoin Selected`.
The local agent can now also act as a small Windows auto-update controller when update manifests are configured. It tracks a selected `stable` or `beta` channel, periodically checks that channel's manifest, surfaces current-versus-latest version in diagnostics, downloads the installer into the configured update cache with SHA-256 verification, and lets the GUI launch that downloaded installer through `Install Update`.
That updater path is now policy-aware too: a manifest can declare which server versions are compatible with a desktop release and can optionally advertise a rollback build. The GUI surfaces that policy in `Service Health` and `Agent Diagnostics`, blocks an incompatible `Download Update`, and adds `Download Rollback` / `Install Rollback` actions when the release feed recommends reverting to an older installer.
The desktop GUI now also includes a `Trusted Devices` pane backed by the local agent device list. It summarizes how many devices are trusted versus revoked for the current account, labels each device as `current-trusted`, `trusted`, or `revoked`, and shows the full fingerprint for the selected device. The operator can copy that fingerprint directly to the Windows clipboard, which makes it much easier to compare trusted devices before deeper device-management actions are added.
That same pane now also works with the selected network: if a network is marked sensitive, the operator can approve or revoke the selected device for that specific network directly from the GUI, and the details view shows whether the selected device is already approved for the selected network.
Sensitive-network join flows are now more explicit as well: the GUI prefers the current service device in `Trusted Devices`, highlights whether the current device is already approved in the network list and device details, and stops `Register Peer` / `Rejoin Selected` early with actionable guidance when the current device is still pending approval.
The connection pane now also includes explicit `Reconnect` and `Rejoin Selected` recovery actions so an operator can restore the service session or re-register the local peer on a network without re-entering the entire setup.
Those recovery actions now sit on top of an automatic reconnect loop in the agent itself: if the control plane is briefly unavailable during service startup or restore, the agent keeps the persisted session, retries restore with exponential backoff, and clears the wait window as soon as the operator presses `Reconnect`.
That reconnect loop is now also surfaced as a first-class diagnostic: `Service Health`, `Agent Diagnostics`, and the onboarding pane show whether the agent is currently waiting inside a reconnect backoff window, when the next retry is scheduled, and what the last reconnect error was.
That reconnect state is now also crash-safe: the service persists its reconnect journal and lifecycle marker, detects unclean shutdown on the next start, immediately resumes persisted-session recovery instead of waiting on a stale backoff timer, and exposes the recovery event through live agent status.
The agent now also handles endpoint roaming more cleanly: if a managed peer heartbeat comes back with a different local endpoint, the direct listener is rebound automatically, and if a remote peer's endpoint or host candidates change, the existing direct session is dropped and renegotiated against the new address set.
The agent now also exposes a small local overlay DNS resolver and points the managed adapter at it. That means managed peers get stable overlay names such as `peer-remote.ole` and `peer-remote.network-a.ole`, both resolving to the current virtual IP without depending on the host machine's global DNS.
That overlay DNS layer is now policy-aware per network: a network can keep the default global-plus-network aliases, limit itself to network-scoped names such as `peer-remote.friends-lan.ole`, or disable name publication entirely. The desktop GUI can create a network with that policy up front and can later apply a new policy to the selected network.
The GUI now also lets the operator persist a per-network routing policy. `SPLIT` matches the current overlay-only behavior, while `FULL` now has the first real Windows gateway slice behind it: when a client has a live path to an eligible gateway peer, the Ole adapter switches that network onto a default route and forwards non-overlay IPv4 traffic through that encrypted connection. On the gateway host, Ole enables IPv4 forwarding plus `NetNat` for the overlay CIDR so that host can act as the network gateway.
Gateway selection is no longer hard-coded to the network owner. Ole now treats `OWNER` and `ADMIN` peers as gateway-eligible, prefers the owner when available, and automatically fails over to another eligible live peer if the current gateway disappears.
The adapter diagnostics still stay honest about readiness. If no usable gateway peer is ready yet, the network remains on its overlay route and the binding reports `PENDING_GATEWAY` instead of pretending exit-node semantics are already active.
That `FULL` behavior is now much easier to inspect from the desktop GUI itself: network rows include compact gateway state, selected-network details show gateway status and next action, and `Connection Diagnostics` calls out the active gateway peer, path mode, RTT, and pending-gateway recovery hints explicitly.
Gateway switching is now visible too. When a `FULL` network selects a gateway for the first time, fails over from one eligible peer to another, loses its current gateway, or changes the active gateway path, the local agent keeps a short recent history and the desktop GUI shows those events in the selected-network details and `Connection Diagnostics`.
The same live connection telemetry is now also rolled up per network. Instead of forcing the operator to inspect every peer path line by line, the GUI now shows a network-level transport summary with aggregate quality, connected-versus-pending counts, direct-versus-relay path totals, average RTT, worst observed loss count, total encrypted transport packets, and a suggested next action for the selected network.
The same network-policy area now also includes `Group Traffic`. `BLOCKED` keeps IPv4 multicast and broadcast off by default, while `FLOOD` fans those packets out to the currently connected peers on the selected network. That gives Ole an explicit, operator-visible answer for LAN-style discovery traffic instead of silently treating it like normal unicast.
Those group-traffic semantics are now observable as well. `Agent Diagnostics` shows per-network counters for blocked packets, flood events, fanout copies, and broadcast-versus-multicast totals, while `Connection Diagnostics` shows which live peer paths actually received flooded copies and when group traffic last flowed.
The overlay adapter slice now also uses the real per-network `overlayCidr` coming from the control plane instead of inferring every network as `/24`. New Ole networks therefore get unique overlay plans by construction, and the Wintun route prefix/prefix length follows that real CIDR during reconcile.
Neighbor and connection diagnostics now also converge downward when discovery changes: if a remote peer disappears from the network view or transitions to `OFFLINE`, the local agent drops the stale encrypted transport session instead of keeping an old `CONNECTED` path alive in diagnostics.
If two managed overlay networks would otherwise install overlapping Windows routes, the adapter layer now suppresses the conflicting route set and reports that conflict through adapter diagnostics instead of silently applying ambiguous address plans.
If `wintun.dll` is available next to `ole-agent.exe` or in `C:\Windows\System32`, the agent also provisions the `Ole` Wintun adapter and applies the current managed peer IP/route configuration.
