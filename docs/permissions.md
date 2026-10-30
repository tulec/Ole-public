# Permissions

`Ole` now uses an explicit network-scoped permission model instead of relying only on ad-hoc role checks.

## Current Permissions

| Permission | Meaning |
| --- | --- |
| `VIEW_NETWORK` | Read network, peer, and tunnel state |
| `USE_NETWORK` | Register peers, list or publish signaling candidates, request tunnels, and update peer/tunnel lifecycle |
| `MANAGE_NETWORK_SETTINGS` | Change routing, DNS, and group-traffic policy |
| `MANAGE_INVITES` | Create and manage invite codes |
| `MANAGE_MEMBERS` | Add or remove members and manage device approvals |
| `MANAGE_FILES` | Manage non-participant file-transfer actions across a network |
| `MODERATE` | Review network-scoped audit history and moderation surfaces |
| `DELETE_NETWORK` | Delete the network |

## Role Matrix

| Role | Permissions |
| --- | --- |
| `OWNER` | `VIEW_NETWORK`, `USE_NETWORK`, `MANAGE_NETWORK_SETTINGS`, `MANAGE_INVITES`, `MANAGE_MEMBERS`, `MANAGE_FILES`, `MODERATE`, `DELETE_NETWORK` |
| `ADMIN` | `VIEW_NETWORK`, `USE_NETWORK`, `MANAGE_NETWORK_SETTINGS`, `MANAGE_INVITES`, `MANAGE_MEMBERS`, `MANAGE_FILES` |
| `MODERATOR` | `VIEW_NETWORK`, `USE_NETWORK`, `MODERATE` |
| `FILE_ADMIN` | `VIEW_NETWORK`, `USE_NETWORK`, `MANAGE_FILES` |
| `MEMBER` | `VIEW_NETWORK`, `USE_NETWORK` |
| `READ_ONLY` | `VIEW_NETWORK` |

## Boundary Semantics

- outsiders fail as `401 unauthorized`
- members without the needed capability fail as `403 insufficient role`
- `READ_ONLY` can inspect network state but cannot operate peers, signaling, or tunnels
- `READ_ONLY` can read network messages and file-transfer listings through `VIEW_NETWORK`, but cannot send messages or initiate/manage transfers
- transfer participants can accept, cancel, or update their own transfers through `USE_NETWORK`; `FILE_ADMIN` and higher can manage any transfer in the network through `MANAGE_FILES`
- deleting a network stays owner-only
- changing another member's role stays owner-only even when the caller can otherwise manage members
- creating or updating tunnel state requires ownership of at least one participating peer, in addition to `USE_NETWORK`; both distinct peers must belong to the tunnel's network
- relay checks the network, current `USE_NETWORK`, online peer status, active device ownership and required device approval on every bind/send; a saved tunnel does not bypass those checks

## Audit Visibility

The global `GET /api/v1/audit-events` feed includes only the caller's personal
events without network scope and events from networks for which the caller has
`VIEW_NETWORK_AUDIT` (`OWNER`, `ADMIN`, or `MODERATOR`). Being the actor of an event
does not bypass that network permission. Filters and pagination apply only to
authorized events; invitation codes are removed before search on both audit APIs.

Migration `018` redacts legacy invitation audit details and deletes invitations
whose exact codes appeared in those records. Existing audit events are preserved.
After upgrading, issue new invitations to replace the exposed codes. Newly issued
invitations remain usable and their codes are returned only by the invite workflow.

## GUI Exposure

The Windows desktop client now surfaces this model directly:

- network rows show the current account role on each listed network
- selected-network details show the current role and current permissions
- selected-network details also include a compact role matrix for quick admin/operator reference
