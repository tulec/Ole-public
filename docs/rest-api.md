# REST API

Base URL: `/api/v1`

Protected routes require `Authorization: Bearer <accessToken>`.

## Password behavior

Registration and password changes store salted Argon2id hashes. Successful legacy
SHA256 verification upgrades the stored hash. Passwords are not trimmed or
truncated; empty registration/login passwords and empty new passwords are rejected.
`PUT /users/{userId}/password` requires the correct old password; invalid or stale
password changes return 400 without changing storage. Only the new password
authenticates after a successful change.

Password/hash fields are absent from user and session responses. A migration or
password-write failure returns generic 500 without diagnostics or a new session;
login storage failures do not count as incorrect-password attempts. Retry after
recovery is supported. Simultaneous password changes may require retry after a
compare-and-swap conflict. Existing access/refresh tokens keep their established
revocation contract; password change does not implicitly log out all devices.

## Client IP and authentication limits

Login and refresh have separate rate-limit buckets per canonical IP, without the
TCP source port. IPv6 spellings are normalized and IPv4-mapped IPv6 addresses use
the IPv4 key. Different ports or a forged X-Forwarded-For do not reset the limit.
With the existing policy, three failures block the next immediate attempt (429).

By default, the server uses the socket peer IP and ignores forwarded headers.
For a reverse proxy, set `OLE_HTTP_TRUSTED_PROXIES` to its literal IPs or CIDRs,
separated by commas; for example `127.0.0.1/32,::1/128` for a local proxy. Empty
configuration trusts none; invalid entries stop startup. Hostnames and ports are
not accepted in this list. Docker Compose passes the setting through its existing
`.env` file; use the actual proxy addresses seen by the server.

X-Forwarded-For is used only when the socket peer is trusted. Repeated fields form
one ordered chain, read from right to left up to the nearest untrusted hop. Each
trusted proxy must set or append the IP of its actual TCP peer. The server ignores
Forwarded and X-Real-IP. A malformed trusted chain uses the socket peer IP; an
invalid socket address uses one shared `unknown` key. Login/refresh session metadata
uses this same IP resolver.

Deploy this change on all API instances. Old port-based keys are not merged into
new keys and expire through normal cleanup. The limiter remains per IP; clients
behind the same NAT share it, while different real IPs have separate limits.

## Core resources

- `POST /users` - register a user
- `GET /users/{userId}` - fetch user profile
- `PUT /users/{userId}/password` - change password
- `POST /sessions` - login
- `POST /sessions/refresh` - refresh session tokens
- `DELETE /sessions?accessToken=...` - logout the token's entire session family, including a concurrently refreshed successor; independent login families stay active. Returns 204 after revocation, 401 for missing/unknown session and 500 for lookup/revoke storage failure.
- `DELETE /sessions/all` - revoke all active sessions for current user
- `DELETE /sessions/{sessionId}` - revoke the current user's session family by a current or retained historical ID, including after refresh and beyond the first 1,000 families. Returns 204 after revocation, 404 for missing/foreign/ambiguous IDs or invalid family, 500 for storage failure. Independent families remain active.
- `GET /networks` - list networks
- `POST /networks` - create a network
- `GET /networks/{networkId}` - fetch a network
- `DELETE /networks/{networkId}?requestorId=...` - delete a network
- `POST /networks/{networkId}/members` - add member
- `PATCH /networks/{networkId}/members/{userId}` - change member role (`OWNER`, `ADMIN`, `MEMBER`)
- `DELETE /networks/{networkId}/members/{userId}?ownerId=...` - remove member
- `POST /networks/{networkId}/invites` - generate invite
- `POST /invites/{code}/redemptions` - join network by invite
- `GET /networks/{networkId}/peers` - list peers
- `POST /networks/{networkId}/peers` - register peer
- `GET /peers/{peerId}` - fetch peer
- `PATCH /peers/{peerId}` - update peer endpoint or mark offline
- `GET /networks/{networkId}/tunnels` - list tunnels
- `POST /networks/{networkId}/tunnels` - create tunnel
- `GET /tunnels/{tunnelId}` - fetch tunnel
- `PATCH /tunnels/{tunnelId}` - mark tunnel `CLOSED` or `FAILED`
- `GET /audit-events?limit=50` - the caller's personal audit plus network audit allowed by `VIEW_NETWORK_AUDIT`; filters never expand access, and invitation codes are redacted before search

## Response shape

Successful responses return JSON with `data`, and collection endpoints also include `meta.count`.

Example:

```json
{
  "data": {
    "id": "net-1",
    "name": "friends",
    "ownerId": "usr-1",
    "access": "INVITE_ONLY",
    "members": ["usr-1"]
  }
}
```

Errors use:

```json
{
  "error": "entity not found"
}
```

OpenAPI spec is available at [docs/openapi.yaml](openapi.yaml) and served by the app at `/openapi.yaml`.

Swagger UI is served directly by the server at `/swagger` and now works fully locally without CDN.
