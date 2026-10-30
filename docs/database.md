# Database

`Ole` now uses PostgreSQL as the primary storage.

It also stores refresh sessions and network member roles in PostgreSQL.

## Quick start with Docker Compose

```powershell
Copy-Item .env.example .env
docker compose up -d postgres
```

To start both PostgreSQL and the server in containers:

First set a private `OLE_JWT_SECRET` in `.env`; see [env.md](env.md) for
generation and startup requirements. The example intentionally leaves it empty.

```powershell
docker compose up -d
```

## Environment variables

- `OLE_DATABASE_URL` - PostgreSQL DSN, default: `postgres://postgres:postgres@localhost:5432/ole?sslmode=disable`
- `OLE_AUTO_MIGRATE` - `true` or `false`, default: `true`
- `OLE_MIGRATIONS_DIR` - path to SQL migrations, default: `internal/store/postgres/migrations`
- `OLE_HTTP_PORT` - HTTP bind address, default: `:8080`
- `OLE_HTTP_TRUSTED_PROXIES` - comma-separated literal proxy IPs/CIDRs; empty by default, so X-Forwarded-For is ignored. Invalid entries prevent server startup before database/listener setup. Example for a local proxy: `127.0.0.1/32,::1/128`.
- `OLE_CLEANUP_INTERVAL` - cleanup loop interval for expired sessions and stale invites, default: `5m`
- `OLE_JWT_SECRET` - required private JWT signing secret, at least 32 bytes; no development fallback. Only the server requires it, not `cmd/migrate`.
- `OLE_JWT_ISSUER` - JWT issuer

Login/refresh rate limits and session metadata use canonical IPs without TCP ports.
With trusted proxies configured, X-Forwarded-For is read right to left, including
repeated header fields, until the nearest untrusted hop. Configure only actual
proxy addresses; each trusted proxy must set or append the address of its TCP
peer. `Forwarded` and `X-Real-IP` are ignored. See [REST API](rest-api.md#client-ip-and-authentication-limits)
for deployment behavior and fallback rules.

## Run migrations

```powershell
go run .\cmd\migrate
```

## Run PostgreSQL integration tests

Start PostgreSQL first:

```powershell
docker compose up -d postgres
```

Then run:

```powershell
go test ./...
```

By default the integration tests use `OLE_TEST_DATABASE_URL`, then `OLE_DATABASE_URL`, then `postgres://postgres:postgres@localhost:5432/ole?sslmode=disable`.

Each test run creates its own temporary schema, applies all migrations there, and drops that schema during cleanup.

## Password storage

New registrations and password changes use Argon2id PHC strings in the existing
TEXT `users.password_hash` column, with 19 MiB memory, two passes, one lane, a
random 16-byte salt and a 32-byte key. The policy follows the
[OWASP baseline](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
using [x/crypto/argon2.IDKey](https://pkg.go.dev/golang.org/x/crypto/argon2#IDKey).
Encoded version/parameters are checked and bounded before KDF allocation.

Existing 64-hex SHA256 hashes are verified and upgraded after correct password
verification. The update compares the verified hash and changes only
`password_hash`, so stale migration cannot restore a concurrently changed password
or overwrite user metadata. A concurrent password-change conflict may require
retry. Failed writes do not issue a new session and surface as generic HTTP 500;
password/hash values are excluded from API responses and User JSON.

No schema migration is needed. Inactive legacy accounts retain SHA256 until they
authenticate; existing hashes cannot be converted without the password. Empty
passwords are rejected. Previously issued sessions retain their existing explicit
revocation semantics. Local Hash/Verify cost was about 57 ms on Windows/386;
production concurrency/load acceptance remains separate.

## Session consistency

With a session repository configured, access validation and refresh always read
storage; local maps do not override database revocation. Last-use updates are
conditional and never overwrite revocation, reuse or rotation fields.

Refresh revokes the old row and inserts its successor in one transaction.
Rotation and all revocation methods lock the same user row using `READ COMMITTED`,
so revoke-all/family also covers a concurrently inserted successor. A failed
successor insert rolls back the old-row change. JWT `jti` identifies each newly
issued session; existing JWTs without `jti` remain readable until expiry/revocation.

Logout identifies the family through the supplied access token's stored history
and uses the same serialized family revocation. It propagates storage errors;
HTTP 204 means revocation completed, rather than just local state being cleared.

Revoke-by-ID resolves retained session history and revokes its family in one
transaction under the same user lock, without list pagination. Both lookup and
update include `user_id`; family revocation also requires a user for logout/reuse,
so legacy family-ID collisions cannot revoke another user's sessions. A session
ID matching different families of one user, or an empty family, is rejected
without updates. Cleanup still removes expired history; a deleted historical
ID is no longer resolvable. No schema migration is required for this change.

## Run server

```powershell
go run .\cmd\server
```

If `OLE_AUTO_MIGRATE=true`, the server applies pending migrations on startup.

The server also runs periodic cleanup jobs for expired `session_tokens` and stale invites (expired or exhausted invites).

`.env` and `.env.local` are loaded automatically if present. Priority is process
environment > `.env.local` > `.env`; a defined empty value is not replaced by a
lower-priority file.
