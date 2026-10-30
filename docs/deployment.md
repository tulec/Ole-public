# Deployment

`Ole` now includes a production-oriented server image pipeline.

## Local Image Build

Build the server image locally:

```powershell
docker build -t ole-server:local .
```

Run it against PostgreSQL from `docker-compose.yml`:

Set a private random `OLE_JWT_SECRET` of at least 32 bytes in `.env` first;
see [env.md](env.md). Empty, short or the former development secret prevents
server startup with exit code 1 before database/listener setup.

```powershell
docker compose up -d postgres
docker run --rm `
  --name ole-server `
  --env-file .env `
  -e OLE_DATABASE_URL=postgres://postgres:postgres@host.docker.internal:5432/ole?sslmode=disable `
  -e OLE_MIGRATIONS_DIR=/app/internal/store/postgres/migrations `
  -p 8080:8080 `
  -p 3478:3478/udp `
  -p 3479:3479/udp `
  ole-server:local
```

The image contains:

- `ole-server`
- PostgreSQL migrations at `/app/internal/store/postgres/migrations`
- OpenAPI description at `/app/docs/openapi.yaml`

The server still honors `OLE_AUTO_MIGRATE=true`, so the image can bootstrap schema migrations on startup without a separate migrator container.

## Runtime Shape

The image is built with a multi-stage Dockerfile and runs on a minimal non-root distroless base.

It exposes:

- `8080/tcp` for the HTTP API
- `3478/udp` for STUN
- `3479/udp` for relay

## CI/CD Pipeline

GitHub Actions workflow: [.github/workflows/server-image.yml](../.github/workflows/server-image.yml)

The workflow now:

- builds the server image on pull requests
- builds and pushes multi-arch `linux/amd64` and `linux/arm64` images on `main`
- publishes versioned tags to GHCR on `v*` tags
- attaches OCI labels for version, revision, build date, and repository source
- signs tagged GHCR images with keyless Cosign using GitHub OIDC

Published image naming convention:

- `ghcr.io/<owner>/<repo>-server`

## Windows Installer

Local build script: [build-installer.ps1](../deploy/windows/build-installer.ps1)

That script now:

- builds `ole-client.exe` and `ole-agent.exe` for `windows/amd64`
- stages them into `dist/windows-installer/stage`
- optionally bundles `wintun.dll` from `OLE_WINTUN_DLL_PATH`, `wintun.dll`, or `third_party/wintun/wintun.dll`
- compiles an Inno Setup installer into `dist/windows-installer/out`

Example local run:

```powershell
.\deploy\windows\build-installer.ps1 -Version 0.1.0
```

If you only want the staged binaries and do not have Inno Setup installed:

```powershell
.\deploy\windows\build-installer.ps1 -Version 0.1.0 -SkipInstaller
```

Installer definition: [ole.iss](../deploy/windows/installer/ole.iss)

The installer now:

- installs `ole-client.exe` and `ole-agent.exe` into `Program Files\Ole`
- installs and starts the Windows `Ole Agent` service after setup
- stops and uninstalls the old service before upgrading
- stops and uninstalls the service during product uninstall
- launches the GUI after install unless setup is silent

GitHub Actions workflow: [windows-installer.yml](../.github/workflows/windows-installer.yml)

That workflow now:

- builds the Windows client and service on `windows-latest`
- installs Inno Setup in CI
- produces staged binaries plus an installer artifact for every PR and `main` push
- writes a `SHA256SUMS.txt` manifest for installer outputs
- writes channel-aware update manifests on tagged releases: `ole-update-beta.json` on every tag and `ole-update-stable.json` on stable tags without prerelease suffixes
- signs tagged installer blobs and the checksum manifest with keyless Cosign using GitHub OIDC
- attaches installer outputs plus signatures and certificates to GitHub releases on `v*` tags

Update-manifest script: [write-windows-update-manifest.ps1](../deploy/release/write-windows-update-manifest.ps1)

That script emits a small JSON feed with:

- `channel`
- `version`
- `publishedAtUnix`
- `installerUrl`
- `sha256`
- `releaseNotesUrl`
- `signatureUrl`
- `certificateUrl`

It can now also emit compatibility and rollback metadata for safer desktop rollouts:

- `compatibility.minimumServerVersion`
- `compatibility.maximumServerVersion`
- `compatibility.minimumRollbackVersion`
- optional `rollback` release metadata with its own `version`, installer URL, SHA-256, signature/certificate URLs, release notes URL, and human-readable `reason`

That lets the local agent decide whether the currently selected update channel is safe for the server it is connected to, and it gives the GUI an explicit rollback target when a newer desktop build should not be installed yet on an older server.

Typical hosted feed shape for desktop clients:

```text
https://updates.example.com/ole/stable/ole-update-stable.json
https://updates.example.com/ole/beta/ole-update-beta.json
```

## Release Signing

Checksum script: [write-checksums.ps1](../deploy/release/write-checksums.ps1)

Current signing shape:

- tagged server images are signed in GHCR with `cosign sign`
- tagged Windows installer artifacts are signed as blobs with `cosign sign-blob`
- Windows release bundles also include `SHA256SUMS.txt`, channel-specific update manifests, and matching `.sig` / `.pem` files for release artifacts

That means `Ole` now has a verifiable release trail even before a later Authenticode-specific step is added.

Typical verification commands:

```powershell
cosign verify ghcr.io/<owner>/<repo>-server:<tag> `
  --certificate-identity-regexp "https://github.com/.+" `
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

```powershell
cosign verify-blob `
  --signature .\Ole-Setup-0.1.0.exe.sig `
  --certificate .\Ole-Setup-0.1.0.exe.pem `
  .\Ole-Setup-0.1.0.exe
```

## Related Files

- Dockerfile: [Dockerfile](../Dockerfile)
- Docker context pruning: [.dockerignore](../.dockerignore)
- Local compose stack: [docker-compose.yml](../docker-compose.yml)
