# Install Enkstein

## Native installers

For the simplest desktop experience, download the installer for your operating
system from GitHub Releases:

- macOS: `Enkstein-VERSION-macos.pkg`
- Windows x64: `Enkstein-VERSION-windows-x64-setup.exe`

Both installers create a clickable Enkstein launcher. The launcher starts
Docker Desktop when needed, initializes unique secrets, and starts the
platform. On macOS, a universal native application displays startup progress,
waits for backend/frontend health, and embeds Enkstein in its own desktop
window. Docker Desktop remains required because Enkstein includes multiple
services and persistent PostgreSQL/Redis data.

The macOS package is signed and notarized by Apple. Tagged public Windows
installers require Authenticode signing.
See [native installer and signing details](native-installers.md).

## Downloadable self-hosted package

Each versioned GitHub Release includes a `.tar.gz` and `.zip` bundle. The
bundle contains the backend, frontend, production Compose configuration, and a
small installer. Docker images are built locally so users can inspect the exact
source they run.

Requirements:

- Docker Desktop or Docker Engine
- Docker Compose v2 (`docker compose`)
- 4 GB RAM minimum; 8 GB recommended

Installation:

```bash
tar -xzf marcellus-VERSION.tar.gz
cd marcellus-VERSION
./install.sh
```

The installer creates `.env` with unique random values for `SECRET_KEY`,
`POSTGRES_PASSWORD`, and `REDIS_PASSWORD`, validates the Compose model, builds
the containers, and starts Enkstein. Existing `.env` files are never
overwritten.

Open:

- UI: `http://localhost:3000`
- API documentation: `http://localhost:8000/docs`

Useful commands:

```bash
docker compose --env-file .env -f compose.yaml ps
docker compose --env-file .env -f compose.yaml logs -f
docker compose --env-file .env -f compose.yaml down
```

Do not use `down -v` unless you intentionally want to delete PostgreSQL data,
encrypted connector credentials, and runtime state.

## Python packages

Release assets also include wheels and source distributions for:

- `regentclaw-cli`
- `regentclaw-core`
- `regentclaw-mcp`

Install a downloaded wheel with `pipx` or `pip`:

```bash
pipx install ./regentclaw_cli-VERSION-py3-none-any.whl
```

The compatibility CLI and MCP packages connect to a running Enkstein server; they do not
replace the self-hosted platform.

## Integrity verification

Every release includes `SHA256SUMS`:

```bash
shasum -a 256 -c SHA256SUMS
```

On Linux, use `sha256sum -c SHA256SUMS`.
