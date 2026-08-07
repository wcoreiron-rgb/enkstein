# Install Enkstein

## Native installers

When a native installer is included in a GitHub Release, its asset name is:

- macOS: `Enkstein-VERSION-macos.pkg`
- Windows x64: `Enkstein-VERSION-windows-x64-setup.exe`

Both installers create a clickable Enkstein launcher. The launcher starts
Docker Desktop when needed, initializes unique secrets, and starts the
platform. On macOS, a universal native application displays startup progress,
waits for backend/frontend health, and embeds Enkstein in its own desktop
window. On Windows, WebView2 provides the native window, but Docker Desktop
remains required because Enkstein includes multiple services and persistent
PostgreSQL/Redis data. Neither installer is a standalone Docker-free runtime.

The published macOS package is Developer ID signed and notarized. Windows
installers may be unsigned when Authenticode credentials are not configured;
Windows then displays a publisher warning.
See [native installer and signing details](native-installers.md).

## Downloadable self-hosted package

The versioned `.tar.gz` release bundle contains the backend, frontend,
production Compose configuration, and a small installer. The installer first
tries the versioned images configured in `compose.yaml`. If either image cannot
be pulled, it builds the backend and frontend from the bundled source.

Requirements:

- Docker Desktop or Docker Engine
- Docker Compose v2 (`docker compose`)
- 4 GB RAM minimum; 8 GB recommended

Installation:

```bash
tar -xzf enkstein-VERSION.tar.gz
cd enkstein-VERSION
./install.sh
```

The installer creates `.env` with unique random values for `SECRET_KEY`,
`POSTGRES_PASSWORD`, and `REDIS_PASSWORD`, validates the Compose model, pulls or
builds the containers as described above, and starts Enkstein. Existing `.env`
files are never overwritten. Backend startup creates or migrates the database
schema and seeds built-in data; no manual seeding command is required.

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

- `enkstein-cli`
- `enkstein-core`
- `enkstein-mcp`

Install a downloaded wheel with `pipx` or `pip`:

```bash
pipx install ./enkstein_cli-VERSION-py3-none-any.whl
```

The compatibility CLI and MCP packages connect to a running Enkstein server; they do not
replace the self-hosted platform.

## Integrity verification

Every release includes `SHA256SUMS`:

```bash
shasum -a 256 -c SHA256SUMS
```

On Linux, use `sha256sum -c SHA256SUMS`.
