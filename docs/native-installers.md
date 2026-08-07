# Native Enkstein Installers

Enkstein packages native launchers around the self-hosted Docker runtime.
This provides a familiar installation and startup experience while preserving
the same FastAPI, Next.js, PostgreSQL, Redis, Trust Fabric, and connector
architecture used by the source deployment.

Docker Desktop remains a prerequisite. The native launchers start Docker when
needed, generate installation secrets, and launch the Enkstein containers.
They do not bundle a hidden VM, database, or credential store outside the
documented Compose runtime.

Before any Enkstein service starts, the native launcher shows a Docker Desktop
prerequisite step and checks `docker info`. It distinguishes a healthy engine,
an installed-but-stopped engine, a missing installation, an unhealthy engine,
and a bounded startup timeout. Installed Docker Desktop is opened automatically
and polled until healthy. If Docker is missing, the launcher opens only Docker's
official installation flow; it does not download an executable from a mirror or
bypass Docker's installer, administrator approval, licensing, or reboot flow.
Compose is never invoked before `docker info` succeeds.

#### Reaching the missing-Docker screen for testing

The prerequisite helpers read `ENKSTEIN_DOCKER_COMMAND` and
`ENKSTEIN_DOCKER_APP`. Pointing both at paths that do not exist reproduces the
missing-Docker screen -- the Docker required message with Install Docker, Open
Startup Log, and Retry -- without uninstalling Docker or removing any image,
volume, or container:

```bash
ENKSTEIN_DOCKER_COMMAND=/nonexistent/docker \
ENKSTEIN_DOCKER_APP=/nonexistent/Docker.app \
ENKSTEIN_DOCKER_INSTALL_ATTEMPTS=0 \
  open -a Enkstein
```

`ENKSTEIN_DOCKER_INSTALL_ATTEMPTS=0` (macOS) and
`ENKSTEIN_DOCKER_INSTALL_TIMEOUT=0` (Windows) hold the terminal missing state
instead of polling for an install, so the install action stays on screen. No
backend, runtime staging, or Compose command runs in this state.

### Native Codex App Server boundary

The macOS Brain Bridge launches the authenticated official
`codex app-server` over stdio for Cowork Agent tools. It stores only
owner-readable opaque scope/thread metadata under Enkstein Application Support;
it does not store prompts, CLI output, commands, patches, raw project paths, or
vendor credentials. The helper binds execution to a desktop-approved project
grant, so the container and web client cannot select an arbitrary cwd. Stopping
the helper interrupts active turns; starting it again attempts to resume the
persisted thread through the official protocol.

## macOS `.pkg`

The package installs `/Applications/Enkstein.app`. Completing installation
launches the app for the signed-in user. On first launch it:

1. Shows **Docker Desktop required** and checks whether the Docker engine is
   healthy.
2. Opens Docker Desktop when it is installed but stopped, or opens Docker's
   official installation page when it is missing. Retry and startup-log controls
   remain available while the engine becomes ready.
3. Copies the versioned runtime to
   `~/Library/Application Support/Marcellus/runtime`, the compatibility data
   location retained during the Enkstein rename.
4. Generates unique application, PostgreSQL, and Redis secrets.
5. Tries the versioned published backend and frontend images, then falls back to
   a local build before starting the production Compose stack if either pull
   fails.
6. Waits for PostgreSQL, Redis, the backend health endpoint, and the frontend.
7. Opens the governed UI inside a native WebKit desktop window.
8. Requires the local owner to create a password, scan an Authenticator QR
   code, confirm the first TOTP, and save one-time recovery codes.
9. Starts the authenticated native Brain Bridge used by Model Cortex for
   supported Codex and Claude subscription runtimes.

The app is a universal Intel and Apple Silicon executable. External links open
in the default browser, while Enkstein routes remain inside the app. The first
launch can take many minutes when the published images are unavailable because
the local backend build installs Prowler and its dependency tree. The app shows
Docker prerequisite and general startup states instead of displaying the UI
before the backend is ready; pull and build details are written only to:

```text
~/Library/Logs/Marcellus/launcher.log
```

Upgrades replace application source while preserving `.env`, PostgreSQL data,
encrypted connector credentials, and runtime state.

### Console and runtime lifecycle

The desktop window is a console, not the security runtime itself. Closing the
window leaves the macOS menu-bar process and Docker services running. The menu
provides **Open Enkstein**, **Lock Console**, and **Quit Console (Runtime
Continues)**. The console also locks after 30 minutes without interaction.

Monitoring, schedules, active Swarms, and approved background automation keep
running while the console is closed or locked. Approval-required actions wait
for an authenticated owner. A new process launch requires the owner password
and a fresh six-digit Authenticator code. Email-code viewer access is optional
and appears only after an Email/SMTP connector is configured.

The first-run owner API is:

```text
GET  /api/v1/auth/owner/status
POST /api/v1/auth/owner/setup
POST /api/v1/auth/owner/setup/confirm
POST /api/v1/auth/owner/login
POST /api/v1/auth/owner/recovery
```

The TOTP secret and password hash are encrypted in the persistent backend
secret volume. Recovery codes are stored only as keyed digests and each code is
removed atomically after use. The old native password-only owner shortcut is
not available after MFA enrollment.

### Native Brain Bridge lifecycle

The macOS launcher starts a separate signed universal helper and leaves it
running with the Docker services. A random bridge secret is generated once at
`~/Library/Application Support/Enkstein/brain-bridge.secret` with owner-only
permissions. The container reaches the host helper through Docker Desktop's
host gateway; vendor subscription credentials never cross that boundary.

The helper detects the official Codex binary bundled with ChatGPT or installed
separately and the official Claude host runtime when present. Missing or
unauthenticated runtimes appear as unavailable in Model Cortex. See
[Brain Bridges](brain-bridges.md).

Version 0.8.3 verifies Codex with `codex login status` and Claude Code with
`claude auth status`; finding an executable alone does not establish readiness.
Codex and Claude prompts are written through stdin, Codex uses a read-only
sandbox, and Claude receives an empty tool set. Brain Connections performs a
forced live refresh after launch, on focus, and after setup actions. The bridge
never returns executable paths, credentials, cookies, tokens, or prompt text in
status responses.

Build a local unsigned package for installation testing:

```bash
./scripts/build_macos_pkg.sh 0.8.3
open dist/Enkstein-0.8.3-macos.pkg
```

The output is `dist/Enkstein-0.8.3-macos.pkg`. Local builds use ad-hoc app
signing and are not suitable for public distribution until Developer ID
signing and notarization are configured.

### Apple signing prerequisites

An Apple account alone is not sufficient for trusted public distribution. The
account must be enrolled in the Apple Developer Program and have:

- A `Developer ID Application` certificate for `Enkstein.app`.
- A `Developer ID Installer` certificate for the `.pkg`.
- An app-specific password for notarization.

Export both certificates and their private keys as password-protected `.p12`
files. Add these encrypted GitHub repository secrets:

| Secret | Value |
|---|---|
| `APPLE_APPLICATION_CERT_P12_BASE64` | Base64 of the Developer ID Application `.p12` |
| `APPLE_APPLICATION_CERT_PASSWORD` | Password used when exporting that `.p12` |
| `APPLE_APPLICATION_SIGNING_IDENTITY` | Exact identity, such as `Developer ID Application: Organization (TEAMID)` |
| `APPLE_INSTALLER_CERT_P12_BASE64` | Base64 of the Developer ID Installer `.p12` |
| `APPLE_INSTALLER_CERT_PASSWORD` | Password used when exporting that `.p12` |
| `APPLE_INSTALLER_SIGNING_IDENTITY` | Exact identity, such as `Developer ID Installer: Organization (TEAMID)` |
| `APPLE_ID` | Apple Developer account email |
| `APPLE_TEAM_ID` | Ten-character Apple Developer team ID |
| `APPLE_APP_PASSWORD` | Apple app-specific password, not the account password |

Create a one-line Base64 value on macOS with:

```bash
base64 < developer-id-application.p12 | tr -d '\n'
```

Never commit certificates, private keys, passwords, or Base64 certificate data.
When all required Apple secrets are configured, the release workflow signs the
app and installer, submits the package to Apple's notary service, staples the
ticket, and validates Gatekeeper acceptance. When those secrets are absent, the
macOS job skips the package so a separately notarized package can be attached.

## Windows `.exe`

The Windows installer is built with Inno Setup and installs per-user under
`%LOCALAPPDATA%\Programs\Enkstein`. It creates Start Menu and optional desktop
shortcuts with the stable `Enkstein.Desktop` AppUserModelID, launches the native
WebView2 Enkstein window after setup, starts Docker Desktop when needed,
creates installation secrets, and starts the Compose stack.

Before Compose is touched, the launcher displays the Docker prerequisite state:
healthy, installed but stopped, missing, unhealthy, or timed out. It opens an
installed Docker Desktop automatically and polls `docker info`. For a missing
installation it opens Docker's official installation flow and keeps checking
for the engine after the user completes Docker's own installer. The native
screen exposes Retry, Open Docker, Install Docker, and Open Startup Log actions.

This is a native desktop shell around the Enkstein runtime, not a standalone
runtime bundle. Docker Desktop with its Linux engine is still required on
Windows; the installer does not silently provide PostgreSQL, Redis, or the
backend/frontend containers. The launcher shows the Docker-specific state and
actionable controls when the engine is unavailable. Removing that dependency requires a
 separate native-runtime distribution and is not claimed by this installer.

The canonical app icon is `frontend/public/enkstein-icon.png`: a red/orange
octopus centered on a white rounded-square tile, with transparent pixels outside
the rounded corners. The same artwork is used for the executable, installer,
shortcuts, and taskbar identity. `favicon-liquid.png` is reserved for explicit
Liquid Glass presentation and is never used for the app icon.

`packaging/windows/Enkstein.ico` is generated from that artwork by
`scripts/generate_app_icon.py` and committed, so the frames Windows loads are the
exact bytes the packaging tests validate. Regenerate it whenever the artwork
changes:

```bash
python scripts/generate_app_icon.py
```

The ICO ships 32-bit RGBA frames at 16, 24, 32, 48, 64, 128, and 256 pixels.
Windows selects a different frame per surface, so `packaging/tests/test_windows_icon_alpha.py`
checks every frame individually: all four outer corners must be alpha 0, the tile
just inside the rounded corner must be opaque white, and the octopus must still
be present after downscaling. The Windows build repeats the corner and tile
checks with `System.Drawing` and fails rather than shipping an opaque square.

The ICO canvas is square by format; only the artwork is rounded. If Windows still
paints a square behind the icon on the Desktop, Start Menu, or taskbar after
those checks pass, that is Windows shell rendering of the icon surface, not the
Enkstein artwork. Do not add a square background to compensate: doing so would
reintroduce the white box on dark taskbars and would fail the alpha checks above.

The tagged release workflow applies Windows code signing when these secrets are
configured:

| Secret | Value |
|---|---|
| `WINDOWS_SIGNING_CERT_PFX_BASE64` | Base64 of an Authenticode code-signing `.pfx` |
| `WINDOWS_SIGNING_CERT_PASSWORD` | Password protecting the `.pfx` |

The Windows launcher also generates a per-install Brain Bridge secret, starts
the loopback/private-peer PowerShell bridge in a hidden background process, and
passes only its host-gateway endpoint and secret to Docker. Codex and Claude
are detected from official host installations; missing or unauthenticated
runtimes remain visibly unavailable.

Without these secrets, the tagged release workflow and native validation can
build an unsigned installer. Windows displays a publisher warning for that
artifact. An Apple Developer account cannot sign a Windows executable; a
separate Authenticode certificate is required.

To create an unsigned Windows preview, run the **Native Package Validation**
workflow manually from GitHub Actions. Its `windows-package` job runs on
Windows Server, installs Inno Setup and ImageMagick, and uploads:

```text
Enkstein-<version>-windows-x64-setup.exe
```

On a Windows development machine with those tools installed, the equivalent
local command is:

```powershell
.\scripts\build_windows_installer.ps1 -Version 0.8.3
```

Release gate: the Windows launcher and installer are not considered verified
from a macOS checkout. Before publishing, build the C# WebView2 host on a real
Windows machine, install the generated package, and test Start Menu launch,
desktop/taskbar identity, uninstall/reinstall cleanup, opaque light/dark modes,
Liquid Glass subtle/balanced/clear, and the transparency-disabled fallback.
Until that host test passes, do not call the Windows package production-ready.

## Publishing a release

The release workflow is triggered by a semantic version tag. Package versions
must exactly match the tag:

```bash
git tag -a v0.8.3 -m "Enkstein v0.8.3"
git push origin v0.8.3
```

The publish job requires the portable and Python package job to succeed. It runs
after the native jobs finish or fail and downloads whichever native artifacts
were produced; the runtime-image job is not a publication dependency. A
complete release should be checked for both native installers, both stable
aliases, both runtime-image manifests, and a `SHA256SUMS` entry for every
published file.
