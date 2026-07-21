# Native Enkstein Installers

Enkstein publishes native launchers around the self-hosted Docker runtime.
This provides a familiar installation and startup experience while preserving
the same FastAPI, Next.js, PostgreSQL, Redis, Trust Fabric, and connector
architecture used by the source deployment.

Docker Desktop remains a prerequisite. The native launchers start Docker when
needed, generate installation secrets, and launch the Enkstein containers.
They do not bundle a hidden VM, database, or credential store outside the
documented Compose runtime.

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

1. Copies the versioned runtime to
   `~/Library/Application Support/Marcellus/runtime` (the compatibility data
   location retained during the Enkstein rename).
2. Starts Docker Desktop if it is not already running.
3. Generates unique application, PostgreSQL, and Redis secrets.
4. Starts the production Compose stack.
5. Waits for PostgreSQL, Redis, the backend health endpoint, and the frontend.
6. Opens the governed UI inside a native WebKit desktop window.
7. Requires the local owner to create a password, scan an Authenticator QR
   code, confirm the first TOTP, and save one-time recovery codes.
8. Starts the authenticated native Brain Bridge used by Model Cortex for
   supported Codex and Claude subscription runtimes.

The app is a universal Intel and Apple Silicon executable. External links open
in the default browser, while Enkstein routes remain inside the app. The first
launch can take several minutes because Docker builds the local backend and
frontend images. The app shows startup status instead of displaying the UI
before the backend is ready. Startup diagnostics are written to:

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
`~/Library/Application Support/Marcellus/brain-bridge.secret` with owner-only
permissions. The container reaches the host helper through Docker Desktop's
host gateway; vendor subscription credentials never cross that boundary.

The helper detects the official Codex binary bundled with ChatGPT or installed
separately and the official Claude host runtime when present. Missing or
unauthenticated runtimes appear as unavailable in Model Cortex. See
[Brain Bridges](brain-bridges.md).

Version 0.3.14 verifies Codex with `codex login status` and Claude Code with
`claude auth status`; finding an executable alone does not establish readiness.
Codex and Claude prompts are written through stdin, Codex uses a read-only
sandbox, and Claude receives an empty tool set. Brain Connections performs a
forced live refresh after launch, on focus, and after setup actions. The bridge
never returns executable paths, credentials, cookies, tokens, or prompt text in
status responses.

Build a local unsigned package for installation testing:

```bash
./scripts/build_macos_pkg.sh 0.3.14
open dist/Enkstein-0.3.14-macos.pkg
```

The output is `dist/Enkstein-0.3.14-macos.pkg`. Local builds use ad-hoc app
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
The release workflow fails before publication when required Apple secrets are
missing. It signs the app, signs the installer, submits the package to Apple's
notary service, staples the ticket, and validates Gatekeeper acceptance.

## Windows `.exe`

The Windows installer is built with Inno Setup and installs per-user under
`%LOCALAPPDATA%\Programs\Enkstein`. It creates Start Menu and optional desktop
shortcuts, launches Enkstein after setup, starts Docker Desktop when needed,
creates installation secrets, starts the Compose stack, and opens the browser.

Windows code signing is required by the tagged public-release workflow. Configure:

| Secret | Value |
|---|---|
| `WINDOWS_SIGNING_CERT_PFX_BASE64` | Base64 of an Authenticode code-signing `.pfx` |
| `WINDOWS_SIGNING_CERT_PASSWORD` | Password protecting the `.pfx` |

The Windows launcher also generates a per-install Brain Bridge secret, starts
the loopback/private-peer PowerShell bridge in a hidden background process, and
passes only its host-gateway endpoint and secret to Docker. Codex and Claude
are detected from official host installations; missing or unauthenticated
runtimes remain visibly unavailable.

Without these secrets, native validation can still build a short-lived unsigned
preview, but the public release is blocked. An Apple Developer account cannot
sign a Windows executable; a separate Authenticode certificate is required.

To create an unsigned Windows preview, run the **Native Package Validation**
workflow manually from GitHub Actions. Its `windows-package` job runs on
Windows Server, installs Inno Setup and ImageMagick, and uploads:

```text
Enkstein-<version>-windows-x64-setup.exe
```

On a Windows development machine with those tools installed, the equivalent
local command is:

```powershell
.\scripts\build_windows_installer.ps1 -Version 0.2.0
```

## Publishing a release

The release workflow is triggered by a semantic version tag. Package versions
must exactly match the tag:

```bash
git tag -a v0.7.0 -m "Enkstein v0.7.0"
git push origin v0.7.0
```

The GitHub Release is created only after portable, Python, notarized macOS, and
Windows builds finish. One `SHA256SUMS` file covers every published asset.
