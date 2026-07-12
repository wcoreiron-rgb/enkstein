# Native RegentClaw Installers

RegentClaw publishes native launchers around the self-hosted Docker runtime.
This provides a familiar installation and startup experience while preserving
the same FastAPI, Next.js, PostgreSQL, Redis, Trust Fabric, and connector
architecture used by the source deployment.

Docker Desktop remains a prerequisite. The native launchers start Docker when
needed, generate installation secrets, launch the RegentClaw containers, and
open the dashboard. They do not bundle a hidden VM, database, or credential
store outside the documented Compose runtime.

## macOS `.pkg`

The package installs `/Applications/RegentClaw.app`. Completing installation
launches the app for the signed-in user. On first launch it:

1. Copies the versioned runtime to
   `~/Library/Application Support/RegentClaw/runtime`.
2. Starts Docker Desktop if it is not already running.
3. Generates unique application, PostgreSQL, and Redis secrets.
4. Starts the production Compose stack.
5. Opens `http://localhost:3000`.

Upgrades replace application source while preserving `.env`, PostgreSQL data,
encrypted connector credentials, and runtime state.

### Apple signing prerequisites

An Apple account alone is not sufficient for trusted public distribution. The
account must be enrolled in the Apple Developer Program and have:

- A `Developer ID Application` certificate for `RegentClaw.app`.
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
`%LOCALAPPDATA%\Programs\RegentClaw`. It creates Start Menu and optional desktop
shortcuts, launches RegentClaw after setup, starts Docker Desktop when needed,
creates installation secrets, starts the Compose stack, and opens the browser.

Windows code signing is required by the tagged public-release workflow. Configure:

| Secret | Value |
|---|---|
| `WINDOWS_SIGNING_CERT_PFX_BASE64` | Base64 of an Authenticode code-signing `.pfx` |
| `WINDOWS_SIGNING_CERT_PASSWORD` | Password protecting the `.pfx` |

Without these secrets, native validation can still build a short-lived unsigned
preview, but the public release is blocked. An Apple Developer account cannot
sign a Windows executable; a separate Authenticode certificate is required.

## Publishing a release

The release workflow is triggered by a semantic version tag. Package versions
must exactly match the tag:

```bash
git tag -a v0.7.0 -m "RegentClaw v0.7.0"
git push origin v0.7.0
```

The GitHub Release is created only after portable, Python, notarized macOS, and
Windows builds finish. One `SHA256SUMS` file covers every published asset.
