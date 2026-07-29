# Enkstein Testing Guide

This guide is for people evaluating Enkstein, especially the connectors. It
states what is verified, what is partial, and what is not built yet, so you can
spend your time where the product is real.

## What you need

- Docker Desktop, running.
- macOS 12+ or Windows 10/11 x64 for the desktop installers, or any host with
  Docker Compose for the self-hosted bundle.
- Optional: Ollama, if you want a local Brain with no API keys.

The first launch builds images and can take several minutes.

## Install

Pick one path.

**macOS desktop.** Install `Enkstein-VERSION-macos.pkg` from
[Releases](https://github.com/wcoreiron-rgb/enkstein/releases). It is signed
and notarized, so Gatekeeper accepts it without a right-click bypass.

**Windows desktop.** Run `Enkstein-VERSION-windows-x64-setup.exe`. The
installer is currently unsigned, so SmartScreen shows a publisher warning;
choose More info, then Run anyway. Verify the download against `SHA256SUMS`
in the release if you want to confirm integrity first.

**Self-hosted.** Extract the `.tar.gz` bundle and run `./install.sh`. It
creates a private `.env` with unique random secrets and never overwrites an
existing one.

On first launch you create a local owner password and enroll TOTP in an
authenticator app. Enkstein shows the QR secret once and returns ten recovery
codes. Keep them.

## Testing connectors

Go to **Connectors**. 53 connector types are registered.

### Start with the ones that need no paid account

- **Ollama.** Install Ollama and `ollama pull llama3.2`. Enkstein detects the
  runtime and lists every installed model. No key, no cost.
- **GitHub.** A personal access token with `repo` and `security_events` gives
  Developer Security real findings from secret scanning and Dependabot.
- **NVIDIA NIM.** A free key from build.nvidia.com enables a cloud Brain.
- **VirusTotal.** A free API key enables threat enrichment.

### Microsoft without an app registration

Entra ID, Azure, Defender, and Sentinel support **interactive sign-in** using
the OAuth device authorization grant. Enkstein shows a code, you approve it on
Microsoft's own sign-in page, and Enkstein receives a refresh token. No app
registration, no client secret.

This is a documented provider flow, not browser-session reuse. No cookies or
vendor session tokens are involved, and you can revoke the grant from
Microsoft's consent screen at any time.

### What "Connected" means, and what it does not

Press **Test** after configuring a connector. A pass means the credential
authenticated against the provider. It does not by itself mean the connector
produces findings, because not every connector type has a live adapter yet.

Seven Capability Nodes call a provider API when configured: Cloud Posture,
Endpoint, Developer Security, Identity, Privileged Access, Security Telemetry,
and AI Governance. The rest are connector-aware but not adapter-backed; they
keep showing demonstration findings with a `simulated` badge and report
`"Connector configured, but no live adapter is available yet"` rather than
pretending a scan failed.

### Telling real data from demonstration data

Every finding records a data origin: `live`, `simulated`, or `unknown`. An
adapter that supplies no origin is recorded as `unknown`, never `live`, so
nothing is presented as verified estate data by omission.

Filter with `GET /api/v1/findings?data_origin=live` or use the data-origin
filter in the Findings console. If you want the platform to refuse
demonstration data entirely, set `REQUIRE_LIVE_DATA=true`.

Demonstration findings never produce a control verdict. A Zero Trust control
passes only when a collector actually ran and returned no violation.

## Testing Brains

Go to **Brain Connections**.

**Local.** With Ollama running, every installed model is listed and selectable.

**Subscriptions.** If you have the Codex CLI or Claude Code installed and
signed in on the host, Enkstein detects the session and offers the models your
account is entitled to. It never copies or stores vendor credentials.

**Browser companion.** Press **Download companion** to get a zip. Unzip it,
then in Chrome or Edge open Extensions, enable Developer mode, choose Load
unpacked, and select the unzipped `enkstein-browser-companion` folder. Return
to Brain Connections and press **Pair browser**.

The companion uses only the visible signed-in page. Cookies and account tokens
never enter Enkstein.

**Secure Model Router.** Under Model Router, each provider reports real
readiness: `Ready`, `No key`, or `Offline`, with the reason. Routing is keyed
to data sensitivity, so Restricted and Top Secret stay on local Ollama while
Public and Internal may go to a cloud provider. If a cloud tier shows `No key`,
turns routed there will fail closed rather than leaking to an unconfigured
provider.

## Known gaps

Worth knowing before you file an issue:

- The Windows installer is unsigned, so SmartScreen warns on first run.
- Slack and Teams ingress works; outbound replies and approval cards do not.
- Remote-agent enrollment lacks signed tokens and key rotation.
- Compliance evidence export bundles are not built.
- Most connectors' adapters are written from API documentation and have not
  each been exercised against a live tenant. A wrong endpoint degrades to
  labelled demonstration data rather than inventing findings, but expect rough
  edges outside the seven adapter-backed nodes.

## Reporting problems

Open an issue at
[github.com/wcoreiron-rgb/enkstein/issues](https://github.com/wcoreiron-rgb/enkstein/issues).
Useful details: the version from the sidebar footer, the connector type, what
you expected, and what the response actually said. Never paste credentials,
tokens, or unredacted findings.
