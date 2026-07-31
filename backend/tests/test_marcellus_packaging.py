from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def _read(relative_path: str) -> str:
    return (ROOT / relative_path).read_text(encoding="utf-8")


def test_native_packaging_uses_enkstein_brand_with_marcellus_compatibility_identity() -> None:
    mac_build = _read("scripts/build_macos_pkg.sh")
    mac_plist = _read("packaging/macos/Info.plist.in")
    mac_component = _read("packaging/macos/component.plist")
    windows_build = _read("scripts/build_windows_installer.ps1")
    windows_manifest = _read("packaging/windows/Marcellus.iss")

    assert "Applications/Enkstein.app" in mac_build
    assert "com.marcellus.desktop" in mac_build
    assert "com.marcellus.desktop" in mac_plist
    assert "BundleIsRelocatable" in mac_component
    assert "<false/>" in mac_component
    assert "Applications/Enkstein.app" in mac_component
    assert "Enkstein-$Version-windows-x64-setup.exe" in windows_build
    assert "AppName=Enkstein" in windows_manifest
    assert "DefaultDirName={localappdata}\\Programs\\Enkstein" in windows_manifest


def test_native_package_workflow_builds_both_desktop_installers() -> None:
    workflow = _read(".github/workflows/native-package-check.yml")

    assert "workflow_dispatch:" in workflow
    assert "runs-on: macos-14" in workflow
    assert "runs-on: windows-2022" in workflow
    assert "Enkstein-${{ env.VERSION }}-macos.pkg" in workflow
    assert "Enkstein-${{ env.VERSION }}-windows-x64-setup.exe" in workflow
    assert "Contents/Resources/EnksteinBrainBridge" in workflow
    assert "BrainBridge.ps1" in workflow


def test_native_launchers_use_isolated_runtime_paths() -> None:
    mac_launcher = _read("packaging/macos/launcher.sh")
    mac_app = _read("packaging/macos/MarcellusApp.swift")
    windows_launcher = _read("packaging/windows/Start-Marcellus.ps1")

    assert "Application Support/Marcellus" in mac_launcher
    assert "Library/Logs/Marcellus" in mac_launcher
    assert "MARCELLUS_EMBEDDED" in mac_launcher
    assert "wait_for_url" in mac_launcher
    assert 'export TMPDIR="$TEMP_DIR"' in mac_launcher
    assert "WKWebView" in mac_app
    assert "showLogin(from: endpoint)" in mac_app
    assert 'components?.path = "/login"' in mac_app
    assert "marcellusOwnerAuth" not in mac_app
    assert "authenticateLocalOwner" not in mac_app
    assert "Runtime active in background" in mac_app
    assert "applicationShouldTerminateAfterLastWindowClosed" in mac_app
    assert "false" in mac_app
    assert "NSWorkspace.shared.open(url)" in mac_app
    assert '"Enkstein\\logs"' in windows_launcher
    assert "RegentClaw" not in mac_launcher
    assert "RegentClaw" not in windows_launcher


def test_native_brain_bridge_restricts_subscription_model_overrides() -> None:
    bridge = _read("packaging/macos/MarcellusBrainBridge.swift")

    assert "!codexModels().contains(model)" in bridge
    assert "!claudeModels().contains(model)" in bridge
    assert '"supports_custom_model": false' in bridge


def test_claude_readiness_reads_reported_login_not_exit_code() -> None:
    """`claude auth status` exits 0 even when signed out, so readiness must
    come from the reported flag rather than the process exit code."""
    bridge = _read("packaging/macos/MarcellusBrainBridge.swift")

    assert 'parsed["loggedIn"] as? Bool' in bridge
    assert "let claudeAuthenticated = claudeStatus.map { $0.code == 0 }" not in bridge


def test_codex_app_server_process_launches_without_prompt() -> None:
    bridge = _read("packaging/macos/MarcellusBrainBridge.swift")

    assert "private final class CodexAppServerProcess" in bridge
    assert '["app-server", "--listen", "stdio://"]' in bridge
    assert "func start()" in bridge
    assert "func stop()" in bridge


def test_macos_bridge_exposes_opt_in_desktop_app_sessions() -> None:
    bridge = _read("packaging/macos/MarcellusBrainBridge.swift")
    build = _read("scripts/build_macos_pkg.sh")

    assert '"chatgpt_desktop"' in bridge
    assert '"claude_desktop"' in bridge
    assert '"/v1/accessibility/request"' in bridge
    assert "AXIsProcessTrustedWithOptions" in bridge
    assert "AXUIElementSetAttributeValue" in bridge
    assert "desktopInvocationLock" in bridge
    assert "frontmostApplication?.processIdentifier" in bridge
    assert "ApplicationServices" in build
    assert "browser cookies" not in bridge.lower()


def test_browser_companion_is_scoped_paired_and_packaged() -> None:
    manifest = _read("browser-extension/manifest.json")
    background = _read("browser-extension/background.js")
    content = _read("browser-extension/content.js")
    bridge = _read("packaging/macos/MarcellusBrainBridge.swift")
    mac_build = _read("scripts/build_macos_pkg.sh")
    bundle_build = _read("scripts/build_release_bundle.sh")

    assert '"https://chatgpt.com/*"' in manifest
    assert '"https://claude.ai/*"' in manifest
    assert '"https://gemini.google.com/*"' in manifest
    assert '"cookies"' not in manifest
    assert '"tabs"' not in manifest
    assert "X-Marcellus-Browser-Token" in background
    assert "marcellusSessionTabs" in background
    assert "task.session_id" in background
    assert "rememberSessionTab" in background
    assert "safeProviderUrl" in background
    assert "parsed.origin" in background
    assert "parsed.pathname" in background
    assert "mapping.url" in background
    assert "chrome.tabs.onRemoved" in background
    assert "document.cookie" not in content
    assert "document.execCommand('insertText'" in content
    assert "waitForSendButton" in content
    assert "waitForSubmission" in content
    assert "The prompt remained in the provider message field" in content
    assert '"/v1/browser/exchange"' in bridge
    assert '"/v1/browser/poll"' in bridge
    assert '"/v1/browser/complete"' in bridge
    assert "pairingCodes" in bridge
    assert "sessionID: sessionID" in bridge
    assert "queue.removeAll" in bridge
    assert "browser-bridge.token" in bridge
    assert 'cp -R "$ROOT_DIR/browser-extension"' in mac_build
    assert 'cp -R "$ROOT_DIR/browser-extension"' in bundle_build


def test_macos_app_supports_github_updates_and_relaunch() -> None:
    mac_app = _read("packaging/macos/MarcellusApp.swift")
    mac_plist = _read("packaging/macos/Info.plist.in")
    mac_build = _read("scripts/build_macos_pkg.sh")

    assert "Check for Updates…" in mac_app
    assert "Relaunch Enkstein" in mac_app
    assert "api.github.com/repos/" in mac_app
    assert "browser_download_url" in mac_app
    assert "EnksteinGitHubRepository" in mac_plist
    assert "wcoreiron-rgb/enkstein" in mac_plist
    assert "rm -rf \"$WORK_DIR\"" in mac_build


def test_no_stale_repository_names_in_user_facing_places() -> None:
    """The repo is wcoreiron-rgb/enkstein; links to the old names 404.

    The in-app update check reads the repository out of Info.plist, so a stale
    name there silently breaks "Check for Updates" rather than failing loudly.
    """
    plist = _read("packaging/macos/Info.plist.in")
    assert "wcoreiron-rgb/enkstein" in plist
    assert "wcoreiron-rgb/marcellus" not in plist

    for doc in ("README.md", "docs/index.html", "docs/testing-guide.md"):
        text = _read(doc)
        assert "wcoreiron-rgb/marcellus" not in text, doc
        assert "wcoreiron-rgb/regentclaw" not in text, doc


def test_release_bundle_is_named_for_the_product() -> None:
    """Downloadable bundles carry the product name, not the former one."""
    bundle = _read("scripts/build_release_bundle.sh")
    workflow = _read(".github/workflows/release.yml")
    mac_build = _read("scripts/build_macos_pkg.sh")

    assert 'PACKAGE_NAME="enkstein-' in bundle
    # The macOS package stages the bundle directory, so the two must agree.
    assert "$DIST_DIR/enkstein-$VERSION" in mac_build
    assert "dist/enkstein-${GITHUB_REF_NAME#v}" in workflow


def test_readme_leads_with_working_installer_links() -> None:
    """The first thing a visitor sees should be a download that works.

    The download URLs name the current version, so they must be bumped with the
    release; a stale name resolves to a 404 on the latest release.
    """
    readme = _read("README.md")
    version = _read("frontend/package.json").split('"version": "', 1)[1].split('"')[0]

    mac = f"releases/latest/download/Enkstein-{version}-macos.pkg"
    win = f"releases/latest/download/Enkstein-{version}-windows-x64-setup.exe"
    assert mac in readme
    assert win in readme

    # Requirements belong beside the button, not buried further down.
    head = readme.split("## ", 1)[0]
    assert "Docker Desktop" in head
    assert "Ollama" in head
    # Ollama is genuinely optional; saying otherwise turns people away.
    assert "Optional" in head


def test_first_launch_prefers_published_images() -> None:
    """Building the backend locally compiles Prowler; a pull should win."""
    installer = _read("packaging/install.sh")
    compose = _read("packaging/compose.release.yaml")
    workflow = _read(".github/workflows/release.yml")

    assert "ghcr.io/wcoreiron-rgb/enkstein-backend" in compose
    assert "ghcr.io/wcoreiron-rgb/enkstein-frontend" in compose
    assert "enkstein-backend:${{ steps.tags.outputs.version }}" in workflow
    assert "linux/amd64,linux/arm64" in workflow

    # A failed or absent pull must still produce a working install.
    assert "up -d --build" in installer
    assert "ENKSTEIN_FORCE_BUILD" in installer


def test_image_pull_cannot_hang_the_launcher() -> None:
    """A pull for an unpublished tag hangs rather than failing.

    Measured against the real registry: `docker pull` on a tag that does not
    exist yet does not return, so an unbounded pull would leave first launch
    waiting forever with no error shown.
    """
    installer = _read("packaging/install.sh")

    assert "run_bounded" in installer
    assert "ENKSTEIN_PULL_TIMEOUT" in installer
    assert "return 124" in installer


def test_images_exclude_local_development_state() -> None:
    """Published images must not carry a developer's venv, caches, or .env."""
    backend = _read("backend/.dockerignore")
    frontend = _read("frontend/.dockerignore")

    assert ".venv/" in backend
    assert ".env" in backend
    assert "node_modules/" in frontend


def test_windows_launcher_matches_the_unix_install_path() -> None:
    """Windows does not run install.sh, so parity has to be asserted here.

    The Windows launcher drives Compose directly. Every fix made to install.sh
    therefore misses Windows entirely unless it is mirrored, which is how
    Windows ended up still compiling images after the pull path shipped.
    """
    launcher = _read("packaging/windows/Start-Marcellus.ps1")

    # Prebuilt images, with the same build fallback and override as install.sh.
    assert "pull" in launcher
    assert "up -d --no-build" in launcher
    assert "up -d --build" in launcher
    assert "ENKSTEIN_FORCE_BUILD" in launcher

    # Compose requires ADMIN_PASSWORD; the placeholder must not survive.
    assert 'Set-EnvValue "ADMIN_PASSWORD"' in launcher
    assert "ADMIN_PASSWORD=CHANGE_ME" in launcher  # the migration check

    # The image tag is derived from APP_VERSION.
    assert 'Set-EnvValue "APP_VERSION"' in launcher


def test_launchers_do_not_fail_on_an_occupied_port() -> None:
    """Binding 3000/8000 unconditionally fails if anything else holds them.

    Reproduced locally: Compose aborts with 'port is already allocated' and the
    launcher surfaces only 'Container startup failed'.
    """
    windows = _read("packaging/windows/Start-Marcellus.ps1")
    mac = _read("packaging/macos/launcher.sh")
    env_example = _read(".env.example")

    assert "Get-FreePort" in windows
    assert "find_free_port" in mac
    # Compose only honours these if they exist in the environment file.
    assert "FRONTEND_PORT=" in env_example
    assert "BACKEND_PORT=" in env_example
    # The browser must open the port actually chosen.
    assert "http://localhost:$frontendPort" in windows


def test_windows_failure_shows_the_log_rather_than_a_path() -> None:
    """A failed launch should open the log, not name a folder to go find."""
    launcher = _read("packaging/windows/Start-Marcellus.ps1")
    assert "notepad.exe" in launcher






def test_sidebar_exposes_capabilities_not_legacy_claw_labels() -> None:
    sidebar = _read("frontend/src/components/Sidebar.tsx")

    assert "label: 'Cortex & Hearts'" in sidebar
    assert "label: 'Protection Arm'" in sidebar
    assert "label: 'Engineering Arm'" in sidebar
    assert "label: 'Cloud Security'" in sidebar
    assert "label: 'Threat Intelligence'" in sidebar
    assert "label: 'Release Governance'" in sidebar
    assert "href: '/capabilities/cloud-security'" in sidebar
    assert "href: '/capabilities/terraform-governance'" in sidebar
    assert "href: '/model-cortex'" in sidebar
    assert "label: 'CloudClaw'" not in sidebar
    assert "label: 'ThreatClaw'" not in sidebar
    assert "label: 'ReleaseClaw'" not in sidebar


def test_web_logo_assets_are_real_png_files() -> None:
    png_signature = b"\x89PNG\r\n\x1a\n"
    for relative_path in (
        "frontend/public/logo.png",
        "frontend/public/favicon.png",
        "docs/logo.png",
        "docs/favicon.png",
    ):
        asset = (ROOT / relative_path).read_bytes()
        assert asset.startswith(png_signature)
        assert asset[25] == 6, f"{relative_path} must use RGBA transparency"


def test_capability_display_names_cover_operator_surfaces() -> None:
    display_names = _read("frontend/src/lib/capability-names.ts")

    for capability in (
        "Cloud Security",
        "Identity Security",
        "Threat Analysis",
        "Model Cortex",
        "Memory Cortex",
        "Release Governance",
        "Terraform Governance",
    ):
        assert capability in display_names


def test_clean_capability_urls_rewrite_to_legacy_implementation_routes() -> None:
    next_config = _read("frontend/next.config.js")

    assert "['cloud-security', 'cloudclaw']" in next_config
    assert "['terraform-governance', 'terraclaw']" in next_config
    assert "source: '/model-cortex'" in next_config
    assert "destination: '/modelclaw'" in next_config


def test_release_frontend_waits_for_backend_health() -> None:
    compose = _read("packaging/compose.release.yaml")
    installer = _read("packaging/install.sh")

    assert 'curl", "-fsS", "http://localhost:8000/health' in compose
    assert "condition: service_healthy" in compose
    assert "ADMIN_PASSWORD" in compose
    assert "append_env_if_missing ADMIN_PASSWORD" in installer


def test_runtime_version_flows_from_package_to_sidebar() -> None:
    bundle_builder = _read("scripts/build_release_bundle.sh")
    mac_launcher = _read("packaging/macos/launcher.sh")
    compose = _read("packaging/compose.release.yaml")
    next_config = _read("frontend/next.config.js")
    sidebar = _read("frontend/src/components/Sidebar.tsx")

    assert "APP_VERSION=$SAFE_VERSION" in bundle_builder
    assert "APP_VERSION=${runtime_version}" in mac_launcher
    assert "APP_VERSION: ${APP_VERSION:-0.0.0}" in compose
    assert "source: '/runtime-info'" in next_config
    assert "fetch('/runtime-info'" in sidebar
    assert "v0.2.0" not in sidebar


def test_desktop_live_feed_uses_authenticated_websocket_handshake() -> None:
    websocket_hook = _read("frontend/src/hooks/useWebSocket.ts")
    dependencies = _read("backend/app/core/deps.py")
    websocket_route = _read("backend/app/api/routes/ws.py")

    assert "protocols: ['marcellus-auth', token]" in websocket_hook
    assert "searchParams.set('token'" not in websocket_hook
    assert 'AUTH_SUBPROTOCOL = "marcellus-auth"' in websocket_route
    assert "connection.query_params" not in dependencies
    assert '"/api/v1/ws"' in dependencies


def test_desktop_auth_is_session_scoped_and_globally_gated() -> None:
    auth = _read("frontend/src/lib/auth.ts")
    boundary = _read("frontend/src/components/AuthBoundary.tsx")
    layout = _read("frontend/src/app/layout.tsx")
    login = _read("frontend/src/app/login/page.tsx")
    mac_app = _read("packaging/macos/MarcellusApp.swift")

    assert "sessionStorage.setItem(AUTH_TOKEN_KEY" in auth
    assert "localStorage.setItem(AUTH_TOKEN_KEY" not in auth
    assert "REMEMBERED_EMAIL_KEY" in auth
    assert "Preparing the Enkstein runtime..." in boundary
    assert "router.replace('/login')" in boundary
    assert "<AuthBoundary>{children}</AuthBoundary>" in layout
    assert "rememberEmail(email)" in login
    assert "window.dispatchEvent(new Event('marcellus:lock'))" in mac_app


def test_alembic_uses_sync_driver_for_sync_migration_url() -> None:
    alembic_env = _read("backend/alembic/env.py")
    entrypoint = _read("backend/entrypoint.sh")

    assert "engine_from_config" in alembic_env
    assert "async_engine_from_config" not in alembic_env
    assert 'replace("+asyncpg", "")' in alembic_env
    assert "schema_is_materialized" in entrypoint
    assert "alembic stamp head" in entrypoint
    assert "alembic stamp 0001" not in entrypoint


def test_native_packages_include_authenticated_brain_bridges() -> None:
    mac_build = _read("scripts/build_macos_pkg.sh")
    mac_launcher = _read("packaging/macos/launcher.sh")
    windows_build = _read("scripts/build_windows_installer.ps1")
    windows_launcher = _read("packaging/windows/Start-Marcellus.ps1")

    assert "MarcellusBrainBridge.swift" in mac_build
    assert 'chmod +x "$RESOURCES_DIR/EnksteinBrainBridge"' in mac_build
    assert '--sign "$APPLE_APPLICATION_SIGNING_IDENTITY" "$RESOURCES_DIR/EnksteinBrainBridge"' in mac_build
    assert '--options runtime --timestamp' in mac_build
    assert "com.marcellus.brain-bridge" in mac_launcher
    assert "--secret-file" in mac_launcher
    assert "BRAIN_BRIDGE_SECRET" in mac_launcher
    assert 'Copy-Item (Join-Path $Root "packaging\\windows\\BrainBridge.ps1")' in windows_build
    assert "Start-BrainBridge" in windows_launcher
    assert "BRAIN_BRIDGE_SECRET" in windows_launcher


def test_macos_shell_exposes_native_cowork_folder_picker() -> None:
    mac_app = _read("packaging/macos/MarcellusApp.swift")

    assert "WKUIDelegate" in mac_app
    assert "runOpenPanelWith parameters" in mac_app
    assert "parameters.allowsDirectories" in mac_app
    assert "panel.urls" in mac_app
    assert "marcellusWorkspace" in mac_app
    assert "workspace-roots.json" in mac_app


def test_native_bridge_scopes_cowork_file_operations() -> None:
    bridge = _read("packaging/macos/MarcellusBrainBridge.swift")

    assert '"/v1/workspace/list"' in bridge
    assert '"/v1/workspace/write"' in bridge
    assert '"/v1/workspace/trash"' in bridge
    assert ".marcellus-trash" in bridge
    assert "resolvingSymlinksInPath" in bridge
    assert "candidate.path.hasPrefix(root.path" in bridge


def test_container_runtime_can_reach_only_configured_host_brain_bridge() -> None:
    development_compose = _read("docker-compose.yml")
    release_compose = _read("packaging/compose.release.yaml")
    config = _read("backend/app/core/config.py")

    for compose in (development_compose, release_compose):
        assert "host.docker.internal:host-gateway" in compose
        assert "BRAIN_BRIDGE_URL" in compose
        assert "BRAIN_BRIDGE_SECRET" in compose
        assert "BRAIN_BRIDGE_TIMEOUT_SECONDS" in compose
    assert "BRAIN_BRIDGE_URL" in config
    assert "BRAIN_BRIDGE_SECRET" in config


def test_native_browser_broker_implements_leased_protocol_with_metadata_only_journal() -> None:
    bridge = _read("packaging/macos/MarcellusBrainBridge.swift")

    assert '"protocol": 2' in bridge
    assert '"lease", "submit_ack", "progress", "complete", "cancel"' in bridge
    assert '"/v1/browser/capabilities"' in bridge
    assert '"/v1/browser/ack"' in bridge
    assert '"/v1/browser/progress"' in bridge
    assert '"/v1/browser/cancel"' in bridge
    assert "Browser progress is a real Companion heartbeat" in bridge
    assert "providers.insert(record.provider)" in bridge
    assert "lastSeen = Date()" in bridge

    assert "case queued, leased, submitted, streaming, completed, failed, cancelled, expired" in bridge

    assert "browser-broker-journal.json" in bridge
    assert "loadJournalAtStartup" in bridge
    assert "payload is unavailable after a Brain Bridge restart" in bridge
    assert "pruneTerminalHistory" in bridge
    assert "maxTerminalHistory" in bridge
    assert "SHA256.hash" in bridge
    assert "promptDigest" in bridge
    assert "posixPermissions: 0o600" in bridge
    assert "journalURL" in bridge

    journal_dict_start = bridge.index("var journalDictionary")
    journal_dict_end = bridge.index("\n    }", journal_dict_start)
    journal_dict_body = bridge[journal_dict_start:journal_dict_end]
    for forbidden in ('"prompt"', "response", "credential", "token", "cookie"):
        assert forbidden not in journal_dict_body.lower(), (
            f"journalDictionary must never persist {forbidden!r}"
        )
    assert '"prompt_digest"' in journal_dict_body


def test_browser_extension_acks_submission_and_reports_streaming_progress() -> None:
    background = _read("browser-extension/background.js")

    assert "'/v1/browser/ack'" in background
    assert "'/v1/browser/progress'" in background
    assert "task_id: entry.task_id" in background
    assert "state: 'streaming'" in background


def test_browser_companion_accepts_only_bounded_contenteditable_normalization() -> None:
    content = _read("browser-extension/content.js")

    assert "function requiredPromptMarkers" in content
    assert "expected.length < 2_000" in content
    assert "Math.floor(expected.length * 0.002)" in content
    assert "requiredPromptMarkers(expected).every" in content


def test_workspace_turns_use_a_dedicated_streaming_proxy() -> None:
    route = _read("frontend/src/app/api/v1/marcellus/workspace/conversations/[id]/turns/stream/route.ts")

    assert "export const maxDuration = 900" in route
    assert "text/event-stream" in route
    assert "X-Accel-Buffering" in route
    assert "no-cache, no-transform" in route
    assert "INTERNAL_API_URL" in route


def test_native_bridge_defines_reusable_codex_app_server_process() -> None:
    bridge = _read("packaging/macos/MarcellusBrainBridge.swift")

    # Reusable class located by the caller-supplied executable finder.
    assert "final class CodexAppServerProcess" in bridge
    assert "executableLocator: @escaping (String) -> String?" in bridge
    assert 'executableLocator("codex")' in bridge

    # app-server over stdio; prompt is never argv.
    assert '["app-server", "--listen", "stdio://"]' in bridge

    # stdin/stdout/stderr pipes.
    assert "process.standardInput = stdinPipe" in bridge
    assert "process.standardOutput = stdoutPipe" in bridge
    assert "process.standardError = stderrPipe" in bridge

    # Lifecycle.
    assert "func start() throws" in bridge
    assert "func stop()" in bridge
    assert "var isRunning: Bool" in bridge

    # JSON-RPC handshake.
    assert 'request(method: "initialize"' in bridge
    assert 'notify(method: "initialized", params: nil)' in bridge

    # Synchronized newline-delimited writes with monotonic numeric IDs.
    assert "writeLock.lock()" in bridge
    assert "line.append(0x0A)" in bridge
    assert "nextID += 1" in bridge

    # Background stdout line reader separating the three channels.
    assert "func readLoop()" in bridge
    assert 'channel: "notification"' in bridge or 'let channel = hasID ? "serverRequest" : "notification"' in bridge

    # Response waiters: 30s timeout and bounded 500-event ring.
    assert "addingTimeInterval(30)" in bridge
    assert "maxEvents = 500" in bridge

    # Termination fails pending waiters.
    assert ".failure(CodexProcessError.terminated)" in bridge

    # Public surface.
    assert "func request(method: String, params: [String: Any]?) throws -> Any?" in bridge
    assert "func notify(method: String, params: [String: Any]?) throws" in bridge
    assert "func drainEvents(after cursor: Int) -> [SanitizedEvent]" in bridge

    # Sanitization retains routing/telemetry, discards free-text bodies.
    for retained in ('"threadId"', '"turnId"', '"usage"', "safeItem"):
        assert retained in bridge
    sanitize_start = bridge.index("private func sanitize(")
    sanitize_end = bridge.index("private func numericFields")
    sanitize_body = bridge[sanitize_start:sanitize_end].lower()
    for forbidden in ("prompt", "delta", "command", "arguments", "output", "patch"):
        assert forbidden not in sanitize_body, f"sanitize must not retain {forbidden!r}"


def test_codex_app_server_session_manager_governs_scoped_threads() -> None:
    bridge = _read("packaging/macos/MarcellusBrainBridge.swift")

    # One shared transport reused by a dedicated session manager.
    assert "final class CodexAppServerSessionManager" in bridge
    assert "private let process: CodexAppServerProcess" in bridge
    assert "CodexAppServerProcess(executableLocator: findExecutable)" in bridge

    # Exact JSON-RPC methods used against the generated schema.
    for method in ('"thread/start"', '"thread/resume"', '"turn/start"', '"turn/interrupt"'):
        assert method in bridge
    assert 'method: "thread/start"' in bridge
    assert 'method: "thread/resume"' in bridge
    assert 'method: "turn/start"' in bridge
    assert 'method: "turn/interrupt"' in bridge

    # Scope digest regex and internal scope keying (digest + workspace token).
    assert 'scopeDigestPattern = "^[a-f0-9]{64}$"' in bridge
    assert "func scopeKey(scopeDigest: String, token: String)" in bridge
    assert '"\\(scopeDigest):\\(token)"' in bridge

    # cwd resolved only from the workspace token, never from the request.
    assert "workspaceRootResolver: (String) throws -> URL" in bridge
    assert "root = try workspaceRootResolver(token)" in bridge
    assert '"cwd": root.path' in bridge
    assert "workspaceRoot(token: token)" in bridge

    # Restrictive approval policy and sandbox validation.
    assert 'approvalPolicy = "untrusted"' in bridge
    assert 'sandbox == "read-only" || sandbox == "workspace-write"' in bridge

    # Prompt bounds; prompt only travels over stdin, never persisted.
    assert "maxPromptLength = 128_000" in bridge
    assert 'params: [String: Any] = [\n            "threadId": session.threadId,\n            "input": [["type": "text", "text": prompt]],' in bridge


def test_codex_app_server_persists_only_opaque_metadata_owner_only() -> None:
    bridge = _read("packaging/macos/MarcellusBrainBridge.swift")

    assert "codex-app-server-sessions.json" in bridge
    assert "posixPermissions: 0o600" in bridge
    assert "replaceItemAt(storeURL, withItemAt: temp)" in bridge

    persist_start = bridge.index("private func persistSessions()")
    persist_end = bridge.index("\n    }", bridge.index("guard let data = try? JSONSerialization.data", persist_start))
    persist_body = bridge[persist_start:persist_end].lower()
    assert '"scope_key"' in persist_body
    assert '"thread_id"' in persist_body
    for forbidden in ("prompt", "response", "credential", "cookie", "input", "event"):
        assert forbidden not in persist_body, f"persistSessions must never write {forbidden!r}"


def test_codex_app_server_approvals_are_allowlisted_and_declinable() -> None:
    bridge = _read("packaging/macos/MarcellusBrainBridge.swift")

    for method in (
        '"item/commandExecution/requestApproval"',
        '"item/fileChange/requestApproval"',
        '"item/permissions/requestApproval"',
    ):
        assert method in bridge

    # Unsupported server requests are auto-declined without exposing a body.
    assert 'respondError(id: requestId, code: -32601, message: "Unsupported request")' in bridge
    assert "func respond(id: Int, result: [String: Any])" in bridge

    # Approvals accept only accept/decline and never grant session scope.
    assert 'decision == "accept" || decision == "decline"' in bridge
    assert '"decision": accept ? "accept" : "decline"' in bridge
    assert "acceptForSession" not in bridge

    # Only allowlisted approval requests retain a routable numeric id.
    assert "let approvalRequestId: Int?" in bridge
    assert "approvalRequestId: requestId, approvalMethod: method" in bridge


def test_codex_app_server_interrupt_and_resume_semantics() -> None:
    bridge = _read("packaging/macos/MarcellusBrainBridge.swift")

    # Persisted sessions load interrupted and resume on next start.
    assert "interrupted: true" in bridge
    assert 'method: "thread/resume", params: params' in bridge
    assert '"status": running ? "running" : "interrupted"' in bridge
    assert "session.interrupted = true" in bridge


def test_codex_app_server_http_routes_are_token_guarded() -> None:
    bridge = _read("packaging/macos/MarcellusBrainBridge.swift")

    for route in (
        '"/v1/codex/start"',
        '"/v1/codex/turn"',
        '"/v1/codex/status"',
        '"/v1/codex/approve"',
        '"/v1/codex/cancel"',
    ):
        assert route in bridge

    # Routes live after the bridge-token guard.
    guard_index = bridge.index('x-marcellus-bridge-token')
    assert bridge.index('"/v1/codex/start"') > guard_index
    assert "codexSessions.start(scopeDigest: scope, token: token, sandbox: sandbox)" in bridge
    assert "CodexAppServerSessionManager.SessionError.invalid(detail)" in bridge


def test_codex_app_server_drains_stderr_and_cleans_up_failed_handshake() -> None:
    bridge = _read("packaging/macos/MarcellusBrainBridge.swift")

    # stderr is drained on a dedicated thread and never retained/logged.
    assert "stderrThread" in bridge
    assert "func stderrDrainLoop()" in bridge
    assert "codex-app-server-stderr" in bridge

    # A failed handshake cleanly terminates the transport.
    handshake_call = bridge.index("try handshake()")
    tail = bridge[handshake_call:handshake_call + 260]
    assert "catch {" in tail
    assert "stop()" in tail


def test_codex_app_server_status_is_strictly_thread_scoped() -> None:
    bridge = _read("packaging/macos/MarcellusBrainBridge.swift")

    # Threadless notifications are dropped, never fanned out to every session.
    assert 'guard let threadId = event.fields["threadId"] as? String else { return false }' in bridge
    assert "return threadId == refreshed.threadId" in bridge

    # Pending approvals require an exact thread match.
    assert "$0.threadId == refreshed.threadId" in bridge

    # approve() matches the current session thread, not approval_id alone.
    assert "$0.approvalId == approvalId && $0.threadId == session.threadId" in bridge


def test_codex_app_server_auto_declines_threadless_approvals() -> None:
    bridge = _read("packaging/macos/MarcellusBrainBridge.swift")

    # PendingApproval carries a concrete (non-optional) threadId.
    assert "let threadId: String\n" in bridge

    ingest_start = bridge.index("private func ingestEventsLocked()")
    ingest_body = bridge[ingest_start:bridge.index("private func updateTurnStateLocked")]
    # Unknown/threadless allowlisted approvals are auto-declined, not enqueued.
    assert "sessions.values.contains(where: { $0.threadId == threadId })" in ingest_body
    assert "approvalResponse(method: method, accept: false)" in ingest_body


def test_codex_app_server_surfaces_only_bounded_allowlisted_transient_content() -> None:
    bridge = _read("packaging/macos/MarcellusBrainBridge.swift")

    assert "maxTextField = 32 * 1024" in bridge
    assert "func transientContent(method: String?, params: [String: Any])" in bridge

    transient_start = bridge.index("func transientContent(")
    transient_body = bridge[transient_start:bridge.index("private func approvalDetail")]
    for method in (
        '"item/agentMessage/delta"',
        '"item/plan/delta"',
        '"turn/diff/updated"',
    ):
        assert method in transient_body
    # Every non-allowlisted method returns nil (no other body retained).
    assert "default:\n            return nil" in transient_body


def test_codex_app_server_approval_detail_is_bounded_and_non_sensitive() -> None:
    bridge = _read("packaging/macos/MarcellusBrainBridge.swift")

    detail_start = bridge.index("private func approvalDetail(method: String")
    detail_body = bridge[detail_start:bridge.index("\n    }\n}", detail_start)]

    # Command approvals may include command/reason/cwd-basename/itemId/turnId.
    assert '"command"' in detail_body
    assert '"reason"' in detail_body
    assert "lastPathComponent" in detail_body
    assert '"itemId"' in detail_body
    assert '"turnId"' in detail_body

    # File/permission approvals never leak a grant root or an absolute path.
    assert "grantRoot" not in detail_body
    assert '"path"' not in detail_body


def test_codex_app_server_status_distinguishes_transport_session_and_turn() -> None:
    bridge = _read("packaging/macos/MarcellusBrainBridge.swift")

    assert '"transport": process.isRunning ? "running" : "interrupted"' in bridge
    assert '"session": running ? "active" : "interrupted"' in bridge
    assert '"turn": refreshed.turnState' in bridge

    # Turn state advances from exact notifications only.
    assert "func updateTurnStateLocked(threadId: String, method: String, fields: [String: Any])" in bridge
    assert 'let finalStatus = (fields["turnStatus"] as? String ?? "").lowercased()' in bridge
    assert 'case "turn/failed", "turn/interrupted", "turn/aborted"' not in bridge
    assert 'case "turn/completed":' in bridge


def test_release_bundle_carries_brain_bridge_operator_docs() -> None:
    bundle_builder = _read("scripts/build_release_bundle.sh")

    assert 'docs/brain-bridges.md" "$STAGE_DIR/docs/brain-bridges.md' in bundle_builder


def test_cli_subprocess_environment_carries_user_identity() -> None:
    """The Claude CLI resolves its login session through the user's Keychain.

    Without USER/LOGNAME it reports {"loggedIn": false} on a host that is in
    fact authenticated, so Claude Subscription read "Needs setup" forever.
    """
    bridge = _read("packaging/macos/MarcellusBrainBridge.swift")

    assert "let userName = NSUserName()" in bridge
    assert '"USER": userName,' in bridge
    assert '"LOGNAME": userName,' in bridge

    # The environment stays explicit rather than inheriting the caller's.
    assert "process.environment = [" in bridge


def test_claude_models_come_from_real_entitlement_not_three_aliases() -> None:
    """Claude offered only sonnet/opus/haiku regardless of plan.

    Codex reads its own model cache, but Claude returned a hardcoded trio, so
    models the account is actually entitled to were unreachable from the
    picker. Entitlement is now read from Claude Code's own state file.
    """
    bridge = _read("packaging/macos/MarcellusBrainBridge.swift")

    assert 'appendingPathComponent(".claude.json")' in bridge
    assert 'payload["modelAccessCache"]' in bridge
    assert 'row["entitled"] as? Bool == true' in bridge
    # The org default is selectable even when absent from the access list.
    assert 'payload["orgModelDefaultCache"]' in bridge
    # Aliases remain, and remain the fallback when the cache is unreadable.
    assert 'let aliases = ["sonnet", "opus", "haiku"]' in bridge
    assert "if entitled.isEmpty { return aliases }" in bridge


def test_browser_companion_ships_in_both_installers() -> None:
    """A tester cannot load an extension that was never packaged.

    macOS bundled it, Windows did not, so Windows testers had no way to use the
    Browser Companion at all.
    """
    mac_build = _read("scripts/build_macos_pkg.sh")
    windows_build = _read("scripts/build_windows_installer.ps1")

    assert "browser-extension" in mac_build
    assert "browser-extension" in windows_build


def test_windows_release_is_not_blocked_by_missing_signing_cert() -> None:
    """Signing is applied when configured, but does not gate the release.

    Throwing on absent Authenticode secrets meant no Windows build shipped at
    all, rather than an unsigned one testers could still run.
    """
    workflow = _read(".github/workflows/release.yml")

    assert "publishing an unsigned installer" in workflow
    assert "Windows Authenticode signing secrets are required" not in workflow
    # Signing still runs and still fails loudly when a certificate is present.
    assert 'throw "Windows installer signing failed"' in workflow


def test_release_publishes_without_apple_secrets_in_ci() -> None:
    """A tag must still yield downloadable assets on a repo without Apple certs.

    macOS packages are signed and notarized on the maintainer's machine. When CI
    has no Apple secrets the macOS job used to fail outright, and ``publish``
    needed it, so tagging produced no release at all.
    """
    workflow = _read(".github/workflows/release.yml")

    assert "skipping the CI macOS build" in workflow
    assert "Missing required Apple signing/notarization secret" not in workflow
    # publish no longer dies with the macOS job, but still requires real assets.
    assert "needs.portable.result == 'success'" in workflow


def test_python_package_versions_match_the_app_version() -> None:
    """The release workflow refuses to build when these drift from the tag."""
    expected = _read("frontend/package.json").split('"version": "', 1)[1].split('"')[0]

    for manifest in (
        "cli/pyproject.toml",
        "enkstein-core/pyproject.toml",
        "mcp-server/pyproject.toml",
    ):
        line = next(
            candidate
            for candidate in _read(manifest).splitlines()
            if candidate.replace(" ", "").startswith("version=")
        )
        assert expected in line, f"{manifest} is {line.strip()}, app is {expected}"



def test_testing_guide_states_what_a_connector_test_proves() -> None:
    """Evaluators need the limits stated, not discovered."""
    guide = _read("docs/testing-guide.md")
    readme = _read("README.md")

    assert "docs/testing-guide.md" in readme
    # The honest boundary: authentication is not the same as live findings.
    assert "does not by itself mean the connector" in guide
    # Known gaps are declared rather than left for a tester to trip over.
    assert "Known gaps" in guide
    assert "unsigned" in guide
