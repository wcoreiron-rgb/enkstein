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
    assert '"Marcellus\\logs"' in windows_launcher
    assert "RegentClaw" not in mac_launcher
    assert "RegentClaw" not in windows_launcher


def test_native_brain_bridge_restricts_subscription_model_overrides() -> None:
    bridge = _read("packaging/macos/MarcellusBrainBridge.swift")

    assert "!codexModels().contains(model)" in bridge
    assert "!claudeModels().contains(model)" in bridge
    assert '"supports_custom_model": false' in bridge


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
    assert "pendingTaskIDs" in bridge
    assert 'task["session_id"]' in bridge
    assert "queuedTasks.removeAll" in bridge
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
    assert "wcoreiron-rgb/marcellus" in mac_plist
    assert "rm -rf \"$WORK_DIR\"" in mac_build


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


def test_release_bundle_carries_brain_bridge_operator_docs() -> None:
    bundle_builder = _read("scripts/build_release_bundle.sh")

    assert 'docs/brain-bridges.md" "$STAGE_DIR/docs/brain-bridges.md' in bundle_builder
