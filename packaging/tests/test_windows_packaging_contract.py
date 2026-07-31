"""Static packaging contracts that can run on non-Windows CI.

These do not pretend to replace a Windows build/install smoke test. They catch
the regressions that are easy to introduce on any host: the wrong icon source,
missing AppUserModelID, accidental browser-first startup, stale branding, and
an undocumented Docker dependency.
"""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WINDOWS = ROOT / "packaging" / "windows"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_windows_launcher_has_stable_identity_and_native_webview_host():
    source = read(WINDOWS / "MarcellusLauncher.cs")
    assert 'AppUserModelId = "Enkstein.Desktop"' in source
    assert "SetCurrentProcessExplicitAppUserModelID" in source
    assert "WebView2" in source
    assert 'Text = AppIdentity.ProductName' in source
    assert 'DefaultUrl = "http://localhost:3000"' in source


def test_installer_creates_only_enkstein_shortcuts_and_removes_legacy_names():
    source = read(WINDOWS / "Marcellus.iss")
    assert 'Name: "{autoprograms}\\Enkstein"' in source
    assert 'Name: "{autodesktop}\\Enkstein"' in source
    assert 'AppUserModelID: "Enkstein.Desktop"' in source
    assert 'Name: "{autoprograms}\\Marcellus.lnk"' in source
    assert 'Name: "{autoprograms}\\RegentClaw.lnk"' in source


def test_build_uses_transparent_standard_logo_not_glass_tile():
    source = read(ROOT / "scripts" / "build_windows_installer.ps1")
    assert 'frontend\\public\\enkstein-icon.png' in source
    assert 'frontend\\public\\favicon-liquid.png' not in source
    assert "alpha" in source


def test_web_favicon_is_not_the_opaque_liquid_tile():
    source = read(ROOT / "frontend" / "src" / "app" / "layout.tsx")
    assert "/favicon-liquid.png" not in source
    assert "/enkstein-icon.png" in source


def test_canonical_icon_has_transparent_corners_and_white_tile():
    from PIL import Image

    icon = Image.open(ROOT / "frontend" / "public" / "enkstein-icon.png").convert("RGBA")
    assert icon.size == (1024, 1024)
    assert icon.getpixel((0, 0))[3] == 0
    assert icon.getpixel((512, 32))[:3] == (255, 255, 255)
    assert icon.getpixel((512, 512))[0] > 200


def test_windows_launcher_does_not_open_a_browser_in_embedded_mode():
    source = read(WINDOWS / "Start-Marcellus.ps1")
    assert '$env:ENKSTEIN_EMBEDDED -ne "1"' in source
    assert "Start-Process $uiUrl" in source


def test_windows_runtime_dependency_is_explicitly_documented():
    launcher = read(WINDOWS / "Start-Marcellus.ps1")
    docs = read(ROOT / "docs" / "native-installers.md") + read(ROOT / "docs" / "installation.md")
    assert "Docker Desktop is required" in launcher or "Docker Desktop was found" in launcher
    assert "not a standalone" in docs.lower()
    assert "Docker Desktop" in docs


def test_liquid_glass_is_explicit_and_has_three_levels():
    provider = read(ROOT / "frontend" / "src" / "components" / "ThemeProvider.tsx")
    css = read(ROOT / "frontend" / "src" / "app" / "globals.css")
    host = read(WINDOWS / "MarcellusLauncher.cs")
    for level in ("subtle", "balanced", "clear"):
        assert level in provider
        assert level in css or level == "balanced"
        assert level in host
    assert "TransparencyEffectsEnabled" in host
    assert "prefers-reduced-transparency" in css
    assert "data-glass" in host
