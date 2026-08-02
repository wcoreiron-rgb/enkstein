"""Mocked cross-platform Docker prerequisite state tests."""

import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_macos_launcher_resolves_prerequisite_from_resources():
    launcher = (ROOT / "packaging/macos/launcher.sh").read_text(encoding="utf-8")
    assert 'DOCKER_HELPER="$APP_ROOT/Resources/docker-prerequisite.sh"' in launcher


def _fake_docker(tmp_path: Path, healthy: bool) -> Path:
    command = tmp_path / "docker"
    command.write_text("#!/bin/sh\n" + ("exit 0\n" if healthy else "exit 1\n"), encoding="utf-8")
    command.chmod(0o755)
    return command


def _mac_state(tmp_path: Path, docker: Path, app: Path) -> tuple[int, str]:
    helper = ROOT / "packaging/macos/docker-prerequisite.sh"
    opener = tmp_path / "open"
    opener.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    opener.chmod(0o755)
    env = {
        **os.environ,
        "ENKSTEIN_DOCKER_COMMAND": str(docker),
        "ENKSTEIN_DOCKER_APP": str(app),
        "ENKSTEIN_DOCKER_OPEN": str(opener),
        "ENKSTEIN_DOCKER_ATTEMPTS": "1",
        "ENKSTEIN_DOCKER_INTERVAL": "0",
    }
    result = subprocess.run(
        ["bash", "-c", f'source "{helper}"; ensure_docker'],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    return result.returncode, result.stdout


def test_macos_docker_states_are_distinguishable(tmp_path: Path):
    healthy_code, healthy_output = _mac_state(tmp_path, _fake_docker(tmp_path, True), tmp_path / "missing.app")
    assert healthy_code == 0 and "ENKSTEIN_DOCKER_STATE=healthy" in healthy_output

    stopped_app = tmp_path / "Docker.app"
    stopped_app.mkdir()
    stopped_code, stopped_output = _mac_state(tmp_path, _fake_docker(tmp_path, False), stopped_app)
    assert stopped_code == 3 and "ENKSTEIN_DOCKER_STATE=timeout" in stopped_output

    missing_code, missing_output = _mac_state(tmp_path, tmp_path / "missing-docker", tmp_path / "missing.app")
    # Missing Docker exits 2 and stays on the missing state so the install
    # action remains available, rather than reporting a generic timeout.
    assert missing_code == 2 and "ENKSTEIN_DOCKER_STATE=missing" in missing_output


def test_windows_helper_reports_healthy_stopped_and_missing(tmp_path: Path):
    helper = ROOT / "packaging/windows/DockerPrerequisite.ps1"
    healthy = _fake_docker(tmp_path, True)
    stopped_dir = tmp_path / "stopped"
    stopped_dir.mkdir()
    stopped = _fake_docker(stopped_dir, False)
    desktop = tmp_path / "Docker Desktop.exe"
    desktop.write_text("fixture", encoding="utf-8")
    script = f'''
    . "{helper}"
    $healthy = Get-DockerState -DockerCommand "{healthy}" -DockerDesktopCandidates @()
    $stopped = Get-DockerState -DockerCommand "{stopped}" -DockerDesktopCandidates @("{desktop}")
    $missing = Get-DockerState -DockerCommand "{tmp_path / "missing-docker"}" -DockerDesktopCandidates @()
    "$healthy|$stopped|$missing"
    '''
    result = subprocess.run(["pwsh", "-NoProfile", "-Command", script], text=True, capture_output=True, check=False)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip().startswith("healthy|")
    assert result.stdout.strip().endswith("|missing")
    assert result.stdout.strip().split("|")[1] in {"stopped", "unhealthy"}


def test_windows_polling_returns_boolean_without_progress_pipeline_leaks(tmp_path: Path):
    helper = ROOT / "packaging/windows/DockerPrerequisite.ps1"
    healthy = _fake_docker(tmp_path, True)
    script = f'''
    . "{helper}"
    $result = Wait-ForDockerEngine -DockerCommand "{healthy}" -TimeoutSeconds 1 -PollSeconds 1 -Progress {{ param($state, $detail); "progress:$state" }}
    "$($result.GetType().FullName)|$result"
    '''
    result = subprocess.run(["pwsh", "-NoProfile", "-Command", script], text=True, capture_output=True, check=False)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip().endswith("System.Boolean|True")


def test_compose_is_after_docker_gate_on_both_launchers():
    mac = (ROOT / "packaging/macos/launcher.sh").read_text(encoding="utf-8")
    windows = (ROOT / "packaging/windows/Start-Marcellus.ps1").read_text(encoding="utf-8")
    assert mac.index("ensure_docker") < mac.index("./install.sh")
    assert windows.index("Ensure-DockerDesktop") < windows.index("docker compose")
    assert "FileShare]::None" in windows
    assert "startup.lock" in windows


def test_macos_missing_state_is_reachable_without_uninstalling_docker(tmp_path: Path):
    """Pointing the overrides at nonexistent paths must reach the terminal
    missing state and stop, rather than polling behind a spinner."""
    helper = ROOT / "packaging/macos/docker-prerequisite.sh"
    opener = tmp_path / "open"
    opener.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    opener.chmod(0o755)
    environment = {
        **os.environ,
        "ENKSTEIN_DOCKER_COMMAND": str(tmp_path / "no-such-docker"),
        "ENKSTEIN_DOCKER_APP": str(tmp_path / "no-such-Docker.app"),
        "ENKSTEIN_DOCKER_OPEN": str(opener),
        # Terminal missing state: do not poll for an install that is not coming.
        "ENKSTEIN_DOCKER_INSTALL_ATTEMPTS": "0",
        "ENKSTEIN_DOCKER_INTERVAL": "0",
    }
    result = subprocess.run(
        ["bash", "-c", f'source "{helper}"; ensure_docker'],
        env=environment,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 2
    assert "ENKSTEIN_DOCKER_STATE=missing" in result.stdout
    # A spinner-only "installing" state would hide the install action.
    assert "ENKSTEIN_DOCKER_STATE=installing" not in result.stdout


def test_failed_install_wait_returns_to_missing_not_generic_timeout(tmp_path: Path):
    """The install action has to stay on screen while Docker is still absent."""
    helper = ROOT / "packaging/macos/docker-prerequisite.sh"
    opener = tmp_path / "open"
    opener.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    opener.chmod(0o755)
    environment = {
        **os.environ,
        "ENKSTEIN_DOCKER_COMMAND": str(tmp_path / "no-such-docker"),
        "ENKSTEIN_DOCKER_APP": str(tmp_path / "no-such-Docker.app"),
        "ENKSTEIN_DOCKER_OPEN": str(opener),
        "ENKSTEIN_DOCKER_INSTALL_ATTEMPTS": "1",
        "ENKSTEIN_DOCKER_INTERVAL": "0",
    }
    result = subprocess.run(
        ["bash", "-c", f'source "{helper}"; ensure_docker'],
        env=environment,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 2
    assert result.stdout.strip().splitlines()[-1].startswith("ENKSTEIN_DOCKER_STATE=missing")


def test_macos_launcher_exits_before_compose_when_docker_is_unavailable():
    """`ensure_docker` failing must exit, never fall through to install.sh."""
    launcher = (ROOT / "packaging/macos/launcher.sh").read_text(encoding="utf-8")
    gate = launcher.index("ensure_docker ||")
    exit_call = launcher.index("exit 1", gate)
    assert exit_call < launcher.index("./install.sh")


def test_windows_helper_honors_environment_overrides():
    helper = (ROOT / "packaging/windows/DockerPrerequisite.ps1").read_text(encoding="utf-8")
    assert "$env:ENKSTEIN_DOCKER_COMMAND" in helper
    assert "$env:ENKSTEIN_DOCKER_APP" in helper


def test_windows_missing_state_can_skip_the_install_poll():
    launcher = (ROOT / "packaging/windows/Start-Marcellus.ps1").read_text(encoding="utf-8")
    assert "ENKSTEIN_DOCKER_INSTALL_TIMEOUT" in launcher
    assert "if ($installTimeout -gt 0)" in launcher


def test_prerequisite_helpers_never_remove_docker():
    """The test path must not be implemented by deleting Docker or its data."""
    for path in (
        ROOT / "packaging/macos/docker-prerequisite.sh",
        ROOT / "packaging/windows/DockerPrerequisite.ps1",
        ROOT / "packaging/macos/launcher.sh",
        ROOT / "packaging/windows/Start-Marcellus.ps1",
    ):
        # Comments legitimately mention the word "uninstall" when explaining
        # that the test path avoids it, so only executable-looking destructive
        # commands are checked.
        source = path.read_text(encoding="utf-8")
        for destructive in (
            "docker system prune",
            "docker volume rm",
            "docker volume prune",
            "docker rmi",
            "rm -rf /Applications/Docker.app",
        ):
            assert destructive not in source, f"{path.name} must not run '{destructive}'"
