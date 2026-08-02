# Docker Desktop prerequisite state machine for the Enkstein Windows launcher.
# Functions are kept separate from Compose startup so they can be mocked in CI
# and so no service process can be started before `docker info` succeeds.

function Test-DockerEngine {
    param([string]$DockerCommand = "docker")
    & $DockerCommand info *> $null
    return ($LASTEXITCODE -eq 0)
}

function Get-DockerState {
    param(
        [string]$DockerCommand = "docker",
        [string[]]$DockerDesktopCandidates = @()
    )
    # The environment overrides exist so the missing-Docker screen can be
    # reached safely during development by pointing at paths that do not
    # exist. Nothing here uninstalls Docker or touches Docker data.
    if ($env:ENKSTEIN_DOCKER_COMMAND) { $DockerCommand = $env:ENKSTEIN_DOCKER_COMMAND }
    if ($env:ENKSTEIN_DOCKER_APP) { $DockerDesktopCandidates = @($env:ENKSTEIN_DOCKER_APP) }
    if (Test-DockerEngine -DockerCommand $DockerCommand) { return "healthy" }
    $installed = ($DockerDesktopCandidates | Where-Object { Test-Path $_ }).Count -gt 0
    if (-not ($installed -or (Get-Command $DockerCommand -ErrorAction SilentlyContinue))) { return "missing" }
    if (Get-Process -Name "Docker Desktop" -ErrorAction SilentlyContinue) { return "unhealthy" }
    return "stopped"
}

function Start-DockerDesktop {
    param([string[]]$Candidates)
    foreach ($candidate in $Candidates) {
        if (Test-Path $candidate) {
            Start-Process -FilePath $candidate | Out-Null
            return $true
        }
    }
    return $false
}

function Wait-ForDockerEngine {
    param(
        [string]$DockerCommand = "docker",
        [int]$TimeoutSeconds = 180,
        [int]$PollSeconds = 2,
        [scriptblock]$Progress = {}
    )
    $attempts = [Math]::Max(1, [Math]::Ceiling($TimeoutSeconds / [double]$PollSeconds))
    for ($attempt = 1; $attempt -le $attempts; $attempt++) {
        & $Progress "starting" "Waiting for Docker Desktop engine ($attempt/$attempts)..." | Out-Null
        if (Test-DockerEngine -DockerCommand $DockerCommand) { return $true }
        Start-Sleep -Seconds $PollSeconds
    }
    return $false
}

function Ensure-DockerDesktop {
    param(
        [string]$DockerCommand = "docker",
        [string[]]$DockerDesktopCandidates = @(),
        [int]$TimeoutSeconds = 180,
        [int]$PollSeconds = 2,
        [scriptblock]$Progress = {},
        [scriptblock]$OpenInstall = {}
    )
    if ($env:ENKSTEIN_DOCKER_COMMAND) { $DockerCommand = $env:ENKSTEIN_DOCKER_COMMAND }
    if ($env:ENKSTEIN_DOCKER_APP) { $DockerDesktopCandidates = @($env:ENKSTEIN_DOCKER_APP) }
    $state = Get-DockerState -DockerCommand $DockerCommand -DockerDesktopCandidates $DockerDesktopCandidates
    & $Progress $state $(switch ($state) {
        "healthy" { "Docker Desktop engine is running."; break }
        "stopped" { "Docker Desktop is installed but its engine is stopped."; break }
        "unhealthy" { "Docker Desktop is running but its engine is unhealthy."; break }
        default { "Docker Desktop is required before Enkstein can start." }
    }) | Out-Null
    if ($state -eq "healthy") { return $true }
    if ($state -eq "missing") {
        & $OpenInstall | Out-Null
        return $false
    }
    Start-DockerDesktop -Candidates $DockerDesktopCandidates | Out-Null
    if (Wait-ForDockerEngine -DockerCommand $DockerCommand -TimeoutSeconds $TimeoutSeconds -PollSeconds $PollSeconds -Progress $Progress) {
        & $Progress "healthy" "Docker Desktop engine is running." | Out-Null
        return $true
    }
    & $Progress "timeout" "Docker Desktop did not become healthy before the startup timeout." | Out-Null
    return $false
}
