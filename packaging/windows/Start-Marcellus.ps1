$ErrorActionPreference = "Stop"

$RuntimeDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$EnvFile = Join-Path $RuntimeDir ".env"
$ComposeFile = Join-Path $RuntimeDir "compose.yaml"
$LogDir = Join-Path $env:LOCALAPPDATA "Enkstein\logs"
$LogFile = Join-Path $LogDir "launcher.log"
$BridgeScript = Join-Path $RuntimeDir "BrainBridge.ps1"
$BridgeSecretFile = Join-Path $env:LOCALAPPDATA "Enkstein\brain-bridge.secret"
$BridgePidFile = Join-Path $env:LOCALAPPDATA "Enkstein\brain-bridge.pid"
$BridgePort = 47831
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
$DockerHelper = Join-Path $RuntimeDir "DockerPrerequisite.ps1"
# Docker Desktop is required before Enkstein services can start. Keep one
# exclusive handle for the lifetime of this launcher so retries or shortcuts
# cannot create duplicate Docker/Compose startup processes.
$StartupLockPath = Join-Path $env:LOCALAPPDATA "Enkstein\startup.lock"
$StartupLock = $null
try {
    $StartupLock = [System.IO.File]::Open(
        $StartupLockPath,
        [System.IO.FileMode]::OpenOrCreate,
        [System.IO.FileAccess]::ReadWrite,
        [System.IO.FileShare]::None
    )
}
catch {
    "[$([DateTime]::UtcNow.ToString('o'))] Enkstein startup already in progress." | Out-File -Append -FilePath $LogFile
    exit 0
}

if (-not (Test-Path $DockerHelper)) {
    throw "Docker prerequisite helper is missing. Reinstall Enkstein."
}
. $DockerHelper

function Write-DockerState([string]$State, [string]$Detail) {
    "ENKSTEIN_DOCKER_STATE=$State|$Detail" | Tee-Object -FilePath $LogFile -Append
}

function Show-Error([string]$Message) {
    if ($env:ENKSTEIN_EMBEDDED -eq "1") {
        Write-Error $Message
        return
    }
    Add-Type -AssemblyName PresentationFramework
    [System.Windows.MessageBox]::Show(
        "Enkstein could not start. $Message",
        "Enkstein",
        "OK",
        "Error"
    ) | Out-Null
}

function New-HexSecret([int]$ByteCount) {
    $bytes = New-Object byte[] $ByteCount
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    return -join ($bytes | ForEach-Object { $_.ToString("x2") })
}

function Get-FreePort([int]$Preferred) {
    # Keep the familiar port when it is genuinely free so bookmarks and the
    # documented URLs keep working; only move when something already holds it.
    foreach ($candidate in @($Preferred) + (($Preferred + 1)..($Preferred + 20))) {
        $listener = $null
        try {
            $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $candidate)
            $listener.Start()
            return $candidate
        }
        catch { continue }
        finally { if ($listener) { $listener.Stop() } }
    }
    return $Preferred
}

$RuntimeVersion = "0.0.0"
$versionFile = Join-Path $RuntimeDir "VERSION"
if (Test-Path $versionFile) {
    $RuntimeVersion = (Get-Content -Raw -Path $versionFile).Trim().TrimStart("v")
}

function Set-EnvValue([string]$Key, [string]$Value) {
    $content = Get-Content -Raw -Path $EnvFile
    $pattern = "(?m)^" + [regex]::Escape($Key) + "=.*$"
    if ([regex]::IsMatch($content, $pattern)) {
        $content = [regex]::Replace($content, $pattern, "$Key=$Value")
    }
    else {
        $content = $content.TrimEnd() + [Environment]::NewLine + "$Key=$Value" + [Environment]::NewLine
    }
    [System.IO.File]::WriteAllText($EnvFile, $content, [System.Text.UTF8Encoding]::new($false))
}

function Start-BrainBridge {
    if (-not (Test-Path $BridgeScript)) { return }
    if (-not (Test-Path $BridgeSecretFile)) {
        [System.IO.File]::WriteAllText($BridgeSecretFile, (New-HexSecret 32), [System.Text.UTF8Encoding]::new($false))
    }
    $bridgeSecret = (Get-Content -Raw -Path $BridgeSecretFile).Trim()
    Set-EnvValue "BRAIN_BRIDGE_URL" "http://host.docker.internal:$BridgePort"
    Set-EnvValue "BRAIN_BRIDGE_SECRET" $bridgeSecret
    Set-EnvValue "BRAIN_BRIDGE_TIMEOUT_SECONDS" "180"

    if (Test-Path $BridgePidFile) {
        $oldPid = [int](Get-Content -Raw -Path $BridgePidFile)
        Stop-Process -Id $oldPid -Force -ErrorAction SilentlyContinue
    }
    $process = Start-Process powershell.exe -WindowStyle Hidden -PassThru -ArgumentList @(
        "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", ('"' + $BridgeScript + '"'),
        "-Port", "$BridgePort", "-SecretFile", ('"' + $BridgeSecretFile + '"')
    )
    [System.IO.File]::WriteAllText($BridgePidFile, [string]$process.Id)
}

try {
    $dockerCli = Join-Path $env:ProgramFiles "Docker\Docker\resources\bin"
    $dockerCliUser = Join-Path $env:LOCALAPPDATA "Programs\Docker\Docker\resources\bin"
    if (Test-Path $dockerCli) {
        $env:PATH = "$dockerCli;$env:PATH"
    }
    elseif (Test-Path $dockerCliUser) {
        $env:PATH = "$dockerCliUser;$env:PATH"
    }

    $dockerDesktopCandidates = @(
        (Join-Path $env:ProgramFiles "Docker\Docker\Docker Desktop.exe"),
        (Join-Path $env:LOCALAPPDATA "Programs\Docker\Docker\Docker Desktop.exe")
    )
    $dockerProgress = {
        param($state, $detail)
        Write-DockerState $state $detail
    }
    $dockerInstall = {
        Write-DockerState "missing" "Docker Desktop is missing. Opening the official Docker installation page."
        Start-Process "https://www.docker.com/products/docker-desktop/"
    }
    $dockerHealthy = Ensure-DockerDesktop -DockerCommand "docker" `
        -DockerDesktopCandidates $dockerDesktopCandidates -TimeoutSeconds 180 -PollSeconds 2 `
        -Progress $dockerProgress -OpenInstall $dockerInstall
    if (-not $dockerHealthy) {
        # The user may install Docker from the official flow while this process
        # remains open. Keep checking so Retry is not required after install.
        # ENKSTEIN_DOCKER_INSTALL_TIMEOUT=0 keeps the screen on the terminal
        # missing state instead of polling, which is how the missing-Docker
        # screen is reached for testing without removing Docker.
        $installTimeout = if ($env:ENKSTEIN_DOCKER_INSTALL_TIMEOUT) { [int]$env:ENKSTEIN_DOCKER_INSTALL_TIMEOUT } else { 600 }
        if ($installTimeout -gt 0) {
            Write-DockerState "installing" "Install Docker Desktop from the official installer, then Enkstein will recheck automatically."
            $dockerHealthy = Wait-ForDockerEngine -DockerCommand "docker" -TimeoutSeconds $installTimeout -PollSeconds 2 -Progress $dockerProgress
        }
    }
    if (-not $dockerHealthy) {
        Write-DockerState "missing" "Docker Desktop is required before Enkstein can start."
        throw "Docker Desktop is unavailable after the startup timeout. Open Docker Desktop, then choose Retry."
    }

    if (-not (Test-Path $EnvFile)) {
        Copy-Item (Join-Path $RuntimeDir ".env.example") $EnvFile
        Set-EnvValue "SECRET_KEY" (New-HexSecret 32)
        Set-EnvValue "POSTGRES_PASSWORD" (New-HexSecret 24)
        Set-EnvValue "REDIS_PASSWORD" (New-HexSecret 24)
        # Compose requires ADMIN_PASSWORD. Leaving the placeholder from
        # .env.example would ship every Windows install with the same known
        # owner password.
        Set-EnvValue "ADMIN_PASSWORD" (New-HexSecret 24)
        Set-EnvValue "DEBUG" "false"
    }
    # Existing installs predate the generated owner password.
    if ((Get-Content -Raw -Path $EnvFile) -match "(?m)^ADMIN_PASSWORD=CHANGE_ME\s*$") {
        Set-EnvValue "ADMIN_PASSWORD" (New-HexSecret 24)
    }
    Set-EnvValue "APP_VERSION" $RuntimeVersion

    # Ports are chosen at launch. Binding 3000 or 8000 unconditionally fails
    # outright when anything else on the machine already holds them, which
    # presents as "Container startup failed" with no indication of the cause.
    $frontendPort = Get-FreePort 3000
    $backendPort = Get-FreePort 8000
    Set-EnvValue "FRONTEND_PORT" "$frontendPort"
    Set-EnvValue "BACKEND_PORT" "$backendPort"

    Start-BrainBridge

    "[$([DateTime]::UtcNow.ToString('o'))] Starting Enkstein" | Out-File -Append -FilePath $LogFile
    if (-not (Test-DockerEngine -DockerCommand "docker")) {
        throw "Docker Desktop stopped before Compose could start. Start Docker Desktop and launch Enkstein again."
    }
    & docker compose --env-file $EnvFile -f $ComposeFile config --quiet *>> $LogFile
    if ($LASTEXITCODE -ne 0) { throw "Docker Compose validation failed. See $LogFile." }

    # Prefer published images so first launch is a download rather than a local
    # compile of Prowler's dependency tree. Windows previously always built,
    # which made it both slow and dependent on a working local toolchain.
    $usedPublishedImages = $false
    if ($env:ENKSTEIN_FORCE_BUILD -ne "true") {
        "Pulling published images..." | Out-File -Append -FilePath $LogFile
        $pull = Start-Process -FilePath "docker" -NoNewWindow -PassThru -Wait `
            -ArgumentList @("compose", "--env-file", $EnvFile, "-f", $ComposeFile, "pull", "--quiet", "backend", "frontend") `
            -RedirectStandardOutput "$LogFile.pull" -RedirectStandardError "$LogFile.pullerr"
        $usedPublishedImages = ($pull.ExitCode -eq 0)
    }

    $composeExit = 1
    for ($attempt = 0; $attempt -lt 3; $attempt++) {
        if (-not (Test-DockerEngine -DockerCommand "docker")) {
            throw "Docker Desktop stopped while Enkstein was starting. Start Docker Desktop and launch Enkstein again."
        }
        if ($usedPublishedImages) {
            & docker compose --env-file $EnvFile -f $ComposeFile up -d --no-build *>> $LogFile
        }
        else {
            "Published images unavailable; building locally." | Out-File -Append -FilePath $LogFile
            & docker compose --env-file $EnvFile -f $ComposeFile up -d --build *>> $LogFile
        }
        $composeExit = $LASTEXITCODE
        if ($composeExit -eq 0) { break }
        "Compose attempt $($attempt + 1) failed with exit code $composeExit; waiting for Docker and retrying." | Out-File -Append -FilePath $LogFile
        Start-Sleep -Seconds 3
    }
    if ($composeExit -ne 0) { throw "Container startup failed after three Docker readiness retries. See $LogFile." }

    # The frontend port is chosen at launch, so the console URL is published to
    # a file for the native host to read. This mirrors the macOS package.
    $uiUrl = "http://localhost:$frontendPort"
    $stateDir = Join-Path $env:LOCALAPPDATA "Enkstein"
    New-Item -ItemType Directory -Force -Path $stateDir | Out-Null
    Set-Content -NoNewline -Path (Join-Path $stateDir "ui-url") -Value $uiUrl

    # When the native WebView2 host started this script it renders the console
    # itself, so opening a browser as well would surface two copies of the app.
    if ($env:ENKSTEIN_EMBEDDED -ne "1") {
        Start-Process $uiUrl
    }
}
catch {
    $_ | Out-File -Append -FilePath $LogFile
    Show-Error "$($_.Exception.Message) See $LogFile for details."
    # Open the log directly. Telling someone a path they must go find is a poor
    # place to leave them when startup has already failed.
    if (Test-Path $LogFile) { Start-Process notepad.exe $LogFile }
    exit 1
}
