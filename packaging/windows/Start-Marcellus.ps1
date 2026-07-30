$ErrorActionPreference = "Stop"

$RuntimeDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$EnvFile = Join-Path $RuntimeDir ".env"
$ComposeFile = Join-Path $RuntimeDir "compose.yaml"
$LogDir = Join-Path $env:LOCALAPPDATA "Marcellus\logs"
$LogFile = Join-Path $LogDir "launcher.log"
$BridgeScript = Join-Path $RuntimeDir "BrainBridge.ps1"
$BridgeSecretFile = Join-Path $env:LOCALAPPDATA "Marcellus\brain-bridge.secret"
$BridgePidFile = Join-Path $env:LOCALAPPDATA "Marcellus\brain-bridge.pid"
$BridgePort = 47831
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

function Show-Error([string]$Message) {
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

function Test-DockerEngine {
    & docker info *> $null
    return ($LASTEXITCODE -eq 0)
}

function Wait-ForDockerEngine {
    $dockerDesktopCandidates = @(
        (Join-Path $env:ProgramFiles "Docker\Docker\Docker Desktop.exe"),
        (Join-Path $env:LOCALAPPDATA "Programs\Docker\Docker\Docker Desktop.exe")
    )

    if (Test-DockerEngine) { return $true }

    foreach ($candidate in $dockerDesktopCandidates) {
        if (Test-Path $candidate) {
            Start-Process $candidate
            break
        }
    }

    # Docker Desktop can report a running process before its Linux engine has
    # created the named pipe. Compose must not run during that interval.
    for ($attempt = 0; $attempt -lt 90; $attempt++) {
        Start-Sleep -Seconds 2
        if (Test-DockerEngine) { return $true }
    }
    return $false
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

    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        Show-Error "Docker Desktop is required. Install it, then start Enkstein again."
        Start-Process "https://www.docker.com/products/docker-desktop/"
        exit 1
    }

    if (-not (Wait-ForDockerEngine)) {
        throw "Docker Desktop was found, but its Linux engine did not become ready within three minutes. Start Docker Desktop, wait for 'Engine running', then launch Enkstein again."
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
    if (-not (Wait-ForDockerEngine)) {
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
        if (-not (Wait-ForDockerEngine)) {
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

    Start-Process "http://localhost:$frontendPort"
}
catch {
    $_ | Out-File -Append -FilePath $LogFile
    Show-Error "$($_.Exception.Message) See $LogFile for details."
    # Open the log directly. Telling someone a path they must go find is a poor
    # place to leave them when startup has already failed.
    if (Test-Path $LogFile) { Start-Process notepad.exe $LogFile }
    exit 1
}
