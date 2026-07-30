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

try {
    $dockerDesktop = Join-Path $env:ProgramFiles "Docker\Docker\Docker Desktop.exe"
    $dockerCli = Join-Path $env:ProgramFiles "Docker\Docker\resources\bin"
    if (Test-Path $dockerCli) {
        $env:PATH = "$dockerCli;$env:PATH"
    }

    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        Show-Error "Docker Desktop is required. Install it, then start Enkstein again."
        Start-Process "https://www.docker.com/products/docker-desktop/"
        exit 1
    }

    & docker info *> $null
    if ($LASTEXITCODE -ne 0) {
        if (Test-Path $dockerDesktop) {
            Start-Process $dockerDesktop
        }
        $ready = $false
        for ($attempt = 0; $attempt -lt 60; $attempt++) {
            Start-Sleep -Seconds 2
            & docker info *> $null
            if ($LASTEXITCODE -eq 0) {
                $ready = $true
                break
            }
        }
        if (-not $ready) {
            throw "Docker Desktop did not become ready within two minutes."
        }
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

    if ($usedPublishedImages) {
        & docker compose --env-file $EnvFile -f $ComposeFile up -d --no-build *>> $LogFile
    }
    else {
        "Published images unavailable; building locally." | Out-File -Append -FilePath $LogFile
        & docker compose --env-file $EnvFile -f $ComposeFile up -d --build *>> $LogFile
    }
    if ($LASTEXITCODE -ne 0) { throw "Container startup failed. See $LogFile." }

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
