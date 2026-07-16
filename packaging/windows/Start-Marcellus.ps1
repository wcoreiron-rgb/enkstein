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
        Set-EnvValue "DEBUG" "false"
    }

    Start-BrainBridge

    "[$([DateTime]::UtcNow.ToString('o'))] Starting Enkstein" | Out-File -Append -FilePath $LogFile
    & docker compose --env-file $EnvFile -f $ComposeFile config --quiet *>> $LogFile
    if ($LASTEXITCODE -ne 0) { throw "Docker Compose validation failed. See $LogFile." }
    & docker compose --env-file $EnvFile -f $ComposeFile up -d --build *>> $LogFile
    if ($LASTEXITCODE -ne 0) { throw "Container startup failed. See $LogFile." }

    Start-Process "http://localhost:3000"
}
catch {
    $_ | Out-File -Append -FilePath $LogFile
    Show-Error "$($_.Exception.Message) See $LogFile for details."
    exit 1
}
