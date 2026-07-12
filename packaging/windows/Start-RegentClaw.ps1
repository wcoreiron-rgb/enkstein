$ErrorActionPreference = "Stop"

$RuntimeDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$EnvFile = Join-Path $RuntimeDir ".env"
$ComposeFile = Join-Path $RuntimeDir "compose.yaml"
$LogDir = Join-Path $env:LOCALAPPDATA "RegentClaw\logs"
$LogFile = Join-Path $LogDir "launcher.log"
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

function Show-Error([string]$Message) {
    Add-Type -AssemblyName PresentationFramework
    [System.Windows.MessageBox]::Show(
        "RegentClaw could not start. $Message",
        "RegentClaw",
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
    $content = [regex]::Replace($content, $pattern, "$Key=$Value")
    [System.IO.File]::WriteAllText($EnvFile, $content, [System.Text.UTF8Encoding]::new($false))
}

try {
    $dockerDesktop = Join-Path $env:ProgramFiles "Docker\Docker\Docker Desktop.exe"
    $dockerCli = Join-Path $env:ProgramFiles "Docker\Docker\resources\bin"
    if (Test-Path $dockerCli) {
        $env:PATH = "$dockerCli;$env:PATH"
    }

    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        Show-Error "Docker Desktop is required. Install it, then start RegentClaw again."
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

    "[$([DateTime]::UtcNow.ToString('o'))] Starting RegentClaw" | Out-File -Append -FilePath $LogFile
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
