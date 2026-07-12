param(
    [Parameter(Mandatory = $false)]
    [string]$Version = "0.7.0"
)

$ErrorActionPreference = "Stop"
$Version = $Version.TrimStart("v")
$Root = Split-Path -Parent $PSScriptRoot
$Dist = Join-Path $Root "dist"
$Work = Join-Path $Dist "windows-$Version"
$Stage = Join-Path $Work "stage"
$Runtime = Join-Path $Stage "runtime"

Remove-Item -Recurse -Force $Work -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $Runtime | Out-Null

function Copy-Tree([string]$Source, [string]$Destination, [string[]]$ExtraExcludedDirectories = @()) {
    $excludedDirectories = @(
        ".venv", ".pytest_cache", ".ruff_cache", ".secrets", ".state",
        "__pycache__", "node_modules", ".next", "e2e", "test-results", "playwright-report", "tests"
    ) + $ExtraExcludedDirectories
    $arguments = @($Source, $Destination, "/E", "/NFL", "/NDL", "/NJH", "/NJS", "/NP", "/XD") + $excludedDirectories + @("/XF", "*.db", "*.pyc", ".DS_Store", "requirements-test.txt")
    & robocopy @arguments | Out-Null
    if ($LASTEXITCODE -gt 7) {
        throw "robocopy failed for $Source with exit code $LASTEXITCODE"
    }
}

Copy-Tree (Join-Path $Root "backend") (Join-Path $Runtime "backend")
Copy-Tree (Join-Path $Root "frontend") (Join-Path $Runtime "frontend")
Copy-Item (Join-Path $Root "packaging\compose.release.yaml") (Join-Path $Runtime "compose.yaml")
Copy-Item (Join-Path $Root ".env.example") (Join-Path $Runtime ".env.example")
Copy-Item (Join-Path $Root "README.md") (Join-Path $Runtime "README.md")
Copy-Item (Join-Path $Root "LICENSE") (Join-Path $Runtime "LICENSE")
Copy-Item (Join-Path $Root "packaging\windows\Start-RegentClaw.ps1") (Join-Path $Runtime "Start-RegentClaw.ps1")
New-Item -ItemType Directory -Force -Path (Join-Path $Runtime "docs") | Out-Null
Copy-Item (Join-Path $Root "docs\installation.md") (Join-Path $Runtime "docs\installation.md")
Copy-Item (Join-Path $Root "docs\native-installers.md") (Join-Path $Runtime "docs\native-installers.md")
Copy-Item (Join-Path $Root "docs\production-deployment.md") (Join-Path $Runtime "docs\production-deployment.md")
Set-Content -NoNewline -Path (Join-Path $Runtime "VERSION") -Value "v$Version"

$Compiler = Join-Path $env:WINDIR "Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if (-not (Test-Path $Compiler)) {
    throw "The .NET Framework C# compiler was not found: $Compiler"
}
if (-not (Get-Command magick -ErrorAction SilentlyContinue)) {
    throw "ImageMagick is required to generate the Windows application icon."
}
$Icon = Join-Path $Stage "RegentClaw.ico"
& magick (Join-Path $Root "frontend\public\logo.png") -define icon:auto-resize=256,128,64,48,32,16 $Icon
if ($LASTEXITCODE -ne 0 -or -not (Test-Path $Icon)) { throw "Windows icon generation failed." }

& $Compiler /nologo /target:winexe /platform:anycpu /reference:System.Windows.Forms.dll /win32icon:"$Icon" /out:"$Stage\RegentClaw.exe" "$Root\packaging\windows\RegentClawLauncher.cs"
if ($LASTEXITCODE -ne 0) { throw "RegentClaw launcher compilation failed." }

$InnoCompiler = "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe"
if (-not (Test-Path $InnoCompiler)) {
    throw "Inno Setup 6 is required: $InnoCompiler"
}

New-Item -ItemType Directory -Force -Path $Dist | Out-Null
& $InnoCompiler "/DVersion=$Version" "/DStageDir=$Stage" "/DOutputDir=$Dist" "$Root\packaging\windows\RegentClaw.iss"
if ($LASTEXITCODE -ne 0) { throw "Inno Setup compilation failed." }

$Output = Join-Path $Dist "RegentClaw-$Version-windows-x64-setup.exe"
if (-not (Test-Path $Output)) { throw "Expected installer was not created: $Output" }
Write-Host "Built: $Output"
