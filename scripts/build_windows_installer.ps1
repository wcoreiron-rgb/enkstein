param(
    [Parameter(Mandatory = $false)]
    [string]$Version = "0.6.8"
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
Copy-Item (Join-Path $Root "packaging\windows\Start-Marcellus.ps1") (Join-Path $Runtime "Start-Enkstein.ps1")
Copy-Item (Join-Path $Root "packaging\windows\DockerPrerequisite.ps1") (Join-Path $Runtime "DockerPrerequisite.ps1")
Copy-Item (Join-Path $Root "packaging\windows\BrainBridge.ps1") (Join-Path $Runtime "BrainBridge.ps1")
New-Item -ItemType Directory -Force -Path (Join-Path $Runtime "docs") | Out-Null
Copy-Item (Join-Path $Root "docs\installation.md") (Join-Path $Runtime "docs\installation.md")
Copy-Item (Join-Path $Root "docs\native-installers.md") (Join-Path $Runtime "docs\native-installers.md")
Copy-Item (Join-Path $Root "docs\brain-bridges.md") (Join-Path $Runtime "docs\brain-bridges.md")
Copy-Item (Join-Path $Root "docs\production-deployment.md") (Join-Path $Runtime "docs\production-deployment.md")
# The browser companion ships with the runtime so the console can serve it as a
# download, matching the macOS package. Without it, Windows testers have no way
# to load the extension.
Copy-Tree (Join-Path $Root "browser-extension") (Join-Path $Runtime "browser-extension")
Set-Content -NoNewline -Path (Join-Path $Runtime "VERSION") -Value "v$Version"

$Compiler = Join-Path $env:WINDIR "Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if (-not (Test-Path $Compiler)) {
    throw "The .NET Framework C# compiler was not found: $Compiler"
}

# The host embeds WebView2 rather than launching a browser, so the SDK
# assemblies and the native loader must be present before compiling. NuGet is
# the published distribution channel for them.
$Packages = Join-Path $Work "packages"
New-Item -ItemType Directory -Force -Path $Packages | Out-Null
$WebView2Version = "1.0.2903.40"
$WebView2Package = Join-Path $Packages "webview2.zip"
$WebView2Dir = Join-Path $Packages "webview2"
if (-not (Test-Path $WebView2Dir)) {
    Invoke-WebRequest -UseBasicParsing `
        -Uri "https://www.nuget.org/api/v2/package/Microsoft.Web.WebView2/$WebView2Version" `
        -OutFile $WebView2Package
    Expand-Archive -Path $WebView2Package -DestinationPath $WebView2Dir -Force
}
$WebView2Core = Join-Path $WebView2Dir "lib\net462\Microsoft.Web.WebView2.Core.dll"
$WebView2Forms = Join-Path $WebView2Dir "lib\net462\Microsoft.Web.WebView2.WinForms.dll"
$WebView2Loader = Join-Path $WebView2Dir "build\native\x64\WebView2Loader.dll"
foreach ($assembly in @($WebView2Core, $WebView2Forms, $WebView2Loader)) {
    if (-not (Test-Path $assembly)) { throw "WebView2 component missing from the NuGet package: $assembly" }
}
# Shipped beside the executable: the managed assemblies are resolved at load
# time and the native loader is required for the control to initialize.
Copy-Item $WebView2Core  $Stage
Copy-Item $WebView2Forms $Stage
Copy-Item $WebView2Loader $Stage

# The canonical app artwork is a red/orange octopus on a white rounded-square
# tile with transparent pixels outside the rounded corners. It is shared by the
# executable, installer, Start Menu, Desktop, and taskbar identity. The liquid
# tile is a presentation asset and must never become the application icon.
#
# The ICO is generated from frontend\public\enkstein-icon.png by
# scripts\generate_app_icon.py and committed, so the frames Windows loads are
# the exact bytes the packaging tests validate.
$IconSource = Join-Path $Root "packaging\windows\Enkstein.ico"
if (-not (Test-Path $IconSource)) {
    throw "Icon missing: $IconSource. Run scripts/generate_app_icon.py."
}
$Icon = Join-Path $Stage "Enkstein.ico"
Copy-Item $IconSource $Icon

# Guard the regression rather than trusting the committed file: any opaque
# outer corner in any frame renders as a white box on a dark desktop. The
# Windows System.Drawing API scales the nearest frame and cannot reliably
# enumerate a 256px ICO entry, so validate the ICO directory itself here.
# `test_windows_icon_alpha.py` performs the pixel-level RGBA/corner checks for
# every decoded frame; this build-time check ensures no frame is omitted.
$IconBytes = [System.IO.File]::ReadAllBytes($Icon)
if ($IconBytes.Length -lt 6) { throw "Windows icon is too small to be a valid ICO." }
$Reserved = [BitConverter]::ToUInt16($IconBytes, 0)
$Type = [BitConverter]::ToUInt16($IconBytes, 2)
$Count = [BitConverter]::ToUInt16($IconBytes, 4)
if ($Reserved -ne 0 -or $Type -ne 1) { throw "Windows icon has an invalid ICO header." }
$ExpectedSizes = @(16, 24, 32, 48, 64, 128, 256)
$FoundSizes = @()
for ($Index = 0; $Index -lt $Count; $Index++) {
    $Offset = 6 + ($Index * 16)
    if ($Offset + 16 -gt $IconBytes.Length) { throw "Windows icon directory is truncated." }
    $WidthByte = $IconBytes[$Offset]
    $HeightByte = $IconBytes[$Offset + 1]
    $Width = if ($WidthByte -eq 0) { 256 } else { [int]$WidthByte }
    $Height = if ($HeightByte -eq 0) { 256 } else { [int]$HeightByte }
    if ($Width -ne $Height) { throw "Windows icon contains a non-square ${Width}x${Height} frame." }
    $FoundSizes += $Width
    $ImageBytes = [BitConverter]::ToUInt32($IconBytes, $Offset + 8)
    $ImageOffset = [BitConverter]::ToUInt32($IconBytes, $Offset + 12)
    if ($ImageBytes -eq 0 -or $ImageOffset + $ImageBytes -gt $IconBytes.Length) {
        throw "Windows icon contains an invalid ${Width}x${Height} frame payload."
    }
}
foreach ($Size in $ExpectedSizes) {
    if ($FoundSizes -notcontains $Size) { throw "Windows icon directory is missing the ${Size}x${Size} frame." }
}

# x64 rather than anycpu: WebView2Loader.dll is architecture-specific, and a
# 32-bit process would fail to load the 64-bit native loader shipped above.
& $Compiler /nologo /target:winexe /platform:x64 `
    /reference:System.Windows.Forms.dll `
    /reference:System.Drawing.dll `
    /reference:System.Net.Http.dll `
    /reference:"$WebView2Core" `
    /reference:"$WebView2Forms" `
    /win32icon:"$Icon" /out:"$Stage\Enkstein.exe" "$Root\packaging\windows\MarcellusLauncher.cs"
if ($LASTEXITCODE -ne 0) { throw "Enkstein launcher compilation failed." }

$InnoCompiler = "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe"
if (-not (Test-Path $InnoCompiler)) {
    throw "Inno Setup 6 is required: $InnoCompiler"
}

New-Item -ItemType Directory -Force -Path $Dist | Out-Null
& $InnoCompiler "/DVersion=$Version" "/DStageDir=$Stage" "/DOutputDir=$Dist" "$Root\packaging\windows\Marcellus.iss"
if ($LASTEXITCODE -ne 0) { throw "Inno Setup compilation failed." }

$Output = Join-Path $Dist "Enkstein-$Version-windows-x64-setup.exe"
if (-not (Test-Path $Output)) { throw "Expected installer was not created: $Output" }
Write-Host "Built: $Output"
