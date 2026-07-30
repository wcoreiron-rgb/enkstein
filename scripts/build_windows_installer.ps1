param(
    [Parameter(Mandatory = $false)]
    [string]$Version = "0.2.0"
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
$WebView2Core = Join-Path $WebView2Dir "lib\net45\Microsoft.Web.WebView2.Core.dll"
$WebView2Forms = Join-Path $WebView2Dir "lib\net45\Microsoft.Web.WebView2.WinForms.dll"
$WebView2Loader = Join-Path $WebView2Dir "runtimes\win-x64\native\WebView2Loader.dll"
foreach ($assembly in @($WebView2Core, $WebView2Forms, $WebView2Loader)) {
    if (-not (Test-Path $assembly)) { throw "WebView2 component missing from the NuGet package: $assembly" }
}
# Shipped beside the executable: the managed assemblies are resolved at load
# time and the native loader is required for the control to initialize.
Copy-Item $WebView2Core  $Stage
Copy-Item $WebView2Forms $Stage
Copy-Item $WebView2Loader $Stage

if (-not (Get-Command magick -ErrorAction SilentlyContinue)) {
    throw "ImageMagick is required to generate the Windows application icon."
}
$Icon = Join-Path $Stage "Enkstein.ico"
& magick (Join-Path $Root "frontend\public\favicon-liquid.png") -define icon:auto-resize=256,128,64,48,32,16 $Icon
if ($LASTEXITCODE -ne 0 -or -not (Test-Path $Icon)) { throw "Windows icon generation failed." }

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
