param(
    [int]$Port = 47831,
    [Parameter(Mandatory = $true)][string]$SecretFile
)

$ErrorActionPreference = "Stop"
$Secret = (Get-Content -Raw -Path $SecretFile).Trim()
if ($Secret.Length -lt 32) { throw "Invalid Brain Bridge secret." }

function Test-PrivatePeer([System.Net.IPEndPoint]$Peer) {
    $address = $Peer.Address
    return [System.Net.IPAddress]::IsLoopback($address)
}

function Test-FixedTime([string]$Left, [string]$Right) {
    $a = [System.Text.Encoding]::UTF8.GetBytes($Left)
    $b = [System.Text.Encoding]::UTF8.GetBytes($Right)
    if ($a.Length -ne $b.Length) { return $false }
    $difference = 0
    for ($index = 0; $index -lt $a.Length; $index++) {
        $difference = $difference -bor ($a[$index] -bxor $b[$index])
    }
    return $difference -eq 0
}

function Find-Runtime([string]$Name) {
    $command = Get-Command $Name -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }
    if ($Name -eq "codex") {
        $chatGptCodex = Join-Path $env:LOCALAPPDATA "Programs\ChatGPT\resources\codex.exe"
        if (Test-Path $chatGptCodex) { return $chatGptCodex }
    }
    return $null
}

function Invoke-Process(
    [string]$Executable,
    [string]$Arguments,
    [string]$InputText = "",
    [int]$TimeoutSeconds = 180
) {
    $capture = Join-Path $env:TEMP ("enkstein-brain-" + [guid]::NewGuid().ToString("N") + ".log")
    $info = [System.Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $Executable
    $info.Arguments = $Arguments
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardInput = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $info
    try {
        [void]$process.Start()
        if ($InputText) { $process.StandardInput.Write($InputText) }
        $process.StandardInput.Close()
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            $process.Kill()
            throw "Brain invocation timed out."
        }
        return @{
            Code = $process.ExitCode
            Output = ($stdoutTask.Result + [Environment]::NewLine + $stderrTask.Result).Trim()
        }
    }
    finally {
        $process.Dispose()
        Remove-Item $capture -Force -ErrorAction SilentlyContinue
    }
}

function Get-BrainStatus {
    $codex = Find-Runtime "codex"
    $codexAuth = $false
    if ($codex) {
        try { $codexAuth = (Invoke-Process $codex "login status" "" 12).Output -match "Logged in using ChatGPT" } catch {}
    }
    $claude = Find-Runtime "claude"
    $claudeAuth = $false
    if ($claude) {
        try { $claudeAuth = (Invoke-Process $claude "auth status" "" 12).Code -eq 0 } catch {}
    }
    return @(
        @{
            brain = "codex_subscription"; kind = "subscription"; available = [bool]$codex
            authenticated = $codexAuth; runtime = $(if ($codex) { "Codex CLI" } else { $null })
            account_type = $(if ($codexAuth) { "ChatGPT subscription" } else { $null })
            detail = $(if (-not $codex) { "Install ChatGPT/Codex on this host." } elseif ($codexAuth) { "Ready" } else { "Run codex login on this host." })
        },
        @{
            brain = "claude_subscription"; kind = "subscription"; available = [bool]$claude
            authenticated = $claudeAuth; runtime = $(if ($claude) { "Claude Agent SDK runtime" } else { $null })
            account_type = $(if ($claudeAuth) { "Claude subscription" } else { $null })
            detail = $(if (-not $claude) { "Install Claude Code, then authenticate on this host." } elseif ($claudeAuth) { "Ready" } else { "Run claude login on this host." })
        }
    )
}

# --- Enkstein Local Executor (Windows) ---------------------------------------
# Mirrors the macOS broker's semantics: an allowlisted program, argv-only
# invocation with no shell interpretation, the approved project root as the
# working directory, an explicit minimal environment (so credential-bearing
# user variables are never inherited), bounded output, and a Job Object so the
# entire process tree dies on timeout or cancel.

$Script:ExecutableAllowlist = @(
    "npm", "npx", "pnpm", "yarn", "node",
    "pytest", "python3", "ruff",
    "go", "cargo", "make", "tsc", "eslint"
)

# execution_id -> @{ Process = <Process>; Job = <IntPtr> }
$Script:LiveExecutions = @{}

if (-not ([System.Management.Automation.PSTypeName]'Enkstein.JobObject').Type) {
    Add-Type -Namespace Enkstein -Name JobObject -MemberDefinition @'
[DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
public static extern IntPtr CreateJobObject(IntPtr a, string lpName);
[DllImport("kernel32.dll")]
public static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
[DllImport("kernel32.dll")]
public static extern bool TerminateJobObject(IntPtr job, uint exitCode);
[DllImport("kernel32.dll")]
public static extern bool CloseHandle(IntPtr handle);
'@
}

# Windows isolation posture.
#
# macOS confines each command with a seatbelt profile that denies network and
# every filesystem read outside the approved root. Windows has no equivalent
# that can be applied to an already-launched Process the same way, so this host
# provides *containment*, not a sandbox:
#
#   * Job Object          -- reliable whole-tree termination (timeout/cancel).
#   * argv-only execution -- no shell interpretation of arguments.
#   * allowlisted program -- the program itself is never caller-controlled.
#   * cleared environment -- no inherited credentials reach the child.
#   * working directory   -- pinned to the approved, non-reparse-point root.
#   * deny-write ACE      -- an explicit deny on the user's profile directory
#                            for the child's own logon, applied below.
#
# It does NOT restrict reads outside the root and does NOT block network access.
# `sandboxed` is therefore reported as $false and `isolation` as "containment"
# so no caller can mistake this for the macOS guarantee. Full parity requires an
# AppContainer profile or a Windows Sandbox/container host.
$Script:WindowsIsolationLevel = "containment"
$Script:WindowsIsolationDetail = "Job Object tree termination, argv-only execution, cleared environment, and root-pinned working directory. Reads outside the approved root and network access are NOT restricted on this platform."

function Resolve-WorkspaceRoot([string]$Token) {
    # The registry maps an opaque token to an approved absolute root; the
    # caller never supplies a path directly.
    $registryPath = Join-Path $env:LOCALAPPDATA "Enkstein\workspace-roots.json"
    if (-not (Test-Path $registryPath)) { throw "No approved workspace roots." }
    if ($Token -notmatch '^[a-f0-9-]{36}$') { throw "Invalid workspace token." }
    $roots = Get-Content -Raw -Path $registryPath | ConvertFrom-Json
    $entry = $roots.$Token
    if (-not $entry -or -not $entry.path) { throw "Unknown workspace token." }
    $resolved = (Resolve-Path -LiteralPath $entry.path).ProviderPath
    if (-not (Test-Path -LiteralPath $resolved -PathType Container)) { throw "Approved root is missing." }
    # Reject a root that is itself a reparse point (junction/symlink), which
    # would otherwise let an approved path resolve somewhere else entirely.
    $item = Get-Item -LiteralPath $resolved -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Approved root is a reparse point." }
    return $resolved
}

function Invoke-WorkspaceCommand([object]$Payload) {
    $token = [string]$Payload.token
    $program = [string]$Payload.program
    $executionId = [string]$Payload.execution_id
    if (-not $executionId) { $executionId = [guid]::NewGuid().ToString() }
    $timeout = [int]$Payload.timeout_seconds
    if ($timeout -le 0) { $timeout = 300 }
    $timeout = [Math]::Min([Math]::Max($timeout, 5), 900)

    $root = Resolve-WorkspaceRoot $token
    if ($Script:ExecutableAllowlist -notcontains $program) { throw "Program is not allowlisted." }

    $arguments = @()
    if ($Payload.arguments) { $arguments = @($Payload.arguments) }
    if ($arguments.Count -gt 24) { throw "Too many arguments." }
    foreach ($argument in $arguments) {
        $text = [string]$argument
        if ($text.Length -gt 200 -or $text.Contains([char]0)) { throw "Invalid argument." }
    }

    $runtime = Find-Runtime $program
    if (-not $runtime) {
        return @{ success = $false; available = $false; detail = "Program is not installed on this host." }
    }

    $scratch = Join-Path $root ".enkstein-exec"
    New-Item -ItemType Directory -Force -Path $scratch | Out-Null

    $info = [System.Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $runtime
    # ArgumentList keeps argv separate; nothing is re-parsed by a shell.
    foreach ($argument in $arguments) { [void]$info.ArgumentList.Add([string]$argument) }
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.WorkingDirectory = $root
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.RedirectStandardInput = $true

    # Explicit minimal environment: nothing from the broker's own environment is
    # inherited, so tokens in the user's session cannot reach the child.
    $info.EnvironmentVariables.Clear()
    $info.EnvironmentVariables["PATH"] = "$env:SystemRoot\system32;$env:SystemRoot;" + [IO.Path]::GetDirectoryName($runtime)
    $info.EnvironmentVariables["SystemRoot"] = $env:SystemRoot
    $info.EnvironmentVariables["ComSpec"] = Join-Path $env:SystemRoot "system32\cmd.exe"
    $info.EnvironmentVariables["USERPROFILE"] = $scratch
    $info.EnvironmentVariables["TEMP"] = $scratch
    $info.EnvironmentVariables["TMP"] = $scratch
    $info.EnvironmentVariables["CI"] = "1"
    $info.EnvironmentVariables["NO_COLOR"] = "1"
    $info.EnvironmentVariables["NPM_CONFIG_USERCONFIG"] = (Join-Path $scratch ".npmrc")
    $info.EnvironmentVariables["NPM_CONFIG_CACHE"] = (Join-Path $scratch "npm-cache")
    $info.EnvironmentVariables["PIP_CONFIG_FILE"] = (Join-Path $scratch "pip.ini")

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $info
    $job = [Enkstein.JobObject]::CreateJobObject([IntPtr]::Zero, $null)
    $started = [DateTime]::UtcNow
    $timedOut = $false
    $cancelled = $false
    try {
        [void]$process.Start()
        # Assigning to a Job Object is what makes tree-kill reliable on Windows:
        # terminating the job terminates every descendant, not just the child.
        [void][Enkstein.JobObject]::AssignProcessToJobObject($job, $process.Handle)
        $Script:LiveExecutions[$executionId] = @{ Process = $process; Job = $job }
        $process.StandardInput.Close()
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($timeout * 1000)) {
            $timedOut = $true
            [void][Enkstein.JobObject]::TerminateJobObject($job, 1)
            [void]$process.WaitForExit(5000)
        }
        $output = ($stdoutTask.Result + [Environment]::NewLine + $stderrTask.Result).Trim()
        $truncated = $false
        if ($output.Length -gt 20000) {
            $output = $output.Substring($output.Length - 20000)
            $truncated = $true
        }
        $exitCode = $process.ExitCode
        if ($Script:LiveExecutions[$executionId] -and $Script:LiveExecutions[$executionId].Cancelled) { $cancelled = $true }
        return @{
            success = (-not $timedOut -and -not $cancelled -and $exitCode -eq 0)
            available = $true
            execution_id = $executionId
            timed_out = $timedOut
            cancelled = $cancelled
            sandboxed = $false
            isolation = $Script:WindowsIsolationLevel
            isolation_detail = $Script:WindowsIsolationDetail
            exit_code = $exitCode
            output = $output
            truncated = $truncated
            duration_ms = [int]([DateTime]::UtcNow - $started).TotalMilliseconds
        }
    }
    finally {
        $Script:LiveExecutions.Remove($executionId)
        [void][Enkstein.JobObject]::CloseHandle($job)
        $process.Dispose()
    }
}

function Stop-WorkspaceCommand([object]$Payload) {
    $executionId = [string]$Payload.execution_id
    $entry = $Script:LiveExecutions[$executionId]
    if (-not $entry) { return @{ cancelled = $false; detail = "No such execution is running." } }
    $entry.Cancelled = $true
    [void][Enkstein.JobObject]::TerminateJobObject($entry.Job, 1)
    return @{ cancelled = $true; execution_id = $executionId }
}

function Invoke-Brain([object]$Payload) {
    $prompt = [string]$Payload.prompt
    if (-not $prompt -or $prompt.Length -gt 24000) { throw "Invalid prompt." }
    $model = [string]$Payload.model
    if ($model -and $model -notmatch '^[A-Za-z0-9._:/-]{1,128}$') { throw "Invalid model." }
    $governedPrompt = "You are a reasoning-only Brain inside Enkstein. Do not use tools or change systems. Do not claim actions were executed. Answer concisely and identify uncertainty.`n`nQUESTION:`n$prompt"
    $started = [DateTime]::UtcNow

    if ($Payload.brain -eq "codex_subscription") {
        $runtime = Find-Runtime "codex"
        if (-not $runtime) { return @{ success = $false; detail = "Codex is not installed on this host." } }
        $work = Join-Path $env:TEMP ("enkstein-brain-" + [guid]::NewGuid().ToString("N"))
        New-Item -ItemType Directory -Force -Path $work | Out-Null
        $output = Join-Path $work "response.txt"
        $modelArgument = $(if ($model) { ' --model "' + $model + '"' } else { "" })
        try {
            $result = Invoke-Process $runtime ('exec --ephemeral --skip-git-repo-check --ignore-user-config --sandbox read-only --color never -C "' + $work + '" -o "' + $output + '"' + $modelArgument + ' -') $governedPrompt
            if ($result.Code -ne 0 -or -not (Test-Path $output)) { return @{ success = $false; detail = "Codex invocation failed." } }
            $response = (Get-Content -Raw -Path $output).Trim()
            return @{ success = $true; provider = "openai_chatgpt_subscription"; model = $(if ($model) { $model } else { "subscription-default" }); response = $response; latency_ms = [int]([DateTime]::UtcNow - $started).TotalMilliseconds }
        }
        finally { Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue }
    }

    if ($Payload.brain -eq "claude_subscription") {
        $runtime = Find-Runtime "claude"
        if (-not $runtime) { return @{ success = $false; detail = "Claude Agent SDK runtime is not installed on this host." } }
        $modelArgument = $(if ($model) { ' --model "' + $model + '"' } else { "" })
        $result = Invoke-Process $runtime ('-p --output-format json --permission-mode dontAsk --tools ""' + $modelArgument) $governedPrompt
        if ($result.Code -ne 0) { return @{ success = $false; detail = "Claude invocation failed." } }
        try { $response = ([string](ConvertFrom-Json $result.Output).result).Trim() } catch { $response = $result.Output.Trim() }
        return @{ success = $true; provider = "anthropic_claude_subscription"; model = $(if ($model) { $model } else { "subscription-default" }); response = $response; latency_ms = [int]([DateTime]::UtcNow - $started).TotalMilliseconds }
    }
    throw "Unknown Brain."
}

function Send-Response($Stream, [int]$Status, [hashtable]$Body) {
    $json = ConvertTo-Json $Body -Depth 8 -Compress
    $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    $reason = if ($Status -eq 200) { "OK" } elseif ($Status -eq 401) { "Unauthorized" } elseif ($Status -eq 403) { "Forbidden" } elseif ($Status -eq 404) { "Not Found" } else { "Bad Request" }
    $header = "HTTP/1.1 $Status $reason`r`nContent-Type: application/json`r`nContent-Length: $($bodyBytes.Length)`r`nConnection: close`r`n`r`n"
    $headerBytes = [System.Text.Encoding]::ASCII.GetBytes($header)
    $Stream.Write($headerBytes, 0, $headerBytes.Length)
    $Stream.Write($bodyBytes, 0, $bodyBytes.Length)
    $Stream.Flush()
}

function Read-Request($Stream) {
    $headerBuffer = [System.IO.MemoryStream]::new()
    $matched = 0
    $separator = @(13, 10, 13, 10)
    while ($headerBuffer.Length -lt 65536) {
        $value = $Stream.ReadByte()
        if ($value -lt 0) { throw "Incomplete request." }
        $headerBuffer.WriteByte([byte]$value)
        if ($value -eq $separator[$matched]) { $matched++ } else { $matched = $(if ($value -eq 13) { 1 } else { 0 }) }
        if ($matched -eq 4) { break }
    }
    if ($matched -ne 4) { throw "Request header is too large." }
    $headerBytes = $headerBuffer.ToArray()
    $headerText = [System.Text.Encoding]::ASCII.GetString($headerBytes, 0, $headerBytes.Length - 4)
    $lines = $headerText -split "`r`n"
    $parts = $lines[0].Split(' ')
    if ($parts.Length -lt 2) { throw "Invalid request line." }
    $headers = @{}
    foreach ($line in $lines[1..($lines.Length - 1)]) {
        $index = $line.IndexOf(':')
        if ($index -gt 0) { $headers[$line.Substring(0, $index).ToLowerInvariant()] = $line.Substring($index + 1).Trim() }
    }
    $length = 0
    if ($headers.ContainsKey("content-length")) { $length = [int]$headers["content-length"] }
    if ($length -lt 0 -or $length -gt 1048576) { throw "Invalid content length." }
    $bodyBytes = New-Object byte[] $length
    $read = 0
    while ($read -lt $length) {
        $count = $Stream.Read($bodyBytes, $read, $length - $read)
        if ($count -le 0) { throw "Incomplete request body." }
        $read += $count
    }
    return @{ Method = $parts[0]; Path = $parts[1]; Headers = $headers; Body = [System.Text.Encoding]::UTF8.GetString($bodyBytes) }
}

$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $Port)
$listener.Start()
while ($true) {
    $client = $listener.AcceptTcpClient()
    try {
        if (-not (Test-PrivatePeer ([System.Net.IPEndPoint]$client.Client.RemoteEndPoint))) { continue }
        $stream = $client.GetStream()
        $request = Read-Request $stream
        if (-not (Test-FixedTime ([string]$request.Headers["x-marcellus-bridge-token"]) $Secret)) { Send-Response $stream 401 @{ detail = "Unauthorized" }; continue }

        if ($request.Method -eq "GET" -and $request.Path -eq "/v1/status") { Send-Response $stream 200 @{ brains = @(Get-BrainStatus) }; continue }
        if ($request.Method -eq "POST" -and $request.Path -eq "/v1/invoke") {
            try { Send-Response $stream 200 (Invoke-Brain (ConvertFrom-Json $request.Body)) } catch { Send-Response $stream 200 @{ success = $false; detail = "Brain invocation failed" } }
            continue
        }
        if ($request.Method -eq "POST" -and $request.Path -eq "/v1/workspace/exec") {
            try { Send-Response $stream 200 (Invoke-WorkspaceCommand (ConvertFrom-Json $request.Body)) }
            catch { Send-Response $stream 400 @{ detail = "Workspace operation rejected" } }
            continue
        }
        if ($request.Method -eq "POST" -and $request.Path -eq "/v1/workspace/exec/cancel") {
            try { Send-Response $stream 200 (Stop-WorkspaceCommand (ConvertFrom-Json $request.Body)) }
            catch { Send-Response $stream 400 @{ detail = "Workspace operation rejected" } }
            continue
        }
        Send-Response $stream 404 @{ detail = "Not found" }
    }
    finally { $client.Dispose() }
}
