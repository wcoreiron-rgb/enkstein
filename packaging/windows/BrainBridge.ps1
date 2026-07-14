param(
    [int]$Port = 47831,
    [Parameter(Mandatory = $true)][string]$SecretFile
)

$ErrorActionPreference = "Stop"
$Secret = (Get-Content -Raw -Path $SecretFile).Trim()
if ($Secret.Length -lt 32) { throw "Invalid Brain Bridge secret." }

function Test-PrivatePeer([System.Net.IPEndPoint]$Peer) {
    $address = $Peer.Address
    if ([System.Net.IPAddress]::IsLoopback($address)) { return $true }
    if ($address.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { return $false }
    $bytes = $address.GetAddressBytes()
    return $bytes[0] -eq 10 -or
        ($bytes[0] -eq 192 -and $bytes[1] -eq 168) -or
        ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31)
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
    $capture = Join-Path $env:TEMP ("marcellus-brain-" + [guid]::NewGuid().ToString("N") + ".log")
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

function Invoke-Brain([object]$Payload) {
    $prompt = [string]$Payload.prompt
    if (-not $prompt -or $prompt.Length -gt 24000) { throw "Invalid prompt." }
    $model = [string]$Payload.model
    if ($model -and $model -notmatch '^[A-Za-z0-9._:/-]{1,128}$') { throw "Invalid model." }
    $governedPrompt = "You are a reasoning-only Brain inside Marcellus. Do not use tools or change systems. Do not claim actions were executed. Answer concisely and identify uncertainty.`n`nQUESTION:`n$prompt"
    $started = [DateTime]::UtcNow

    if ($Payload.brain -eq "codex_subscription") {
        $runtime = Find-Runtime "codex"
        if (-not $runtime) { return @{ success = $false; detail = "Codex is not installed on this host." } }
        $work = Join-Path $env:TEMP ("marcellus-brain-" + [guid]::NewGuid().ToString("N"))
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

$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, $Port)
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
        Send-Response $stream 404 @{ detail = "Not found" }
    }
    finally { $client.Dispose() }
}
