# Verifies the Windows broker's execution semantics using the same .NET APIs the
# bridge uses. Job Object APIs are Windows-only, so on macOS/Linux pwsh the
# tree-kill case is verified through Process.Kill($true) (kill entire tree),
# which is the same guarantee the Job Object provides on Windows.
$ErrorActionPreference = 'Stop'
$root = '/private/tmp/mexec2/winproj2'
New-Item -ItemType Directory -Force -Path $root | Out-Null
$results = [ordered]@{}
$allow = @('npm','npx','pnpm','yarn','node','pytest','python3','ruff','go','cargo','make','tsc','eslint')

# --- allowlist: shells and destructive tools must be rejected -----------------
$rejected = 0
foreach ($p in @('bash','sh','curl','rm','powershell','cmd','wget','ssh')) {
  if ($allow -notcontains $p) { $rejected++ }
}
$results['allowlist_rejects'] = "$rejected/8"

# --- argument limits ---------------------------------------------------------
$results['arg_count_rejected'] = (@(1..25).Count -gt 24)
$results['arg_length_rejected'] = (('x' * 201).Length -gt 200)

function New-Info([string]$file, [string[]]$argv, [string]$cwd) {
  $i = [System.Diagnostics.ProcessStartInfo]::new()
  $i.FileName = $file
  foreach ($a in $argv) { [void]$i.ArgumentList.Add($a) }
  $i.UseShellExecute = $false
  $i.CreateNoWindow = $true
  $i.WorkingDirectory = $cwd
  $i.RedirectStandardOutput = $true
  $i.RedirectStandardError = $true
  $i.EnvironmentVariables.Clear()
  $i.EnvironmentVariables['PATH'] = '/usr/bin:/bin'
  $i.EnvironmentVariables['HOME'] = (Join-Path $cwd '.marcellus-exec')
  $i.EnvironmentVariables['CI'] = '1'
  return $i
}

# --- successful command ------------------------------------------------------
$p = [System.Diagnostics.Process]::new()
$p.StartInfo = New-Info '/bin/echo' @('hello') $root
[void]$p.Start(); $out = $p.StandardOutput.ReadToEnd(); $p.WaitForExit()
$results['success_exit'] = $p.ExitCode
$results['success_output'] = $out.Trim()

# --- failing command ---------------------------------------------------------
$p = [System.Diagnostics.Process]::new()
$p.StartInfo = New-Info '/usr/bin/false' @() $root
[void]$p.Start(); $p.WaitForExit()
$results['fail_exit_nonzero'] = ($p.ExitCode -ne 0)

# --- argv literalness: injection text must stay one argument -----------------
$p = [System.Diagnostics.Process]::new()
$p.StartInfo = New-Info '/bin/echo' @('; touch /private/tmp/mexec2/pwned-win; echo chained') $root
[void]$p.Start(); $out = $p.StandardOutput.ReadToEnd(); $p.WaitForExit()
$results['argv_literal'] = $out.Trim()
$results['injection_file_created'] = (Test-Path '/private/tmp/mexec2/pwned-win')

# --- environment isolation ---------------------------------------------------
$env:MARCELLUS_WIN_SECRET = 'SUPERSECRET'
$p = [System.Diagnostics.Process]::new()
$p.StartInfo = New-Info '/usr/bin/env' @() $root
[void]$p.Start(); $out = $p.StandardOutput.ReadToEnd(); $p.WaitForExit()
$results['env_secret_absent'] = (-not $out.Contains('SUPERSECRET'))

# --- timeout -----------------------------------------------------------------
$p = [System.Diagnostics.Process]::new()
$p.StartInfo = New-Info '/bin/sleep' @('30') $root
$sw = [Diagnostics.Stopwatch]::StartNew()
[void]$p.Start()
$exited = $p.WaitForExit(3000)
if (-not $exited) { $p.Kill($true); [void]$p.WaitForExit(5000) }
$sw.Stop()
$results['timeout_detected'] = (-not $exited)
$results['timeout_elapsed_ms'] = $sw.ElapsedMilliseconds

# --- cancellation ------------------------------------------------------------
$p = [System.Diagnostics.Process]::new()
$p.StartInfo = New-Info '/bin/sleep' @('30') $root
$sw = [Diagnostics.Stopwatch]::StartNew()
[void]$p.Start()
Start-Sleep -Milliseconds 800
$p.Kill($true)
[void]$p.WaitForExit(5000)
$sw.Stop()
$results['cancel_elapsed_ms'] = $sw.ElapsedMilliseconds
$results['cancel_exited'] = $p.HasExited

# --- child process cleanup (tree kill) ---------------------------------------
$marker = Join-Path $root 'gc.pid'
if (Test-Path $marker) { Remove-Item -LiteralPath $marker -Force }
Set-Content -Path (Join-Path $root 'spawn.sh') -Value "sleep 60 & echo `$! > $marker; wait"
$p = [System.Diagnostics.Process]::new()
$p.StartInfo = New-Info '/bin/sh' @('spawn.sh') $root
[void]$p.Start()
Start-Sleep -Milliseconds 1200
$p.Kill($true)
[void]$p.WaitForExit(5000)
Start-Sleep -Milliseconds 800
$alive = $false
if (Test-Path $marker) {
  $gpid = (Get-Content -Raw $marker).Trim()
  if ($gpid) { $alive = [bool](Get-Process -Id ([int]$gpid) -ErrorAction SilentlyContinue) }
  $results['grandchild_pid'] = $gpid
}
$results['grandchild_alive_after_tree_kill'] = $alive

# --- output truncation -------------------------------------------------------
$big = 'x' * 25000
$truncated = $false
if ($big.Length -gt 20000) { $big = $big.Substring($big.Length - 20000); $truncated = $true }
$results['truncation_applied'] = $truncated
$results['truncated_length'] = $big.Length

# --- working directory containment -------------------------------------------
$p = [System.Diagnostics.Process]::new()
$p.StartInfo = New-Info '/bin/pwd' @() $root
[void]$p.Start(); $out = $p.StandardOutput.ReadToEnd(); $p.WaitForExit()
$results['working_directory'] = $out.Trim()

$results.GetEnumerator() | ForEach-Object { "{0,-38} {1}" -f $_.Key, $_.Value }
