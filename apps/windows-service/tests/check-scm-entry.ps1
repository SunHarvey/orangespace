param([Parameter(Mandatory = $true)][string]$ServiceBinary)
$ErrorActionPreference = 'Stop'
$Clock = [System.Diagnostics.Stopwatch]::StartNew()
[Console]::Out.WriteLine('scm-entry stage=script-enter elapsed_ms=0')
[Console]::Out.Flush()

# Fixture-local exact-root observation; no process-tree/PID lookup or service mutation.
function Invoke-EntryCase {
    param([string]$Binary, [string]$Arguments, [int]$Expected, [string]$Label)
    $Child = New-Object System.Diagnostics.Process
    $Owned = $false
    $Handle = [IntPtr]::Zero
    $Stage = 'prepare'
    $Actual = -1
    $Cleanup = 'not-started'
    $Passed = $false
    try {
        $Child.StartInfo.FileName = $Binary
        $Child.StartInfo.Arguments = $Arguments
        $Child.StartInfo.UseShellExecute = $false
        $Child.StartInfo.CreateNoWindow = $true
        # Never relay arbitrary child output; bounded root waits do not drain pipes.
        $Child.StartInfo.RedirectStandardOutput = $true
        $Child.StartInfo.RedirectStandardError = $true
        if ($Clock.ElapsedMilliseconds -ge 10000) { throw 'observation-budget' }
        $Stage = 'launch-begin'
        [Console]::Out.WriteLine("scm-entry case=$Label stage=$Stage elapsed_ms=$($Clock.ElapsedMilliseconds)")
        [Console]::Out.Flush()
        if (-not $Child.Start()) { throw 'start-failed' }
        $Owned = $true # Must precede every Handle/property observation after Start.
        $Stage = 'launch-returned'
        [Console]::Out.WriteLine("scm-entry case=$Label stage=$Stage elapsed_ms=$($Clock.ElapsedMilliseconds)")
        [Console]::Out.Flush()
        $Stage = 'handle-observe'
        [Console]::Out.WriteLine("scm-entry case=$Label stage=$Stage elapsed_ms=$($Clock.ElapsedMilliseconds)")
        [Console]::Out.Flush()
        $Handle = $Child.Handle # Retain the exact started object's handle until receipt/disposal.
        $Stage = 'root-wait'
        [Console]::Out.WriteLine("scm-entry case=$Label stage=$Stage elapsed_ms=$($Clock.ElapsedMilliseconds)")
        [Console]::Out.Flush()
        $Remaining = [Math]::Max(0, [Math]::Min(4000, 10000 - $Clock.ElapsedMilliseconds))
        if (-not $Child.WaitForExit([int]$Remaining)) { throw 'root-timeout' }
        $Stage = 'wait-complete'
        $Actual = $Child.ExitCode
        [Console]::Out.WriteLine("scm-entry case=$Label stage=$Stage elapsed_ms=$($Clock.ElapsedMilliseconds) exit_code=$Actual")
        [Console]::Out.Flush()
        $Stage = 'exit-assert'
        if ($Actual -ne $Expected) { throw 'exit-mismatch' }
        $Passed = $true
        $Stage = 'passed'
    } catch {
        # Preserve the last fixed stage, never exception text or arbitrary child data.
        $Passed = $false
    } finally {
        if ($Owned) {
            $Cleanup = 'unknown'
            [Console]::Out.WriteLine("scm-entry case=$Label stage=cleanup-begin elapsed_ms=$($Clock.ElapsedMilliseconds)")
            [Console]::Out.Flush()
            try {
                if (-not $Child.HasExited) {
                    if (-not $CleanupClock.IsRunning) { $CleanupClock.Start() }
                    try { $Child.Kill() } catch {
                        if (-not $Child.HasExited) { throw 'cleanup-kill' }
                    }
                    $Left = [Math]::Max(0, 2000 - $CleanupClock.ElapsedMilliseconds)
                    if (-not $Child.WaitForExit([int]$Left)) { throw 'cleanup-wait' }
                }
                $Actual = $Child.ExitCode
                $Cleanup = 'complete'
            } catch { $Passed = $false }
        }
        # Receipt precedes disposal, including unknown cleanup; never continue on uncertainty.
        [Console]::Out.WriteLine("scm-entry case=$Label stage=$Stage elapsed_ms=$($Clock.ElapsedMilliseconds) exit_code=$Actual cleanup=$Cleanup")
        [Console]::Out.Flush()
        $Child.Dispose()
    }
    return ($Passed -and $Cleanup -eq 'complete')
}

$CleanupClock = New-Object System.Diagnostics.Stopwatch
$Preflight = 'foundation-query'
try {
    [Console]::Out.WriteLine("scm-entry stage=$Preflight elapsed_ms=$($Clock.ElapsedMilliseconds)")
    [Console]::Out.Flush()
    # Enumerate successfully before interpreting absence. Query failure is not absence.
    $Services = @(Get-Service -ErrorAction Stop)
    if (@($Services | Where-Object { $_.Name -eq 'OrangeSpaceFoundation' }).Count -ne 0) {
        $Preflight = 'foundation-existing'
        throw 'ineligible-host'
    }
    $Preflight = 'foundation-absent'
    [Console]::Out.WriteLine("scm-entry stage=$Preflight elapsed_ms=$($Clock.ElapsedMilliseconds)")
    [Console]::Out.Flush()
    $Preflight = 'binary-resolve'
    $Binary = (Resolve-Path -LiteralPath $ServiceBinary -ErrorAction Stop).ProviderPath
} catch {
    [Console]::Out.WriteLine("scm-entry stage=$Preflight elapsed_ms=$($Clock.ElapsedMilliseconds) result=failed")
    [Console]::Out.Flush()
    exit 1
}
# No SCM registration, privilege elevation, service installation, or skip occurs here.
if (-not (Invoke-EntryCase $Binary '' 1063 'noargs')) { exit 1 }
if (-not (Invoke-EntryCase $Binary '--console' 87 'console')) { exit 1 }
[Console]::Out.WriteLine("scm-entry stage=complete elapsed_ms=$($Clock.ElapsedMilliseconds) result=passed")
[Console]::Out.Flush()
