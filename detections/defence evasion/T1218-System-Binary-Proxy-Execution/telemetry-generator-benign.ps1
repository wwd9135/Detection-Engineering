#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Benign-only slice of the T1218 telemetry generator: the 9 false-positive-baseline
    cases (rundll32 / mshta / regsvr32 used the way legitimate software uses them).
    Produces one Sysmon EID 1 (process creation) EVTX slice per case for the Chainsaw
    harness. NONE of these should match rule.yml -- they are the "must NOT fire" baseline.

.DESCRIPTION
    Split out from telemetry-generator.ps1 to confirm the capture/export pipeline works
    end to end with content that carries no abuse patterns at all -- so there is nothing
    here for Defender / AMSI to flag. If this runs clean and the EVTX slices populate, the
    plumbing (Sysmon logging, time-window query, wevtutil export) is good, and any issue
    with the full generator is isolated to the malicious cases, not the harness.

    Every case is legitimate:
      * rundll32 -> named System32 exports (Control_RunDLL, ProcessIdleTasks, ...), no ordinal
      * mshta    -> opens a plain, script-free local .html document by file path
      * regsvr32 -> /s registration of a signed System32 DLL (no DllRegisterServer => no-op),
                    or a vendor DLL copied into the lab dir. No scrobj.dll, no .sct, no URL.
    All spawned windows are closed by the kill sweep after each capture.
#>
[CmdletBinding()]
param(
    [string]$OutputDir = "C:\Users\theri\ChainsawTestDataset",
    [string]$LabDir    = "C:\ProgramData\T1218_lab",
    [bool]$AddDefenderExclusion = $true
)
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
New-Item -ItemType Directory -Path $LabDir    -Force | Out-Null

function Write-Section($msg) { Write-Host "`n=== $msg ===" -ForegroundColor Cyan }
function Write-Payload([string]$Path, [string]$Content) {
    [System.IO.File]::WriteAllText($Path, $Content, (New-Object System.Text.UTF8Encoding($false)))
}

# ------------------------------------------------------------------
# Preflight -- confirm Sysmon EID 1 is being logged
# ------------------------------------------------------------------
Write-Section "Preflight"
$SysmonLog = "Microsoft-Windows-Sysmon/Operational"
try {
    $null = Get-WinEvent -ListLog $SysmonLog -ErrorAction Stop
    $recent = Get-WinEvent -FilterHashtable @{ LogName = $SysmonLog; Id = 1 } -MaxEvents 1 -ErrorAction SilentlyContinue
    if ($recent) {
        Write-Host "  Sysmon EID 1 logging confirmed." -ForegroundColor Green
    } else {
        Write-Host "  WARNING: Sysmon log present but no EID 1 found -- confirm the Sysmon config isn't excluding these images." -ForegroundColor Yellow
    }
} catch {
    Write-Host "  ERROR: '$SysmonLog' not found. Install Sysmon with process creation (EID 1) enabled, then re-run." -ForegroundColor Red
}

# Optional temporary Defender path exclusions (only the paths we add are removed at teardown).
$AddedExclusions = @()
if ($AddDefenderExclusion) {
    try {
        $existing = @((Get-MpPreference -ErrorAction Stop).ExclusionPath)
        foreach ($p in @($OutputDir, $LabDir)) {
            if ($existing -notcontains $p) { Add-MpPreference -ExclusionPath $p -ErrorAction Stop; $AddedExclusions += $p }
        }
        if ($AddedExclusions) { Write-Host "  Added temporary Defender path exclusions: $($AddedExclusions -join ', ')" -ForegroundColor Green }
        else { Write-Host "  Lab/output dirs already excluded -- nothing to add." -ForegroundColor Green }
    } catch {
        Write-Host "  WARNING: could not set Defender exclusions ($($_.Exception.Message)). Continuing." -ForegroundColor Yellow
    }
}

$KillNames = @('rundll32','mshta','regsvr32','control','calc','win32calc','CalculatorApp','Calculator','notepad')

Write-Section "Creating benign (false-positive baseline) events"
$tests = @(
 # ----------------- rundll32.exe ---------------------------------------------
 # Named System32 exports, no ordinal, no user-writable path -> no rule selection matches.
    @{
    Name    = "benign_rundll32_local_dll"
    Category= "benign"
    # Classic Control Panel routing -- the #1 legitimate rundll32 use.
    Trigger = { Start-Process rundll32.exe -ArgumentList 'shell32.dll,Control_RunDLL' }
    Cleanup = {}
    },
    @{
    Name    = "benign_rundll32_signed_dll"
    Category= "benign"
    Trigger = { Start-Process rundll32.exe -ArgumentList 'advapi32.dll,ProcessIdleTasks' }
    Cleanup = {}
    },
    @{
    Name    = "benign_rundll32_system_dll"
    Category= "benign"
    Trigger = { Start-Process rundll32.exe -ArgumentList 'user32.dll,UpdatePerUserSystemParameters' }
    Cleanup = {}
    },
 # ----------------- mshta.exe ------------------------------------------------
 # mshta opening a local, script-free .html by file path: command line is just the path,
 # parent is powershell -> no rule selection matches. Window closed by the kill sweep.
    @{
    Name    = "benign_mshta_local_html"
    Category= "benign"
    Setup   = { Write-Payload (Join-Path $LabDir 'benign_local.html')  '<html><body>Benign lab document - T1218 mshta FP baseline (local).</body></html>' }
    Trigger = { Start-Process mshta.exe -ArgumentList (Join-Path $LabDir 'benign_local.html') }
    Cleanup = { Remove-Item (Join-Path $LabDir 'benign_local.html') -Force -ErrorAction SilentlyContinue }
    },
    @{
    Name    = "benign_mshta_signed_html"
    Category= "benign"
    Setup   = { Write-Payload (Join-Path $LabDir 'benign_signed.html') '<html><body>Benign lab document - T1218 mshta FP baseline (signed).</body></html>' }
    Trigger = { Start-Process mshta.exe -ArgumentList (Join-Path $LabDir 'benign_signed.html') }
    Cleanup = { Remove-Item (Join-Path $LabDir 'benign_signed.html') -Force -ErrorAction SilentlyContinue }
    },
    @{
    Name    = "benign_mshta_system_html"
    Category= "benign"
    Setup   = { Write-Payload (Join-Path $LabDir 'benign_system.html') '<html><body>Benign lab document - T1218 mshta FP baseline (system).</body></html>' }
    Trigger = { Start-Process mshta.exe -ArgumentList (Join-Path $LabDir 'benign_system.html') }
    Cleanup = { Remove-Item (Join-Path $LabDir 'benign_system.html') -Force -ErrorAction SilentlyContinue }
    },
 # ----------------- regsvr32.exe ---------------------------------------------
 # Parent is powershell and no scrobj.dll/.sct/URL -> no rule selection matches. Target DLLs
 # export no DllRegisterServer, so /s is a silent no-op.
    @{
    Name    = "benign_regsvr32_local_dll"
    Category= "benign"
    # Stand-in for a third-party installer registering a vendor DLL from its own dir.
    Setup   = { Copy-Item 'C:\Windows\System32\kernel32.dll' (Join-Path $LabDir 'vendor_com.dll') -Force }
    Trigger = { Start-Process regsvr32.exe -ArgumentList '/s',(Join-Path $LabDir 'vendor_com.dll') }
    Cleanup = { Remove-Item (Join-Path $LabDir 'vendor_com.dll') -Force -ErrorAction SilentlyContinue }
    },
    @{
    Name    = "benign_regsvr32_signed_dll"
    Category= "benign"
    Trigger = { Start-Process regsvr32.exe -ArgumentList '/s','C:\Windows\System32\user32.dll' }
    Cleanup = {}
    },
    @{
    Name    = "benign_regsvr32_system_dll"
    Category= "benign"
    Trigger = { Start-Process regsvr32.exe -ArgumentList '/s','C:\Windows\System32\kernel32.dll' }
    Cleanup = {}
    }
)

# ------------------------------------------------------------------
# Execute each case and export its own EVTX slice (Sysmon EID 1)
# ------------------------------------------------------------------
try {
    foreach ($t in $tests) {
        Write-Host "`n=== [$($t.Category)] $($t.Name) ===" -ForegroundColor Cyan

        if ($t.Setup) { & $t.Setup }

        $triggerStart = Get-Date
        $start = $triggerStart.ToUniversalTime().AddSeconds(-2).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        & $t.Trigger
        Start-Sleep -Seconds 3
        if ($t.Cleanup) { & $t.Cleanup }

        foreach ($n in $KillNames) {
            Get-Process -Name $n -ErrorAction SilentlyContinue |
                Where-Object { try { $_.StartTime -ge $triggerStart } catch { $false } } |
                ForEach-Object { try { Stop-Process -Id $_.Id -Force -ErrorAction Stop } catch {} }
        }

        Start-Sleep -Seconds 1
        $end = (Get-Date).ToUniversalTime().AddSeconds(1).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")

        $outFile = Join-Path $OutputDir "$($t.Category)_$($t.Name).evtx"
        $query   = "*[System[(EventID=1) and TimeCreated[@SystemTime>='$start' and @SystemTime<='$end']]]"

        try {
            wevtutil epl "$SysmonLog" "$outFile" /q:"$query" /ow:true
            $count = (Get-WinEvent -Path $outFile -ErrorAction SilentlyContinue | Measure-Object).Count
            Write-Host "  Exported $count event(s) -> $outFile" -ForegroundColor Green
            if ($count -eq 0) {
                Write-Host "  WARNING: 0 events captured -- check Sysmon is running and EID 1 isn't filtered for this image." -ForegroundColor Yellow
            }
        } catch {
            Write-Host "  Export failed: $_" -ForegroundColor Red
        }
    }
}
finally {
    Remove-Item $LabDir -Recurse -Force -ErrorAction SilentlyContinue
    foreach ($p in $AddedExclusions) {
        try { Remove-MpPreference -ExclusionPath $p -ErrorAction Stop } catch {
            Write-Host "  WARNING: could not remove Defender exclusion for $p -- remove it manually." -ForegroundColor Yellow
        }
    }
    if ($AddedExclusions) { Write-Host "  Removed temporary Defender exclusions." -ForegroundColor Green }
}

Write-Host "`nDone. Benign EVTX slices are in $OutputDir." -ForegroundColor Cyan
