# <TEMPLATE FOR GENERATING TELEMETRY IN POWERSHELL>
This one is written for T1218 so change names and what not to fit the technique youre working on.
``` Powershell
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Collects Windows Security event telemetry for scheduled task creation (EID 4698),
    exporting one EVTX slice per test case for use with chainsaw.
.DESCRIPTION
    T1218.005/11/10 - System Binary Proxy Execution:
    Suspicious use of regsvr32.exe, mshta.exe, and rundll32.exe to execute scripts or load DLLs from remote locations.
.NOTES
    Run on a lab or test system, not a live environment.
    Required sysmon configuration with EID 1/3 whitelisted.
#>

[CmdletBinding()]
param(
    [string]$OutputDir = "C:\Users\theri\ChainsawTestDataset"
)
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
function Write-Section($msg) {
    Write-Host "`n=== $msg ===" -ForegroundColor Cyan
}

Write-Section "Creating Malicious & benign Events"
$tests = @(
 # ---------------- MALICIOUS ----------------
 # ----------------- rundll32.exe ------------
    @{
    Name = "mal_rundll32_script_abuse"
    Category = "malicious"
    TaskName = "ScriptAbuse"
    Trigger = {}
    Cleanup = {}
    },
    @{
    Name = "mal_rundll32_credential_dumping"
    Category = "malicious"
    TaskName = "CredentialDumping"
    Trigger = {}
    Cleanup = {}
    },
    @{
    Name = "mal_rundll32_parent"
    Category = "malicious"
    TaskName = "ParentProcess"
    Trigger = {}
    Cleanup = {}
    },
 # ----------------- mshta.exe ---------------
    @{
    Name = "mal_mshta_clsid"
    Category = "malicious"
    TaskName = "CLSID"
    Trigger = {}
    Cleanup = {}
    },
    @{
    Name = "mal_mshta_encoded"
    Category = "malicious"
    TaskName = "Encoded"
    Trigger = {}
    Cleanup = {}
    },
    @{
    Name = "mal_mshta_frombase64string"
    Category = "malicious"
    TaskName = "FromBase64String"
    Trigger = {}
    Cleanup = {}
    },
 # ----------------- regsvr32.exe -------------
    @{
    Name = "mal_regsvr32_parent"
    Category = "malicious"
    TaskName = "ParentProcess"
    Trigger = {}
    Cleanup = {}
    },
    @{
    Name = "mal_regsvr32_squiblydoo"
    Category = "malicious"
    TaskName = "SquiblyDoo"
    Trigger = {}
    Cleanup = {}
    },
    @{
    Name = "mal_regsvr32_suspicious_url"
    Category = "malicious"
    TaskName = "SuspiciousURL"
    Trigger = {}
    Cleanup = {}
    },
 # ---------------- BENIGN ------------------
 # ----------------- rundll32.exe ------------
    @{
    Name = "benign_rundll32_local_dll"
    Category = "benign"
    TaskName = "LocalDLL"
    Trigger = {}
    Cleanup = {}
    }, 
 @{
    Name = "benign_rundll32_signed_dll"
    Category = "benign"
    TaskName = "SignedDLL"
    Trigger = {}
    Cleanup = {}
    },
    @{
    Name = "benign_rundll32_system_dll"
    Category = "benign"
    TaskName = "SystemDLL"
    Trigger = {}
    Cleanup = {}
    },
# ================ mshta.exe ---------------
    @{
    Name = "benign_mshta_local_html"
    Category = "benign"
    TaskName = "LocalHTML"
    Trigger = {}
    Cleanup = {}
    },
    @{
    Name = "benign_mshta_signed_html"
    Category = "benign"
    TaskName = "SignedHTML"
    Trigger = {}
    Cleanup = {}
    },
@{
    Name = "benign_mshta_system_html"
    Category = "benign"
    TaskName = "SystemHTML"
    Trigger = {}
    Cleanup = {}
    },
 # ----------------- regsvr32.exe -------------
    @{
    Name = "benign_regsvr32_local_dll"
    Category = "benign"
    TaskName = "LocalDLL"
    Trigger = {}
    Cleanup = {}
    },
    @{
    Name = "benign_regsvr32_signed_dll"
    Category = "benign"
    TaskName = "SignedDLL"
    Trigger = {}
    Cleanup = {}
    },
    @{
    Name = "benign_regsvr32_system_dll"
    Category = "benign"
    TaskName = "SystemDLL"
    Trigger = {}
    Cleanup = {}
    }
)

# ------------------------------------------------------------------
# Execute each test case and export its own EVTX slice
# ------------------------------------------------------------------
foreach ($t in $tests) {
    Write-Host "`n=== [$($t.Category)] $($t.Name) ===" -ForegroundColor Cyan

    if ($t.Setup) { & $t.Setup }

    $start = (Get-Date).ToUniversalTime().AddSeconds(-1).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    & $t.Trigger
    Start-Sleep -Seconds 2
    & $t.Cleanup
    Start-Sleep -Seconds 1
    $end = (Get-Date).ToUniversalTime().AddSeconds(1).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")

    $outFile = Join-Path $OutputDir "$($t.Category)_$($t.Name).evtx"
    $query = "*[System[(EventID=4698 or EventID=4699) and TimeCreated[@SystemTime>='$start' and @SystemTime<='$end']]]"

    try {
        wevtutil epl Security "$outFile" /q:"$query" /ow:true
        $count = (Get-WinEvent -Path $outFile -ErrorAction SilentlyContinue | Measure-Object).Count
        Write-Host "  Exported $count event(s) -> $outFile" -ForegroundColor Green
        if ($count -eq 0) {
            Write-Host "  WARNING: 0 events captured -- check that auditing is enabled and the task actually registered." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "  Export failed: $_" -ForegroundColor Red
    }
}


Write-Host "`nDone. Files in $OutputDir are ready for:" -ForegroundColor Cyan
Write-Host "  chainsaw hunt $OutputDir -s <sigma_rules_dir> --mapping <mapping.yml> --csv -o results.csv" -ForegroundColor White
```