#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Generates 10 labeled, real (non-synthetic) EVTX files -- 5 benign, 5 malicious --
    each containing the 4698 (and 4699 where relevant) events produced by a specific
    scheduled-task creation scenario, for Chainsaw batch/regression testing.

.DESCRIPTION
    For each test case: records a start timestamp, runs the trigger (creates a real
    scheduled task via the stated method), waits briefly, cleans up the task, then
    exports ONLY that time window from the Security log to its own .evtx file via
    wevtutil. No log content is hand-authored -- every record is genuine output from
    the Task Scheduler engine / Security auditing subsystem.

.PREREQUISITE
    Run Enable-ScheduledTaskAuditing.ps1 (or equivalent) first so "Other Object Access
    Events" success auditing is actually enabled -- otherwise no 4698s will exist to export.

.NOTES
    Run this on an isolated lab VM. Test cases intentionally create tasks with
    encoded PowerShell and suspicious paths -- do not run on production or your
    daily-driver machine.
#>

[CmdletBinding()]
param(
    [string]$OutputDir = "C:\ChainsawTestData"
)

$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

# Small helper: base64-encode a command the way -EncodedCommand expects (UTF-16LE)
function ConvertTo-PSEncodedCommand($cmd) {
    [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
}

$encodedPing = ConvertTo-PSEncodedCommand 'ping 127.0.0.1'

# ------------------------------------------------------------------
# Test case definitions
# Each: Name, Category, TaskName, Setup{}, Trigger{}, Cleanup{}, ExtraEventIds
# ------------------------------------------------------------------
$tests = @(

    # ---------------- MALICIOUS ----------------
    @{
        Name     = "mal_schtask_encoded_powershell"
        Category = "malicious"
        TaskName = "WinDiagCheck1"
        Trigger  = { schtasks /create /tn "WinDiagCheck1" /tr "powershell.exe -nop -w hidden -enc $encodedPing" /sc once /st 23:59 /f }
        Cleanup  = { schtasks /delete /tn "WinDiagCheck1" /f 2>$null }
    },
    @{
        Name     = "mal_pscmdlet_encoded"
        Category = "malicious"
        TaskName = "AtomicTaskEncoded"
        Trigger  = {
            $Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-nop -w hidden -enc $encodedPing"
            $Trig   = New-ScheduledTaskTrigger -AtLogon
            $Principal = New-ScheduledTaskPrincipal -GroupId "BUILTIN\Administrators" -RunLevel Highest
            Register-ScheduledTask -TaskName "AtomicTaskEncoded" -Action $Action -Trigger $Trig -Principal $Principal -Settings (New-ScheduledTaskSettingsSet) | Out-Null
        }
        Cleanup  = { Unregister-ScheduledTask -TaskName "AtomicTaskEncoded" -Confirm:$false -ErrorAction SilentlyContinue }
    },
    @{
        Name     = "mal_wmi_registerbyxml_temp_path"
        Category = "malicious"
        TaskName = "SysHelperUpdate"
        Trigger  = {
            $xml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>
  <Principals><Principal id="Author"><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
  <Settings><Enabled>true</Enabled></Settings>
  <Actions Context="Author">
    <Exec><Command>C:\Users\Public\syshelper.exe</Command><Arguments>/quiet</Arguments></Exec>
  </Actions>
</Task>
"@
            Invoke-CimMethod -ClassName PS_ScheduledTask -Namespace "Root\Microsoft\Windows\TaskScheduler" `
                -MethodName "RegisterByXml" -Arguments @{ Force = $true; TaskPath = "\SysHelperUpdate"; Xml = $xml } | Out-Null
        }
        Cleanup  = { Unregister-ScheduledTask -TaskName "SysHelperUpdate" -Confirm:$false -ErrorAction SilentlyContinue }
    },
    @{
        Name     = "mal_qakbot_pattern"
        Category = "malicious"
        TaskName = "ATOMIC-T1053.005"
        Setup    = { reg add "HKCU\SOFTWARE\ATOMIC-T1053.005" /v test /t REG_SZ /d "$encodedPing" /f | Out-Null }
        Trigger  = {
            schtasks.exe /Create /F /TN "ATOMIC-T1053.005" /TR "cmd /c start /min `"`" powershell.exe -Command IEX([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String((Get-ItemProperty -Path HKCU:\SOFTWARE\ATOMIC-T1053.005).test)))" /sc daily /st 23:59
        }
        Cleanup  = {
            schtasks /delete /tn "ATOMIC-T1053.005" /f 2>$null
            reg delete "HKCU\SOFTWARE\ATOMIC-T1053.005" /f 2>$null
        }
    },
    @{
        Name     = "mal_privesc_runlevel_highest"
        Category = "malicious"
        TaskName = "UserProfileSync"
        Trigger  = { schtasks /create /tn "UserProfileSync" /tr "C:\Users\Public\svc.ps1" /sc onlogon /ru SYSTEM /rl HIGHEST /f }
        Cleanup  = { schtasks /delete /tn "UserProfileSync" /f 2>$null }
    },

    # ---------------- BENIGN ----------------
    @{
        Name     = "benign_signed_backup_task"
        Category = "benign"
        TaskName = "NightlyBackup"
        Trigger  = { schtasks /create /tn "NightlyBackup" /tr "`"C:\Program Files\BackupTool\backup.exe`" /silent" /sc daily /st 02:00 /f }
        Cleanup  = { schtasks /delete /tn "NightlyBackup" /f 2>$null }
    },
    @{
        Name     = "benign_system_maintenance_task"
        Category = "benign"
        TaskName = "DiskDefragWeekly"
        Trigger  = { schtasks /create /tn "DiskDefragWeekly" /tr "C:\Windows\System32\defrag.exe C: /O" /sc weekly /d SUN /st 03:00 /ru SYSTEM /f }
        Cleanup  = { schtasks /delete /tn "DiskDefragWeekly" /f 2>$null }
    },
    @{
        Name     = "benign_clean_powershell_script"
        Category = "benign"
        TaskName = "LogCleanupScript"
        Trigger  = { schtasks /create /tn "LogCleanupScript" /tr "powershell.exe -NoProfile -File `"C:\Scripts\Cleanup.ps1`"" /sc daily /st 01:00 /f }
        Cleanup  = { schtasks /delete /tn "LogCleanupScript" /f 2>$null }
    },
    @{
        Name     = "benign_installer_temp_task"
        Category = "benign"
        TaskName = "AdobeUpdateTask"
        Trigger  = { schtasks /create /tn "AdobeUpdateTask" /tr "`"C:\Users\jdoe\AppData\Local\Temp\AdobeARM.exe`" /silent" /sc hourly /f }
        Cleanup  = { schtasks /delete /tn "AdobeUpdateTask" /f 2>$null }
    },
    @{
        Name     = "benign_user_logon_notepad"
        Category = "benign"
        TaskName = "OpenNotesOnLogon"
        Trigger  = { schtasks /create /tn "OpenNotesOnLogon" /tr "C:\Windows\System32\notepad.exe C:\Users\jdoe\notes.txt" /sc onlogon /f }
        Cleanup  = { schtasks /delete /tn "OpenNotesOnLogon" /f 2>$null }
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