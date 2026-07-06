#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Collects windows event telemetry for Task Scheduler events 4698
    which are generated when scheduled tasks are created, modified, deleted, enabled, or disabled.
    This is to be used with chainsaw.
.DESCRIPTION
    4698 - A scheduled task was created
    This script will create 5 malicious, 5 benign event that can occur during scheduled task creation.
    The events will be created in the event log and can be used with chainsaw to test my alerts if theyd trigger on these events.

.NOTES
    Run on a lab or test system not live environment. 
    Requires 4698 to be enabled in the event log- Enabling 'Other Object Access Events' auditing is required.
#>

[CmdletBinding()]
param(
    [string]$OutputDir = "C:\Users\theri\ChainsawTestData"
)

$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
function ConvertTo-PSEncodedCommand($cmd) {
    [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
}

$encodedPing = ConvertTo-PSEncodedCommand 'ping 127.0.0.1'

# Function to write a section header in the console output for each section of the script
function Write-Section($msg) {
    Write-Host "`n=== $msg ===" -ForegroundColor Cyan
}

Write-Section "Creating Malicious & benign Events"

$tests = @(
 # ---------------- MALICIOUS ----------------
    @{
        Name = "mal_schtask_encoded_powershell"
        Category = "malicious"
        TaskName = "WinDiagCheck1"
        Trigger = { schtasks /create /tn "WinDiagCheck1" /tr "powershell.exe -nop -w hidden -enc $encodedPing" /sc once /st 23:59 /f }
        Cleanup = { schtasks /delete /tn "WinDiagCheck1" /f 2>$null }
    },
    @{
        Name     = "mal_pscmdlet_encoded"
        Category = "malicious"
        TaskName = "AtomicEncoded"
        Trigger  = {
            $Action    = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-nop -w hidden -enc $encodedPing"
            $Trig      = New-ScheduledTaskTrigger -AtLogon
            $Principal = New-ScheduledTaskPrincipal -GroupId "BUILTIN\Administrators" -RunLevel Highest
            Register-ScheduledTask -TaskName "AtomicEncoded" -Action $Action -Trigger $Trig -Principal $Principal -Settings (New-ScheduledTaskSettingsSet) | Out-Null
        }
        Cleanup  = { Unregister-ScheduledTask -TaskName "AtomicEncoded" -Confirm:$false -ErrorAction SilentlyContinue }
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
            Register-ScheduledTask -Xml $xml -TaskName "SysHelperUpdate" -Force | Out-Null
        }
        Cleanup  = { Unregister-ScheduledTask -TaskName "SysHelperUpdate" -Confirm:$false -ErrorAction SilentlyContinue }
    },
    @{
        Name     = "mal_privesc_runlevel_highest"
        Category = "malicious"
        TaskName = "PrivEsc"
        Trigger  = { schtasks /create /tn "TaskName" /tr "C:\Users\Public\svc.ps1" /sc onlogon /ru SYSTEM /rl HIGHEST /f }
        Cleanup  = { schtasks /delete /tn "TaskName" /f 2>$null }
    },

 # ---------------- BENIGN ------------------
 @{
        Name     = "benign_signed_backup_task"
        Category = "benign"
        TaskName = "NightlyBackup"
        Trigger  = { schtasks /create /tn "NightlyBackup" /tr "C:\Program Files\BackupTool\backup.exe"  /sc daily /st 02:00 /f }
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