#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Collects Windows Security event telemetry for scheduled task creation (EID 4698),
    exporting one EVTX slice per test case for use with chainsaw.
.DESCRIPTION
    T1218.005/11/10 - System Binary Proxy Execution:
    Suspciious use of regsvr32.exe, mshta.exe, and rundll32.exe to execute scripts or load DLLs from remote locations.
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