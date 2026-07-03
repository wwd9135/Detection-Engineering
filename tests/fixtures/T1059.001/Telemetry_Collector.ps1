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

# Function to write a section header in the console output for each section of the script
function Write-Section($msg) {
    Write-Host "`n=== $msg ===" -ForegroundColor Cyan
}
# Malicious events
Write-Section "Creating Malicious Events"

# ------------------------------------------------------------------
# 1. LOLBin + encoded args, via schtasks
# ------------------------------------------------------------------


# ------------------------------------------------------------------
# 2. Via PS cmdlet- Register-ScheduledTask 
# ------------------------------------------------------------------