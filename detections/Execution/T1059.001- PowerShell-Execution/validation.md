# Validation methods T1059.001- PowerShell execution

> **Rule**: `rule.yml` / `rule.kql`
> **Test date**: 2026-06-14
> **Lab host**: LAB-WIN11-01 (Windows 11 22H2, synthetic hostname)
> **Emulation tool**: Atomic Red Team (Invoke-AtomicRedTeam)
> **Sysmon version**: 15.14

---


### Pre-conditions
- Sysmon 15.x installed and running on LAB-WIN11-01 with registry event collection enabled (EID 1)
- Win event 4104 log enabled via registry key alteration- This detects script block logging/ shows encoded commands in their decoded form.
- Live updating Splunk or Sentinel SIEM hosted from laptop lab environment.
