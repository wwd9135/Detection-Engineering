#



## Known gaps

If an attacker uses a rundll32 to launch another process or script, then that script is say powershell.exe not rundll, this rule wont detect it and any network connection it makes wont be detected either. So rundll32 as a jump script needs to be taken into account in my T1059.001 rules.