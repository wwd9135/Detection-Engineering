# Validation Record — T1547.001 Registry Run Key Persistence
 Rule: rule.yml / rule.spl Test date: 2026-06-14 Lab host: LAB-WIN11-01 (Windows 11 22H2, synthetic hostname) Emulation tool: Atomic Red Team (Invoke-AtomicRedTeam) Sysmon version: 15.14

## 1. Test Procedure
Test used from atomic red team.
1.  **Suspicious jse file run from startup Folder**
Copy-Item "$PathToAtomicsFolder\T1547.001\src\jsestartup.jse" "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\jsestartup.jse" <Requires admin or root>
2. **Suspicious vbs file run from startup Folder** <Required admin or root>
Copy-Item "$PathToAtomicsFolder\T1547.001\src\vbsstartup.vbs" "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\vbsstartup.vbs"
3. **Suspicious bat file run from startup Folder** - <Requires admin or root>
Copy-Item "$PathToAtomicsFolder\T1547.001\src\batstartup.bat" "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\batstartup.bat"
4. **A .LNK file- Executable Shortcut Link to User Startup Folder (NonMalicious link to redirect to a malicious file location. Will auto run whatever its targeted at, works well as a .LNK is less suspicious than whatever they’re pointing at & the destination can be obfuscated in line.** - <Requires admin or root>

### Pre-conditions
1. Sysmon 15.4 installed and running on LAB-WIN11-01 with registry event collection enabled (EIDs 1, 2, 11).
2. Splunk sysmon & winevents index Agent forwarding Sysmon & winevents events to the splunk enterprise SIEM.
3. PowerShell 7 available for running Invoke-AtomicRedTeam.

### Tests ran
Since the four tests were very similar during testing I ran and fully documented the two slightly different types only.
In the detection being written, it will account for all four and be tested thoroughly to account for any mishaps of not testing at this current stage.
#### Test 1- .JSE file
Create file in the desired folder path
Copy-Item "$PathToAtomicsFolder\T1547.001\src\jsestartup.jse" "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\jsestartup.jse"
Copy-Item "$PathToAtomicsFolder\T1547.001\src\jsestartup.jse" "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\jsestartup.jse"
Trigger script to run to observe output


cscript.exe /E:Jscript "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\jsestartup.jse"
cscript.exe /E:Jscript "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\jsestartup.jse"
#### Test 4- .LNK file
$Target = "C:\Windows\System32\calc.exe"
$ShortcutLocation = "$home\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\calc_exe.lnk"
$WScriptShell = New-Object -ComObject WScript.Shell
$Create = $WScriptShell.CreateShortcut($ShortcutLocation)
$Create.TargetPath = $Target
$Create.Save()

After capturing telemetry, run cleanup
Invoke-AtomicTest T1547.001 -TestNumbers 5,7 -Cleanup

Expected telemetry - claude to finish this section, use the validation.md template given, fill in the expected telemetry for the two tests, use readme for inspiration if youre unsure.

# Generated telemetry- Need to insert this bit, grab  spl (splunk siem)
Test 1
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385f-c22a-43e0-bf4c-06f5698ffbd9}'/><EventID>11</EventID><Version>2</Version><Level>4</Level><Task>11</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='2026-06-17T16:07:01.5844598Z'/><EventRecordID>36070</EventRecordID><Correlation/><Execution ProcessID='33716' ThreadID='27368'/><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WILL</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='RuleName'>T1023</Data><Data Name='UtcTime'>2026-06-17 16:07:01.583</Data><Data Name='ProcessGuid'>{a751ca4b-c625-6a32-22c3-000000004500}</Data><Data Name='ProcessId'>5444</Data><Data Name='Image'>C:\WINDOWS\system32\WindowsPowerShell\v1.0\powershell.exe</Data><Data Name='TargetFilename'>C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\jsestartup.jse</Data><Data Name='CreationUtcTime'>2026-06-17 16:06:46.363</Data><Data Name='User'>WILL\theri</Data></EventData></Event>

Test 4
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385f-c22a-43e0-bf4c-06f5698ffbd9}'/><EventID>11</EventID><Version>2</Version><Level>4</Level><Task>11</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='2026-06-17T16:06:46.3638537Z'/><EventRecordID>36012</EventRecordID><Correlation/><Execution ProcessID='33716' ThreadID='27368'/><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WILL</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='RuleName'>T1023</Data><Data Name='UtcTime'>2026-06-17 16:06:46.363</Data><Data Name='ProcessGuid'>{a751ca4b-c615-6a32-ebc2-000000004500}</Data><Data Name='ProcessId'>11200</Data><Data Name='Image'>C:\WINDOWS\system32\WindowsPowerShell\v1.0\powershell.exe</Data><Data Name='TargetFilename'>C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\jsestartup.jse</Data><Data Name='CreationUtcTime'>2026-06-17 16:06:46.363</Data><Data Name='User'>WILL\theri</Data></EventData></Event>

5. Verification intended blocks didnt prevent the above TP flagging.:
