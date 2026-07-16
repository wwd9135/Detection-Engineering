# Rule to be correlated with <rule.yml>  into a single SPL rule (rule.SPL) with risk scoring.
title: Suspicious System Binary Proxy Execution via Rundll32, Mshta or Regsvr32
id: e9437397-4604-453b-92a3-feab79e44a2c
status: experimental
description: |
  Detects three sub-techniques of T1218 System Binary Proxy Execution:
  Mshta (T1218.005), Regsvr32 (T1218.010) and Rundll32 (T1218.011).
  These trusted, signed system binaries are abused to proxy the execution of
  malicious code past application control and signature-based defences.
  The rule looks for suspicious command-line arguments, suspicious parent/child
  process relationships, and well-known abuse patterns such as comsvcs.dll
  MiniDump credential dumping and the regsvr32 "Squiblydoo" remote scriptlet.
  Intended to be correlated with the companion network_connection rule below
  into a single KQL rule (rule.kql) with risk scoring.
references:
  - https://attack.mitre.org/techniques/T1218/
  - https://attack.mitre.org/techniques/T1218/005/
  - https://attack.mitre.org/techniques/T1218/010/
  - https://attack.mitre.org/techniques/T1218/011/
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218/T1218.md
  - https://lolbas-project.github.io/lolbas/Binaries/Regsvr32/
author: William Richardson
date: 2026-07-09
modified: 2026-07-10
tags:
  # ATT&CK restructure: Defense Evasion split into 'stealth' / 'defense-impairment';
  # T1218 maps to 'stealth' in the taxonomy sigma check validates against.
  - attack.stealth
  - attack.t1218
  - attack.t1218.005
  - attack.t1218.010
  - attack.t1218.011
# New networks rule to be correlated on above rule post KQL conversion.
log source:
  product: windows
  category: network_connection
  detection:
   