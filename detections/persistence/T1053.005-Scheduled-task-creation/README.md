# Windows Schedueled task creation

> **Technique**: T1053.005 — Schedueled task creation
> **Tactic**: Persistence (TA0003)
> **Severity**: High
> **Status**: Experimental

## Known real-world usage
Numerous ransomware families and APT groups (e.g., APT29, FIN7, various ransomware affiliates) use scheduled tasks for persistence and lateral execution — worth pulling a couple of current CTI examples if you want your detection writeup to cite specific TTP variants (e.g., specific task names or COM-API-only creation used by a given group). 

## Goal
Detect purely the creation of malicious scheduled tasks or tasks that contribute to an adversaries attack chain in any capacity.
An atomic rule that assesses all features of the 4698 windows event log to determine if a scheduled task creation is genuine admin activity.
Use a probabilistic severity scoring system IE. Suspicious arguments = 2 points, Susp folder path = 2 points, 5 points = High, 4 = Medium, 2 and below = informational.

---

## Categorisation



---

## Strategy Abstract




## Assumptions
object-access auditing (4698-4702) actually enabled

## Considerations
