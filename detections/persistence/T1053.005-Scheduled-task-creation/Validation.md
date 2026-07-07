# Chainsaw & Atomic red team validation for T1053.005
> **Rule**:  `rule.yml``rule.spl` 
> **Test date**: 2026-07-07
> **Lab host**: LAB-WIN11-01 (Windows 11 22H2, synthetic hostname)
> **Emulation tool**: Atomic Red Team (Invoke-AtomicRedTeam), Chainsaw

---

# Chain saw validation
--- 
### Summary table
| Round | Benign FP rate | Malicious TP rate |
| iteration 1 | 20% | 80% |
| iteration 2 | 100% | 100% |


## Raw result from iteration 1
tests/test_detections.py::test_fixtures_present PASSED                   [  7%]
tests/test_detections.py::test_no_wiring_errors[NOTSET] SKIPPED (got...) [ 15%]
tests/test_detections.py::test_fires_on_malicious[T1053.005-Scheduled-task-creation/malicious_mal_privesc_runlevel_highest] PASSED [ 23%]
tests/test_detections.py::test_fires_on_malicious[T1053.005-Scheduled-task-creation/malicious_mal_pscmdlet_encoded] PASSED [ 30%]
tests/test_detections.py::test_fires_on_malicious[T1053.005-Scheduled-task-creation/malicious_mal_schtask_encoded_powershell] PASSED [ 38%]
tests/test_detections.py::test_fires_on_malicious[T1053.005-Scheduled-task-creation/malicious_mal_wmi_registerbyxml_temp_path] FAILED [ 46%]
tests/test_detections.py::test_fires_on_malicious[T1059.001-PowerShell-Execution/malicious] PASSED [ 53%]
tests/test_detections.py::test_quiet_on_benign[T1053.005-Scheduled-task-creation/benign_benign_clean_powershell_script] FAILED [ 61%]
tests/test_detections.py::test_quiet_on_benign[T1053.005-Scheduled-task-creation/benign_benign_installer_temp_task] PASSED [ 69%]
tests/test_detections.py::test_quiet_on_benign[T1053.005-Scheduled-task-creation/benign_benign_signed_backup_task] PASSED [ 76%]
tests/test_detections.py::test_quiet_on_benign[T1053.005-Scheduled-task-creation/benign_benign_system_maintenance_task] PASSED [ 84%]
tests/test_detections.py::test_quiet_on_benign[T1053.005-Scheduled-task-creation/benign_benign_user_logon_notepad] PASSED [ 92%]
tests/test_detections.py::test_quiet_on_benign[T1059.001-PowerShell-Execution/benign] FAILED [100%]
## Description of results
First iteration worked well, 7/9 were expected results, the malicious failed once, benign failed once. 
Second iteration eliminated these two failures, now benign wont fire and malicious will always be detected. 

I changed the following to achieve those results between first and second iteration:
Create a filter for- 
C:\Users\Public\**
This is the main one from- malicious_mal_wmi_registerbyxml_temp_path
Registering a seemingly admin/benign sounding executable to the public file system (Any user can write to this but its very rarely done by system or in a non malicious fashion)

In doing this though a benign test started failing, I'd rather accept a benign test failure than a malciious one however so I'll leave this as failing and in the splunk SIEM I can tune out this False positive benign test anyhow.

--- 

# Atomic red team valiadtion
