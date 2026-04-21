# MITRE ATT&CK Mapping

A complete mapping of all detections in this lab to the MITRE ATT&CK framework.

| Technique ID | Name | Tactic | Detection File | Runbook | Validated |
|-------------|------|--------|----------------|---------|-----------|
| [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | Brute Force: Password Guessing | Credential Access | T1110-001-brute-force.kql | runbook-T1110-001.md | ✅ Yes |
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Initial Access / Persistence | T1078-after-hours-access.kql | runbook-T1078.md | 📋 Query only |
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | PowerShell | Execution | T1059-001-powershell.kql | runbook-T1059-001.md | ✅ Yes |
| [T1087.001](https://attack.mitre.org/techniques/T1087/001/) | Account Discovery: Local Account | Discovery | T1087-001-account-discovery.kql | runbook-T1087-001.md | ✅ Yes |
| [T1136.001](https://attack.mitre.org/techniques/T1136/001/) | Create Account: Local Account | Persistence | T1136-001-create-local-account.kql | runbook-T1136-001.md | ✅ Yes |

## Tactic Coverage

| Tactic | Techniques Covered |
|--------|-------------------|
| Credential Access | T1110.001 |
| Initial Access | T1078 |
| Persistence | T1078, T1136.001 |
| Execution | T1059.001 |
| Discovery | T1087.001 |

## Detection Method Notes

**T1110.001 - Brute Force**
Detected via EventID 4625 (failed logon). Dynamic severity based on attempt volume within a 15-minute static window. Known limitation: static bin() buckets mean an attacker splitting attempts across two windows evades detection. Threat Hunting Hypothesis 1 addresses this gap.

**T1078 — Valid Accounts**
Detected via EventID 4624 (successful logon) filtered to LogonType 2 and 10 (interactive and RDP). Monitors named privileged accounts outside business hours. Query written and documented — not simulated in this lab as the monitored accounts do not exist in the lab environment.

**T1059.001 - PowerShell**
Detected via EventID 4688 (process creation) filtered to powershell.exe and pwsh.exe with suspicious flag patterns. Requires command-line logging enabled via registry key. EncodedPayload field extracts Base64 payload automatically for analyst triage.

**T1087.001 - Account Discovery**
Detected via EventID 4688 using pattern matching on enumeration commands. Volume-based detection — a single whoami is normal, four enumeration commands in ten minutes is not. Detects the sequence rather than individual commands to reduce false positives.

**T1136.001 - Create Account**
Detected via union of EventID 4688 (net user /add command) and EventID 4720 (Windows account management event). Dual-signal approach catches both command-line and API-based account creation. DetectionMethod field identifies which signal fired.
