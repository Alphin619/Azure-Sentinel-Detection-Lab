# Detection Runbook: Account Discovery - Local Account

**MITRE ATT&CK:** T1087.001
**Tactic:** Discovery
**Severity:** Medium / High (dynamic)
**Data Source:** SecurityEvent, EventID 4688
**Last Reviewed:** 2026

---

## Detection Logic

Fires when two or more account enumeration commands are run by the same user on the same host within a 10-minute window. A single whoami is normal developer or admin behaviour. The pattern of sequencing multiple enumeration commands like who am I, what groups exist, what users are active, is textbook post-compromise reconnaissance executed before lateral movement or privilege escalation. Detecting the pattern rather than individual commands dramatically reduces false positives.

## KQL Query

See [`/detections/T1087-001-account-discovery.kql`](https://github.com/Alphin619/Azure-Sentinel-Detection-Lab/blob/main/detections/T1087-001-account-discovery.kql)

---

## False Positives

- A new IT staff member auditing a system they have just been handed responsibility for
- A developer troubleshooting a permissions issue by checking their own group membership
- Automated compliance or vulnerability scanning tools running enumeration commands
- A legitimate admin running multiple commands in sequence during routine maintenance

---

## Triage Steps

1. Check **SubjectUserName** - is this a named user, a service account, or SYSTEM? SYSTEM running enumeration commands is a higher-fidelity signal than a named user.
2. Review **CommandsRun** - what specific commands were run and in what sequence? The combination of whoami /all followed by net localgroup administrators is a particularly suspicious pairing.
3. Check the time window - did the commands run in a tight burst (seconds apart) or spread across several minutes? Tight bursts suggest scripted execution.
4. Correlate with the PowerShell detection (T1059.001) on the same host. Was PowerShell executed immediately before or after the discovery commands?
5. Check for a preceding brute force or after-hours logon alert on the same host within the last hour. Discovery activity following an initial access indicator significantly raises confidence.
6. Query EventID 4688 on the same Computer for 30 minutes after the discovery window to identify what the account did next.

---

## Escalation Criteria

- **Escalate to L2 if:** CommandCount >= 4, or SYSTEM is the subject account, or discovery commands follow a brute force or after-hours logon alert on the same host within 60 minutes
- **Escalate to IR if:** Discovery activity is followed by account creation (T1136.001) or lateral movement indicators on other hosts

---

## Containment (L1)

- Do not isolate the host without L2 instruction unless an active threat is confirmed because isolation may alert the attacker
- Document the full CommandsRun list, SubjectUserName, and timestamps in the ticket
- Preserve all EventID 4688 entries from the affected host for the 60-minute window around the alert by exporting the query results

---
