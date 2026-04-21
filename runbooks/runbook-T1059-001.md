# Detection Runbook: Suspicious PowerShell Execution

**MITRE ATT&CK:** T1059.001
**Tactic:** Execution
**Severity:** Medium / High (dynamic)
**Data Source:** SecurityEvent, EventID 4688
**Last Reviewed:** 2026

---

## Detection Logic

Detects PowerShell launched with flags or patterns associated with fileless malware, download cradles, and obfuscated execution. Requires command-line logging enabled via audit policy and registry key (see `/infrastructure/audit-policy-config.md`). High severity fires when encoded commands or download cradles are present. Medium fires for execution policy bypass flags alone.

## KQL Query

See [`/detections/T1059-001-powershell.kql`](https://github.com/Alphin619/Azure-Sentinel-Detection-Lab/blob/main/detections/T1059-001-powershell.kql)

---

## False Positives

- Legitimate admin automation scripts using -EncodedCommand for special character handling
- Software deployment agents (Intune, SCCM) invoking encoded PowerShell
- IT staff running one-liners with -nop for convenience
- Security tooling or EDR agents spawning PowerShell for telemetry collection

---

## Triage Steps

1. If **EncodedPayload** is populated, decode it immediately using CyberChef (From Base64 — inspect the plaintext command)
2. Check **SubjectUserName** - is this a named user, a service account, or SYSTEM?
3. Correlate with the account discovery detection (T1087.001) on the same Computer in the same 30-minute window; enumeration followed by PowerShell execution is a strong post-compromise indicator
4. Check whether this Computer generated a brute force alert in the preceding hour
5. Determine whether the CommandLine contains an external URL as this indicates a download cradle scenario

---

## Escalation Criteria

- **Escalate to L2 if:** Decoded command contains a download cradle pointing to an external URL, or if the user is breakglass or soc.analyst1, or if this alert appears within 30 minutes of a brute force or account discovery alert on the same host
- **Escalate to IR if:** Confirmed malicious payload decoded, or lateral movement indicators present on other hosts

---

## Containment (L1)

- Do not reboot the VM without L2 instruction as volatile memory evidence would be lost
- Preserve the full CommandLine value and timestamp in the ticket verbatim
- Isolate the VM via NSG deny-all rule if payload is confirmed malicious

---
