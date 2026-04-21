# Detection Runbook: Create Account - Local Account

**MITRE ATT&CK:** T1136.001
**Tactic:** Persistence
**Severity:** High (static)
**Data Source:** SecurityEvent, EventID 4688 and EventID 4720
**Last Reviewed:** 2026

---

## Detection Logic

Detects local account creation via two separate signals unified with a union operator: process creation events showing net user /add or New-LocalUser commands (EventID 4688), and the Windows account management event for user account creation (EventID 4720). Using both signals ensures coverage regardless of whether the attacker uses command-line tooling or Windows API calls directly. The DetectionMethod field identifies which signal fired, narrowing the investigation path immediately.

In a managed enterprise environment, local account creation outside of a provisioning workflow is almost never legitimate. A new local account that did not originate from the IAM system is either a misconfiguration or an attacker establishing persistence.

## KQL Query

See [`/detections/T1136-001-create-local-account.kql`](https://github.com/Alphin619/Azure-Sentinel-Detection-Lab/blob/main/detections/T1136-001-create-local-account.kql)

---

## False Positives

- A local administrator manually creating a service account outside the IAM workflow - flag regardless and review the account
- An automated deployment script creating a local account as part of application setup - verify against the change management record for the deployment
- A developer creating a test account on a non-production host they manage directly

---

## Triage Steps

1. Identify **TargetAccount** - is this a recognisable account name pattern, or does it appear randomised or generic (e.g. svc_x, user1, admin2)? Randomised names suggest automated attacker tooling.
2. Check **SubjectUserName** - who created the account? Was it a named admin, SYSTEM, or the same account that triggered a preceding alert?
3. Check **DetectionMethod** - if ProcessCreation, review the full CommandLine. If AccountManagementEvent only, the account was created via API with no visible command, higher suspicion.
4. Query EventID 4732 and 4728 after the creation time - was the new account immediately added to a privileged group such as Administrators or Remote Desktop Users?
5. Correlate with preceding alerts on the same host - discovery activity or PowerShell execution in the prior 30 minutes significantly elevates severity.
6. Determine whether the account has been used - query EventID 4624 with TargetUserName matching the new account name.

---

## Escalation Criteria

- **Escalate to L2 immediately if:** The new account was added to Administrators or Remote Desktop Users, or if the account has already generated a successful logon (EventID 4624), or if preceding alerts suggest an active compromise chain
- **Escalate to IR if:** Confirmed attacker persistence - new account created and used for lateral movement or further activity

---

## Containment (L1)

- Disable the account immediately: `net user [accountname] /active:no` - this preserves forensic evidence while preventing further use
- Do NOT delete the account until L2 instructs - deletion destroys evidence
- Document the account name, creation timestamp, SubjectUserName, and whether the account was added to any groups
- If the account has already been used for logon, treat as active compromise and escalate to IR without waiting for L2 triage

---
