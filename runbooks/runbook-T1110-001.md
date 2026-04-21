# Detection Runbook: Brute Force - Password Guessing

**MITRE ATT&CK:** T1110.001
**Tactic:** Credential Access
**Severity:** Low / Medium / High (dynamic)
**Data Source:** SecurityEvent, EventID 4625
**Last Reviewed:** 2026

---

## Detection Logic

Fires when 5 or more failed logon attempts occur against the same host within a 15-minute static window. Severity is dynamic based on volume from Low for 5-9 attempts, Medium for 10-19, High for 20+. In the AxiomCorp environment, any failed logon against the breakglass or soc.analyst1 accounts should be treated as High regardless of volume due to the blast radius of those accounts.

## KQL Query

See `/detections/T1110-001-brute-force.kql`

---

## False Positives

- Service accounts with expired or rotated passwords causing repeated failures
- A user locking themselves out after a password change
- Scheduled tasks running with stale credentials
- Admin RDP sessions entering the wrong password initially from a new device

---

## Triage Steps

1. Check **SourceIPs** - is the source internal, external, or a known admin range?
2. Check **AccountList** - are any Tier 0 or Tier 1 accounts being targeted?
3. Run the after-hours access detection (T1078) for the same accounts. Did a successful logon follow the failures within 30 minutes?
4. Query EventID 4624 from the same source IP in the same time window. Did a successful logon occur after the failures?
5. Confirm whether the target host is internet-facing and whether RDP port 3389 is exposed.

---

## Escalation Criteria

- **Escalate to L2 if:** 20+ attempts, or any Tier 0/Tier 1 account is targeted, or a successful logon (EventID 4624) follows within 30 minutes from the same source IP
- **Escalate to IR if:** Confirmed successful authentication following brute force activity

---

## Containment (L1)

- Block the source IP at NSG level if external and no business justification
- Notify the account owner if a named user account is targeted
- Document source IP, account list, time window, and attempt count in the ticket

---
