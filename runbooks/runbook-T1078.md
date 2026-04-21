# Detection Runbook: After-Hours Access by Privileged Accounts

**MITRE ATT&CK:** T1078
**Tactic:** Initial Access / Persistence
**Severity:** High (static)
**Data Source:** SecurityEvent, EventID 4624
**Last Reviewed:** 2026

---

## Detection Logic

Fires when the breakglass or soc.analyst1 accounts generate a successful interactive or RDP logon (LogonType 2 or 10) outside Monday-Friday 08:00-18:00. The breakglass account exists only for emergency access and should almost never produce a logon event. soc.analyst1 has Reader scope across the entire Azure subscription. An attacker with this account can enumerate the full environment silently. Any out-of-hours logon from either account warrants immediate investigation regardless of the stated reason.

## KQL Query

See [`/detections/T1078-after-hours-access.kql`](https://github.com/Alphin619/Azure-Sentinel-Detection-Lab/blob/main/detections/T1078-after-hours-access.kql)

---

## False Positives

- A genuine emergency requiring breakglass access outside business hours - this should be documented in the change management system before or immediately after the logon. Cross-reference with open incident tickets.
- An analyst working overtime who has not followed the process for extended-hours access - contact the account holder directly to confirm.
- Automated testing or deployment pipelines misconfigured to run as a named user account rather than a service principal.

---

## Triage Steps

1. Identify the **source IP** - is it an internal corporate range, VPN, or external?
2. Contact the **account holder** directly via phone or Slack (not email) to confirm whether the logon was intentional.
3. Check whether a **change request or incident ticket** exists authorising out-of-hours access for this account at this time.
4. Run the brute force detection (T1110.001) against the same host in the preceding 60 minutes, did failed logon attempts precede the successful one?
5. Query **EventID 4688** on the same Computer after the logon time to identify what processes the account ran after authenticating.
6. Check for **lateral movement** - query EventID 4624 with LogonType 10 from the same TargetUserName across other hosts in the same time window.

---

## Escalation Criteria

- **Escalate to L2 immediately if:** The account holder cannot be reached or denies making the logon, or if post-logon process creation (EventID 4688) shows enumeration or suspicious tooling
- **Escalate to IR if:** Confirmed unauthorised access, or lateral movement indicators present on any other host

---

## Containment (L1)

- Do not disable the breakglass account without L2 authorisation. It may be needed for active incident response
- For soc.analyst1: L1 can request a temporary password reset via the IAM team if the account holder confirms compromise
- Document the logon timestamp, source IP, LogonType, and all post-logon process creation events in the ticket before taking any action

---
