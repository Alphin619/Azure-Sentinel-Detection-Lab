# Threat Hunting Hypotheses

## Hypothesis 1 - Slow Credential Spray Evading the Brute Force Threshold

**Hypothesis:** If an attacker tests 1-2 passwords per hour, Detection 1 never fires because the volume never crosses the 5-attempts-in-15-minutes threshold.

**Why this matters:** Every threshold-based detection has a floor. An attacker who knows the threshold will attempt 4 per window indefinitely. This hunt catches persistence across time rather than volume in a single window, directly addressing the static bin() limitation in Detection 1.

**Result in this lab:** No results - the simulated brute force was a burst (25 attempts in ~50 seconds), not a slow spray. This is the expected outcome and confirms the query logic is correct. In a real environment with a patient attacker, this hunt would surface activity that Detection 1 misses entirely.

```kql
SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(24h)
| summarize
    TotalFailures = count(),
    ActiveHours = dcount(bin(TimeGenerated, 1h)),
    TargetAccounts = make_set(TargetUserName, 10),
    SourceIPs = make_set(IpAddress, 5)
    by Computer
| where TotalFailures between (3 .. 15) and ActiveHours >= 4
| extend HuntHypothesis = "Slow credential spray - evading threshold-based detection"
```

---

## Hypothesis 2 - Lateral Movement via RDP to Previously Unseen Hosts

**Hypothesis:** A compromised account used for lateral movement will suddenly appear authenticating to hosts it has never connected to before. Comparing recent RDP activity to a 14-day baseline surfaces this anomaly.

**Why this matters:** This hunt uses behavioural baselining by comparing recent activity to historical normal, which is a core technique in threat hunting and anomaly detection. It catches compromised accounts being used to move laterally without generating any traditional alert.

**Result in this lab:** The query fired and axiomadmin appeared to RDP to a previously unseen host (vm-axiomcorp-ta). This is because the VM was created less than 14 days ago so no baseline exist. Every connection looks new. In a real environment with established baseline data, this would be a proper lateral movement indicator. This result documents a data maturity requirement: the hunt needs at least 14 days of baseline data to be reliable.

```kql
let Baseline =
    SecurityEvent
    | where EventID == 4624 and LogonType == 10
    | where TimeGenerated between (ago(14d) .. ago(1d))
    | summarize NormalTargets = make_set(Computer) by TargetUserName;

let Recent =
    SecurityEvent
    | where EventID == 4624 and LogonType == 10
    | where TimeGenerated > ago(1d)
    | summarize RecentTargets = make_set(Computer) by TargetUserName;

Recent
| join kind=leftouter Baseline on TargetUserName
| extend NewTargets = set_difference(RecentTargets, NormalTargets)
| where array_length(NewTargets) > 0
| project TargetUserName, NewTargets, RecentTargets, NormalTargets
| extend HuntHypothesis = "RDP to previously unseen host — possible lateral movement"
```

---

## Hypothesis 3 - Tier 3 Standard User Accessing Tier 0/1 Restricted Resources

**Hypothesis:** If a Tier 3 standard user account (standard.user1) generates privileged account management events, either the RBAC model has been violated or the account has been compromised and escalated.

**Why this matters:** This hunt makes the detection layer an active validation of the identity tier model. If standard.user1 is generating account management events, something is wrong; either the access control design has been bypassed or the account is compromised.

**Result in this lab:** No results - standard.user1 does not exist in the lab environment. This is the expected outcome. In a real AxiomCorp environment with the full tiered identity model in place, this hunt would fire immediately if a Tier 3 account performed any privileged action.

```kql
SecurityEvent
| where EventID in (4688, 4728, 4732, 4756)
| where SubjectUserName has_any ("standard.user1")
| extend
    HuntHypothesis = "Tier 3 account performing privileged account management activity",
    Severity = "Critical"
| project TimeGenerated, Computer, SubjectUserName, EventID, TargetUserName, HuntHypothesis
```

---
