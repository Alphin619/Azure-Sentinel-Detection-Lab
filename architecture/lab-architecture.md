# Lab Architecture

## <ins>Overview</ins>

This lab is built across six components, each serving the next. The VM generates raw events, the AMA collects them, the DCR routes them, the workspace stores them, Sentinel parses them, and KQL queries surface threats from them.  
<img width="617" height="572" alt="Screenshot 2026-04-21 005747" src="https://github.com/user-attachments/assets/35c29e50-1a94-43b6-9921-32d3fe3feb57" />

## <ins>Why Each Component Exists</ins>

### Windows Server 2022 VM
The VM is the log source. It generates Windows Security Events, the raw material that all five detections query against. Windows Server 2022 was chosen because its Security Event Log maps directly to MITRE ATT&CK technique IDs. EventID 4625 is a failed logon (T1110.001). EventID 4688 is process creation (T1059.001, T1087.001, T1136.001). EventID 4720 is account creation (T1136.001).

### Azure Monitor Agent (AMA)
The AMA is installed on the VM and reads the Data Collection Rule to determine what logs to collect and where to send them. It replaced the legacy Microsoft Monitoring Agent (MMA) which is being retired. The AMA authenticates to Azure using the VM's System-assigned Managed Identity. No stored credentials required.

### Data Collection Rules (DCR)
Two DCRs were created in this lab:
- **dcr-axiomcorp-windows-events** - initial DCR created via Azure Monitor, Central US
- **dcr-sentinel-security-events** - created via the Sentinel Windows Security Events via AMA connector, routes events into the SecurityEvent table

The DCR is the pipeline definition. Without it, the agent is installed but idle.

### Log Analytics Workspace
The workspace (law-axiomcorp-central, Central US) is the centralised log store. It ingests data from the VM via the DCRs, indexes it into queryable tables, and retains it for 30 days on the free tier. All KQL queries run against tables inside this workspace.

### Microsoft Sentinel
Sentinel was added mid-lab when pipeline validation revealed that Windows Security Events were routing to the generic Event table as unparsed XML rather than the SecurityEvent table with named fields. Enabling Sentinel and installing the Windows Security Events via AMA connector resolved this. It populates the SecurityEvent table with properly parsed fields like TargetUserName, CommandLine, and IpAddress that the detection queries depend on.

## Region Notes

| Resource | Region | Reason |
|----------|--------|--------|
| VM | East US | UK South and Central US had quota restrictions on the subscription |
| Log Analytics Workspace | Central US | Created before VM region was finalised |
| DCRs | Central US / subscription-level | Cross-region data collection works without issues |

The cross-region setup (VM in East US, workspace in Central US) functions correctly. Azure Monitor Agent sends data across regions without problems.

## Audit Policy Configuration  
Windows audit policies and the command-line registry key were configured on the VM before the AMA was installed. This ensures that from the moment logs begin flowing, the relevant event IDs are being generated with full detail. See `/infrastructure/audit-policy-config.md` for the exact commands and explanation.

---
