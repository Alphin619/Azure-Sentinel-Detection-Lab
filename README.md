# Azure Sentinel Detection Engineering Lab

A detection engineering lab built on **Microsoft Azure** and **Microsoft Sentinel**, demonstrating end-to-end detection development across five MITRE ATT&CK techniques. This project covers infrastructure deployment, log pipeline validation, KQL detection authoring, runbook documentation, attack simulation, and threat hunting. The full workflow of a SOC detection engineer.

---

## 📋 Project Overview

| Item | Detail |
|------|--------|
| **Cloud Platform** | Microsoft Azure |
| **SIEM** | Microsoft Sentinel |
| **Log Source** | Windows Security Events (`SecurityEvent` table) |
| **Detection Language** | KQL (Kusto Query Language) |
| **VM** | Windows Server 2022 Datacenter, Azure Edition |
| **Region** | East US |
| **MITRE Techniques** | T1110.001 · T1078 · T1059.001 · T1087.001 · T1136.001 |

---

## 🏗️ ArchitectureWindows Server 2022 VM (East US)  

<img width="617" height="572" alt="Screenshot 2026-04-21 005747" src="https://github.com/user-attachments/assets/35c29e50-1a94-43b6-9921-32d3fe3feb57" />


**Why this architecture:** The VM generates raw Windows Security Events. The Azure Monitor Agent collects those events and streams them to the Log Analytics Workspace via a Data Collection Rule; a pipeline configuration that defines what to collect and where to send it. Microsoft Sentinel sits on top of the workspace and unlocks the `SecurityEvent` table with properly parsed fields like `TargetUserName` and `CommandLine`, which the KQL detections query against. Without Sentinel, events route to the generic `Event` table as unparsed XML. Unusable for clean detection queries.

---

## 🖥️ Infrastructure Built

### <ins>Resources Deployed</ins>

| Resource | Name | Detail |
|----------|------|--------|
| **Resource Group** | `rg-axiomcorp-detection-lab` | Container for all lab resources |
| **Virtual Machine** | `vm-axiomcorp-target` | Standard D2s v3, Windows Server 2022, East US |
| **Log Analytics Workspace** | `law-axiomcorp-central` | Central US, Pay-as-you-go |
| **SIEM** | Microsoft Sentinel | Enabled on law-axiomcorp-central |
| **Data Collection Rules** | `dcr-axiomcorp-windows-events` + `dcr-sentinel-security-events` | Security + System event logs |
| **Monitoring Agent** | Azure Monitor Agent | v1.41.0.0, installed via DCR |

### Audit Policy Configuration

Windows does not log everything by default. The following audit policies were enabled on the VM to generate the Security Event Log entries the detections depend on:

`auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable`  
`auditpol /set /subcategory:"Logon" /success:enable /failure:enable`  
`auditpol /set /category:"Account Logon" /success:enable /failure:enable`  
`auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable`  
`reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f`  
<img width="943" height="611" alt="Screenshot 2026-04-19 151503" src="https://github.com/user-attachments/assets/3d507b20-7b2c-4b5f-9dce-c91a556dc116" />

**Why the registry key matters:** Even with Process Creation auditing enabled, the `CommandLine` field in EventID 4688 is blank by default for privacy reasons. This registry key switches it on, the difference between seeing that `powershell.exe` ran versus seeing the actual command it executed, including encoded payloads and suspicious flags.

---
