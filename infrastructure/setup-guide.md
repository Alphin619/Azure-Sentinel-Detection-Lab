# Infrastructure Setup Guide

Step-by-step guide to reproduce this lab from scratch.

## Prerequisites

- Microsoft Azure account (Pay-as-you-go) free trial has vCPU quota restrictions)
- Basic familiarity with the Azure Portal

---

## Step 1 - Create a Resource Group

1. Search **Resource Groups** in the Azure Portal
2. Click **Create**
3. Name: `rg-axiomcorp-detection-lab`
4. Region: East US
5. Click **Review + Create -> Create**
 
<img width="483" height="364" alt="Screenshot 2026-04-18 161644" src="https://github.com/user-attachments/assets/3705082a-ff1a-4e6b-9bb2-fc2f53ea6bfd" />

**Why:** A resource group is a logical container. Everything in this lab lives inside it. When finished, deleting the resource group removes all resources and stops all billing in one action.

---

## Step 2 - Create a Log Analytics Workspace

1. Search **Log Analytics Workspaces**
2. Click **Create**
3. Name: `law-axiomcorp-central`
4. Resource Group: `rg-axiomcorp-detection-lab`
5. Region: Central US
6. Pricing tier: Pay-as-you-go (first 5GB/day free)
7. Click **Review + Create -> Create**

<img width="1622" height="424" alt="Screenshot 2026-04-18 162115" src="https://github.com/user-attachments/assets/e807287a-d5b4-418a-a3eb-12b505d5cd9e" />

**Why:** The workspace is the centralised log store. All KQL queries run against tables inside it. Microsoft Sentinel is built on top of Log Analytics and the workspace is the data layer everything else depends on.

---

## Step 3 - Deploy the Windows VM

1. Search **Virtual Machines -> Create -> Azure Virtual Machine**
2. Settings:
   - Name: `vm-axiomcorp-target`
   - Resource Group: `rg-axiomcorp-detection-lab`
   - Region: East US
   - Image: Windows Server 2022 Datacenter: Azure Edition - x64 Gen2
   - Size: Standard_D2s_v3
   - Username: `axiomadmin`
   - Password: strong password 
   - Inbound ports: RDP 3389
3. Under **Management tab**: enable **System-assigned managed identity**
4. Click **Review + Create -> Create**

<img width="1610" height="910" alt="Screenshot 2026-04-19 150307" src="https://github.com/user-attachments/assets/576f9a05-2e6d-4473-af61-4f242fe63e3f" />

**Why the managed identity:** The Azure Monitor Agent uses the VM's managed identity to authenticate to Azure, so no stored credentials required.

---

## Step 4 - Configure Audit Policies on the VM

RDP into the VM and run the commands in `/infrastructure/audit-policy-config.md` from an elevated Command Prompt.

Reboot the VM after running all commands.

<img width="943" height="611" alt="Screenshot 2026-04-19 151503" src="https://github.com/user-attachments/assets/84c7cd27-d013-4674-93c1-2d3eaae2458a" />

**Why:** Windows does not log everything by default. Audit policies tell Windows which events to write to the Security Event Log. Without these, the detections have no data to query against.

---

## Step 5 - Enable Microsoft Sentinel

1. Search **Microsoft Sentinel**
2. Click **Create**
3. Select `law-axiomcorp-central`
4. Click **Add**

<img width="1860" height="872" alt="Screenshot 2026-04-19 163104" src="https://github.com/user-attachments/assets/116bb025-f73b-4d28-892f-108aba7ca9e8" />

**Why:** Sentinel unlocks the SecurityEvent table with properly parsed fields. Without it, Windows Security Events route to the generic Event table as unparsed XML.

---

## Step 6 - Install Windows Security Events Connector

1. In Sentinel, go to **Content Hub**
2. Search **Windows Security Events**
3. Select **Windows Security Events** by Microsoft
4. Click **Install**
5. Go to **Data Connectors > Windows Security Events via AMA**
6. Click **Open connector page > Create data collection rule**
7. Add `vm-axiomcorp-target` as the resource
8. Select **All Security Events**
9. Click **Review + Create > Create**

<img width="1466" height="823" alt="Screenshot 2026-04-19 163200" src="https://github.com/user-attachments/assets/664f1d08-eef8-4778-b0c4-2c7fde765572" />
<img width="554" height="729" alt="Screenshot 2026-04-19 163348" src="https://github.com/user-attachments/assets/5a80b520-d350-4efb-8a0d-79968fd7c8dc" />
<img width="1602" height="711" alt="Screenshot 2026-04-19 163621" src="https://github.com/user-attachments/assets/dd031075-afaa-4ed8-ab40-c183caec38df" />

**Why:** This creates the DCR that routes events into the SecurityEvent table and installs/configures the Azure Monitor Agent on the VM automatically.

---

## Step 7 - Validate the Pipeline

Wait 10-15 minutes then run this in **Sentinel -> Logs**:

```kql
SecurityEvent
| summarize count () by EventID
| order by count_ desc
```
<img width="359" height="318" alt="Screenshot 2026-04-19 165133" src="https://github.com/user-attachments/assets/0a4d1131-1297-45f0-a542-349f20ec658a" />

You should see EventIDs including 4624, 4688, and 4673 with non-zero counts. If the SecurityEvent table does not exist yet, wait longer, it can take up to 30 minutes on first setup.

---

## Cost Notes

- **VM:** Standard_D2s_v3 costs approximately $0.21/hour. Stop (deallocate) the VM when not in use.
- **Log Analytics:** First 5GB/day ingestion is free. This lab generates well under 1GB/day.
- **Sentinel:** Free for the first 31 days on a new workspace.
- **Total lab cost:** Under £5 if the VM is stopped when not in use and the resource group is deleted when finished.

## Cleanup

When finished, delete the entire resource group:

1. Go to **Resource Groups -> rg-axiomcorp-detection-lab**
2. Click **Delete resource group**
3. Type the name to confirm
4. Click **Delete**

This removes all resources and stops all billing.

> NOTE: The information provided and the information in the pictures looks different because, I had to change somethings around because of free tier issues. Information written up are the updated working information.
---
