# Audit Policy Configuration

Commands run on the VM to enable Security Event Log generation for the detections.

## Why This Step Exists

Windows does not log everything by default. Audit policies are the switches that tell Windows which categories of events to write to the Security Event Log. Without enabling the relevant subcategories, the following event IDs are never generated, meaning the detection queries have no data to run against:

| EventID | Description | Required For |
|---------|-------------|-------------|
| 4625 | Failed logon | Detection 1 - Brute Force |
| 4624 | Successful logon | Detection 2 - After Hours Access |
| 4688 | Process creation | Detections 3, 4, 5 |
| 4720 | User account created | Detection 5 - Create Account |

## Commands

Run these from an **elevated Command Prompt** (Run as Administrator) on the VM:

```cmd
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /category:"Account Logon" /success:enable /failure:enable
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```
<img width="943" height="611" alt="Screenshot 2026-04-19 151503" src="https://github.com/user-attachments/assets/82957fc4-5c43-4edb-a8d5-8914596cb1f1" />  

**Reboot the VM after running all commands.**

## Why the Registry Key

Even with Process Creation auditing enabled, the `CommandLine` field in EventID 4688 is blank by default for privacy reasons. The registry key switches this on.

Without it:
EventID: 4688
Process: powershell.exe
CommandLine: (blank)

With it:
EventID: 4688
Process: powershell.exe
CommandLine: powershell.exe -EncodedCommand VwByAGkAdABlAC0ATwB1AHQ...

The CommandLine field is what Detections 3 and 4 query against. Without it, both detections are completely blind to what commands were actually executed.

## Note on Account Logon Subcategory

The command `auditpol /set /subcategory:"Account Logon"` may return an error on some Windows Server 2022 builds. Use the category flag instead:

```cmd
auditpol /set /category:"Account Logon" /success:enable /failure:enable
```

This applies the policy to all subcategories within Account Logon and achieves the same result.

---
