# Attack Simulation Guide

Four simulations run against the VM to validate that the detection queries fire against real activity. All simulations use benign commands that mimic attacker behaviour without causing actual harm.

---

## Before Running Simulations

1. Ensure the VM is running and the pipeline is validated (SecurityEvent table returning data)
2. RDP into the VM as axiomadmin
3. Run PowerShell simulations from PowerShell (Run as Administrator)
4. Run CMD simulations from Command Prompt (Run as Administrator)
5. Wait 3-5 minutes after each simulation before running the detection query

---

## Simulation 1 - Brute Force (T1110.001)

**What it simulates:** 25 failed logon attempts against the local SAM database using a non-existent user account with a wrong password.

**Why net use:** The `net use` command attempts to connect to a network share using credentials. With a non-existent user and wrong password, Windows generates EventID 4625 each time. Exactly what a real brute force attempt against the local SAM database looks like in the Security Event Log.

```powershell
1..25 | ForEach-Object {
    Start-Process -FilePath "net.exe" `
        -ArgumentList "use \\localhost\IPC$ /user:fakeuser wrongpassword" `
        -Wait -WindowStyle Hidden
    Start-Sleep -Seconds 2
}
```
<img width="633" height="137" alt="Screenshot 2026-04-19 165815" src="https://github.com/user-attachments/assets/48c4260e-10f6-415e-ac8d-4339de1e7fa8" />
<img width="827" height="814" alt="Screenshot 2026-04-19 170143" src="https://github.com/user-attachments/assets/3ca6d7c2-fab5-4502-8d94-d9d7bd8a9ba4" />

### 🚩**Expected result:** Detection 1 fires with FailedAttempts = 16-25, AccountList = ["fakeuser"], Severity = Medium or High.

---

## Simulation 2 - Suspicious PowerShell (T1059.001)

**What it simulates:** Three PowerShell invocations using flags associated with malicious activity, encoded command execution, execution policy bypass, and WebClient instantiation.

**Why these commands:**
- `-EncodedCommand` - mimics Base64 obfuscation used by malware to hide payloads
- `-ExecutionPolicy Bypass` - mimics unsigned script execution used to run malicious scripts
- `New-Object System.Net.WebClient` - mimics download cradle setup used to fetch payloads from remote URLs

All three commands are harmless - they produce no malicious output.

```powershell
$command = "Write-Output 'AxiomCorp Detection Test'"
$encoded = [Convert]::ToBase64String(
    [System.Text.Encoding]::Unicode.GetBytes($command)
)
powershell.exe -NoProfile -NonInteractive -EncodedCommand $encoded
```

```powershell
powershell.exe -ExecutionPolicy Bypass -Command "Write-Output 'Bypass test'"
```

```powershell
powershell.exe -Command "(New-Object System.Net.WebClient)"
```

<img width="813" height="414" alt="Screenshot 2026-04-19 170352" src="https://github.com/user-attachments/assets/bf0d1a95-2a10-4a5c-a150-604ddf680742" />
<img width="1132" height="651" alt="Screenshot 2026-04-19 170718" src="https://github.com/user-attachments/assets/1c3b21be-4ef5-4567-8f86-e8e1090d0f96" />


### 🚩**Expected result:** Detection 3 fires with three results - High (encoded command), Medium (bypass), Low (WebClient).

---

## Simulation 3 - Account Discovery (T1087.001)

**What it simulates:** Four account enumeration commands run in sequence, mimicking post-compromise reconnaissance.

**Why these commands:** This sequence maps to textbook attacker behaviour after initial access. Establishing who the current user is, what groups exist, what users are on the system, and who is currently logged in.

```cmd
net user
net localgroup administrators
whoami /all
query user
```

<img width="1261" height="961" alt="Screenshot 2026-04-19 170952" src="https://github.com/user-attachments/assets/5e731d83-3b83-403f-8573-d83ac5067330" />
<img width="1127" height="622" alt="Screenshot 2026-04-19 171928" src="https://github.com/user-attachments/assets/6c4bc910-bbc1-4cb6-92b1-84ffa8a8de08" />

### 🚩**Expected result:** Detection 4 fires with CommandCount = 2-4, Severity = Medium or High.

---

## Simulation 4 - Create Local Account (T1136.001)

**What it simulates:** Creating a local user account via command line, mimicking an attacker establishing persistence.

```cmd
net user testpersist Password123! /add
```

<img width="566" height="238" alt="Screenshot 2026-04-19 172139" src="https://github.com/user-attachments/assets/028ce694-0c0d-4378-85af-a7e6b43c70a6" />
<img width="1132" height="553" alt="Screenshot 2026-04-19 172251" src="https://github.com/user-attachments/assets/715052fa-2189-4b8b-ac2d-27e4a2588d3d" />

### 🚩**Expected result:** Detection 5 fires with TargetAccount = testpersist, DetectionMethod = AccountManagementEvent, Severity = High.

**Clean up after simulation:**

```cmd
net user testpersist /delete
```

---

## Evidence

Screenshots of all fired detections are in [`/evidence/`.](https://github.com/Alphin619/Azure-Sentinel-Detection-Lab/blob/main/evidence/all-process.md)
