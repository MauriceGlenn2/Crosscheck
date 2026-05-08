# Threat Hunt: CROSSCHECK

## Executive Summary

This document summarizes the threat hunting investigation conducted on a corporate environment following unauthorized access and sensitive data exposure by an unknown threat actor. The investigation focused on a compromised user account (`5y51-d3p7`) operating across two endpoints, with activity spanning employee compensation data, performance reviews, and candidate scorecards.

The investigation covered **3 days of attacker dwell time** (December 1–4, 2025) and was conducted across **22 flags** of malicious activity. The attack chain included initial remote access, PowerShell-based tooling, data staging, persistence mechanisms, and outbound exfiltration attempts targeting sensitive HR and finance artifacts.

---

## Threat Actor Profile

| Attribute | Detail |
|-----------|--------|
| Compromised Account | 5y51-d3p7 |
| Initial Access Vector | Remote session via 49.147.192.23 |
| Attacker Machine | M1-ADMIN → M2-ADMIN |
| Operation Type | Insider Threat / Unauthorized Data Access |
| Attack Model | Data Staging + Exfiltration Attempt |
| Primary Targets | Bonus matrices, performance reviews, candidate scorecards |

---

## Investigation Overview

### Phase 1 – Initial Access & Reconnaissance (December 1–3, 2025)

**Target System:** sys1-dept — Employee Workstation

**Summary:** The attacker established remote access to `sys1-dept` using account `5y51-d3p7` from IP `49.147.192.23` via `M1-ADMIN`. A support-themed PowerShell script (`PayrollSupportTool.ps1`) was executed, followed by immediate system reconnaissance. Persistence was established via both a registry Run key and a scheduled task.

| Metric | Value |
|--------|-------|
| Flags Investigated | 1–9 |
| Initial Access | Remote session from 49.147.192.23 |
| Compromised Account | 5y51-d3p7 |
| Persistence | Registry Run key + Scheduled Task (BonusReviewAssist) |
| First Recon Command | `whoami.exe /all` |

**Key Findings:**
- Remote logon from `M1-ADMIN` (192.168.0.110) at `2025-12-01T10:23`
- `PayrollSupportTool.ps1` executed with `-ExecutionPolicy Bypass`
- Recon initiated with `whoami /all` on `2025-12-03T06:12`
- Registry Run key established at `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- Scheduled task `BonusReviewAssist` created for daily persistence
- Staging directory: `C:\Users\5y51-D3p7\Documents\`

---

### Phase 2 – Sensitive Data Access & Staging (December 3, 2025)

**Target System:** sys1-dept — Employee Workstation

**Summary:** The attacker accessed sensitive HR artifacts including bonus matrices, performance reviews, and candidate scorecards across multiple remote session contexts (`M1-ADMIN`, `YE-HELPDESKTECH`, `YE-HRPLANNER`). Data was staged into ZIP archives and outbound connectivity was tested. Local event logs were cleared to reduce forensic visibility.

| Metric | Value |
|--------|-------|
| Flags Investigated | 10–16 |
| Remote Sessions | M1-ADMIN, YE-HELPDESKTECH, YE-HRPLANNER |
| Sensitive Files Accessed | BonusMatrix_Draft_v3.xlsx, BonusMatrix_Q4_Approved.xlsx, Review_JavierR, Review_CynthiaM, Scorecard_JavierR |
| Archive Created | export_stage.zip, Q4Candidate_Pack.zip |
| Log Clearing | wevtutil cl Microsoft-Windows-PowerShell/Operational |

**Key Findings:**
- `BonusMatrix_Draft_v3.xlsx` accessed via `notepad.exe` by `M1-ADMIN` and `YE-HRPLANNER`
- `YE-HELPDESKTECH` accessed performance reviews from `C:\CorpHR\PerformanceReviews\` (unintentional cross-department access)
- `BonusMatrix_Q4_Approved.xlsx` accessed via `SensitiveFileRead` event (file accessed over network share, no local copy created)
- `export_stage.zip` created at `C:\Users\5y51-D3p7\Documents\` at `2025-12-03T06:27`
- `Q4Candidate_Pack.zip` created at `C:\Users\5y51-D3p7\Documents\Q4Candidate_Pack.zip` at `2025-12-03T07:26`
- Outbound connectivity tested via PowerShell at `2025-12-03T06:27:31`
- Event log cleared at `2025-12-03T08:18:58`

---

### Phase 3 – Second Endpoint Compromise (December 4, 2025)

**Target System:** main1-srvr — Internal Server

**Summary:** Activity pivoted to a second endpoint (`main1-srvr`) where the approved bonus artifact was accessed again by a new attacker machine (`M2-ADMIN`) and a Finance department session (`YE-FINANCEREVIE`). A staging directory was created, archives were dropped, and a final outbound connection was attempted.

| Metric | Value |
|--------|-------|
| Flags Investigated | 17–22 |
| Remote Sessions | M2-ADMIN, YE-FINANCEREVIE |
| Sensitive Files Accessed | BonusMatrix_Q4_Approved.xlsx, Scorecard_JavierR |
| Staging Directory | C:\Users\Main1-Srvr\Documents\InternalReferences\ArchiveBundles\ |
| Archive Created | YearEnd_ReviewPackage_2025.zip |
| Outbound IP | 54.83.21.156 (httpbin.org) |

**Key Findings:**
- `BonusMatrix_Q4_Approved.xlsx` accessed by `M2-ADMIN` at `2025-12-04T02:27` and `02:32`
- Scorecard access confirmed via `YE-FINANCEREVIE` remote session
- Archive `YearEnd_ReviewPackage_2025.zip` created in staging directory at `2025-12-04T03:15`
- Final outbound connection to `54.83.21.156` at `2025-12-04T03:15:48`

---

## Complete Attack Path

```
                            CROSSCHECK Attack Flow
                            ======================

    [EXTERNAL]                                          [INTERNAL SESSIONS]
        │                                                        │
        │ Remote Session (49.147.192.23)                         │
        ▼                                                        │
┌─────────────────┐                                   ┌─────────────────┐
│   sys1-dept     │◀──── M1-ADMIN (192.168.0.110) ────│    M1-ADMIN     │
│  (Beachhead)    │◀──── YE-HELPDESKTECH               │    M2-ADMIN     │
│                 │◀──── YE-HRPLANNER                  │  YE-HELPDESKTECH│
│  • Dec 1–3      │                                   │  YE-HRPLANNER   │
│  • PayrollSup.. │                                   │  YE-FINANCEREVIE│
│  • Recon        │                                   └─────────────────┘
│  • Persistence  │
│  • Data Staging │
└────────┬────────┘
         │
         │ Lateral Movement / Network Share Access
         ▼
┌─────────────────┐
│   main1-srvr    │◀──── M2-ADMIN
│  (2nd Endpoint) │◀──── YE-FINANCEREVIE
│                 │
│  • Dec 4        │
│  • Bonus access │
│  • Scorecard    │
│  • Archive/Exfil│
└─────────────────┘
```

---

## Flag Findings

### Flag 1 – Initial Endpoint Association

**Objective:** Determine which endpoint first shows activity tied to the user context involved in the chain.

```kusto
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-01T00:00:00) .. datetime(2026-01-01T20:00:00))
| where AccountName == "5y51-d3p7"
| summarize FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated), Count = count() by DeviceName
| order by FirstSeen asc
```

**What This Reveals:** Identifies the device associated with account `5y51-d3p7` and the earliest observed activity timestamp.

**Answer:** `sys1-dept`

**MITRE ATT&CK:** T1078 – Valid Accounts

---

### Flag 2 – Remote Session Source Attribution

**Objective:** Identify the remote session source IP tied to the initiating access on the first endpoint.

```kusto
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-01T00:00:00) .. datetime(2026-01-01T20:00:00))
| where AccountName == "5y51-d3p7"
| where DeviceName == "sys1-dept"
| where isnotempty(InitiatingProcessRemoteSessionIP)
| project TimeGenerated, InitiatingProcessRemoteSessionIP
```

**What This Reveals:** Surfaces the source IP of the remote session used for initial access, confirming external origin.

**Answer:** `192.168.0.110` — `2025-12-01T03:13:34.3476301Z`

**MITRE ATT&CK:** T1021.001 – Remote Services: Remote Desktop Protocol

---

### Flag 3 – Support Script Execution Confirmation

**Objective:** Confirm execution of a support-themed PowerShell script from a user-accessible directory.

```kusto
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-01T00:00:00) .. datetime(2026-01-01T20:00:00))
| where AccountName == "5y51-d3p7"
| where DeviceName == "sys1-dept"
| where InitiatingProcessCommandLine contains "powershell.exe"
| where ProcessCommandLine contains @"\downloads"
```

**What This Reveals:** Confirms a PowerShell script was launched from the Downloads directory using execution policy bypass, consistent with attacker-dropped tooling.

**Answer:** `"powershell.exe" -ExecutionPolicy Bypass -File C:\Users\5y51-D3p7\Downloads\PayrollSupportTool.ps1`

**MITRE ATT&CK:** T1059.001 – Command and Scripting Interpreter: PowerShell

---

### Flag 4 – System Reconnaissance Initiation

**Objective:** Identify the first reconnaissance action used to gather host and user context.

```kusto
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-01T00:00:00) .. datetime(2026-01-01T20:00:00))
| where AccountName == "5y51-d3p7"
| where DeviceName == "sys1-dept"
| where ProcessCommandLine has_any ("ipconfig", "net", "user", "arp", "nslookup", "whoami")
| project TimeGenerated, AccountName, FileName, ProcessCommandLine
```

**What This Reveals:** Identifies the opening recon move — `whoami /all` — revealing the attacker immediately profiled the compromised account's privileges and group memberships.

**Answer:** `"whoami.exe" /all` — `2025-12-03T06:12:03.7890991Z`

**MITRE ATT&CK:** T1033 – System Owner/User Discovery

---

### Flag 5 – Sensitive Bonus-Related File Exposure

**Objective:** Identify the first sensitive year-end bonus-related file that was accessed during exploration.

```kusto
DeviceFileEvents
| where TimeGenerated between (datetime(2025-12-01T00:00:00) .. datetime(2026-01-01T20:00:00))
| where DeviceName == "sys1-dept"
| where FileName contains "bonus"
```

**What This Reveals:** Confirms the attacker discovered and accessed a draft bonus matrix file during the data discovery phase.

**Answer:** `BonusMatrix_Draft_v3.xlsx` — `2025-12-03T07:24:42.9603372Z`

**MITRE ATT&CK:** T1083 – File and Directory Discovery

---

### Flag 6 – Data Staging Activity Confirmation

**Objective:** Confirm that sensitive data was prepared for movement by staging into an export/archive output.

```kusto
DeviceFileEvents
| where TimeGenerated between (datetime(2025-10-01T00:00:00) .. datetime(2026-01-01T20:00:00))
| where DeviceName == "sys1-dept"
| where ActionType == "FileCreated"
| where FileName has_any (".rar", ".zip", ".7z", ".tar", ".gz", ".cab")
| project TimeGenerated, DeviceName, FileName, FolderPath, 
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessId, InitiatingProcessUniqueId
| order by TimeGenerated asc
```

**What This Reveals:** Identifies the creation of `export_stage.zip` as the staging artifact, and extracts the unique process ID of the initiating process for correlation.

**Answer:** `2533274790396713` — `C:\Users\5y51-D3p7\Documents\export_stage.zip` — `2025-12-03T06:27:10.6828355Z`

**MITRE ATT&CK:** T1560.001 – Archive Collected Data: Archive via Utility

---

### Flag 7 – Outbound Connectivity Test

**Objective:** Confirm that outbound access was tested prior to any attempted transfer.

```kusto
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-12-01T00:00:00) .. datetime(2025-12-04T20:00:00))
| where DeviceName == "sys1-dept"
| where InitiatingProcessAccountName contains "5y51-d3p7"
| where InitiatingProcessCommandLine has_any ("curl", "wget", "http", "Invoke-WebRequest", "iwr", "curl.exe")
    or InitiatingProcessFileName in~ ("curl.exe", "powershell.exe", "pwsh.exe")
| project TimeGenerated, ActionType, InitiatingProcessCommandLine, RemoteIP, RemoteUrl
```

**What This Reveals:** Confirms the attacker tested outbound connectivity via PowerShell before attempting data exfiltration, a common pre-exfil validation step.

**Answer:** `2025-12-03T06:27:31.1857946Z`

**MITRE ATT&CK:** T1071.001 – Application Layer Protocol: Web Protocols

---

### Flag 8 – Registry-Based Persistence

**Objective:** Identify evidence of persistence established via a user Run key.

```kusto
DeviceRegistryEvents
| where TimeGenerated between (datetime(2025-12-01T00:00:00) .. datetime(2025-12-04T20:00:00))
| where DeviceName == "sys1-dept"
| where InitiatingProcessAccountName == "5y51-d3p7"
| where ActionType has_any ("RegistryValueSet", "RegistryKeyCreated")
```

**What This Reveals:** Confirms persistence via the HKCU Run key, ensuring the attacker's tooling would survive user logon cycles.

**Answer:** `HKEY_CURRENT_USER\S-1-5-21-805396643-3920266184-3816603331-500\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` — `2025-12-03T06:27:59.603716Z`

**MITRE ATT&CK:** T1547.001 – Boot or Logon Autostart Execution: Registry Run Keys

---

### Flag 9 – Scheduled Task Persistence

**Objective:** Confirm a scheduled task was created or used to automate recurring execution.

```kusto
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-01T00:00:00) .. datetime(2025-12-04T20:00:00))
| where DeviceName == "sys1-dept"
| where InitiatingProcessAccountName contains "5y51-d3p7"
| where InitiatingProcessCommandLine has_any ("curl", "wget", "http", "Invoke-WebRequest", "iwr", "curl.exe")
    or InitiatingProcessFileName in~ ("curl.exe", "powershell.exe", "pwsh.exe")
| project TimeGenerated, ActionType, InitiatingProcessCommandLine, ProcessCommandLine
```

**What This Reveals:** Reveals a daily scheduled task (`BonusReviewAssist`) created to execute `PayrollSupportTool.ps1` — social engineering naming designed to evade casual review.

**Answer:** `BonusReviewAssist` — `2025-12-03T06:28:28.1020219Z`

**MITRE ATT&CK:** T1053.005 – Scheduled Task/Job: Scheduled Task

---

### Flag 10 – Secondary Access to Employee Scorecard Artifact

**Objective:** Identify evidence that a different remote session context accessed an employee-related scorecard file.

```kusto
DeviceFileEvents
| where TimeGenerated between (datetime(2025-12-01T00:00:00) .. datetime(2026-01-01T20:00:00))
| where DeviceName == "sys1-dept"
| where FileName has_any ("scorecard", "review")
| project TimeGenerated, FileName, FolderPath, ActionType,
          InitiatingProcessAccountName,
          InitiatingProcessRemoteSessionDeviceName,
          InitiatingProcessRemoteSessionIP
| order by TimeGenerated asc
```

**What This Reveals:** Surfaces a second remote session (`YE-HELPDESKTECH`) accessing employee scorecard files, indicating multiple department sessions were involved in the chain.

**Answer:** `YE-HELPDESKTECH`

**MITRE ATT&CK:** T1039 – Data from Network Shared Drive

---

### Flag 11 – Bonus Matrix Activity by a New Remote Session Context

**Objective:** Identify another remote session device name associated with bonus payout related activities.

```kusto
DeviceFileEvents
| where TimeGenerated between (datetime(2025-12-01T00:00:00) .. datetime(2026-01-01T20:00:00))
| where DeviceName == "sys1-dept"
| where InitiatingProcessRemoteSessionDeviceName != "M1-ADMIN"
| where InitiatingProcessRemoteSessionDeviceName != "YE-HELPDESKTECH"
| where isnotempty(InitiatingProcessRemoteSessionDeviceName)
| project TimeGenerated, FileName, FolderPath, ActionType,
          InitiatingProcessAccountName,
          InitiatingProcessRemoteSessionDeviceName,
          InitiatingProcessRemoteSessionIP
| order by TimeGenerated asc
```

**What This Reveals:** Identifies a third remote session (`YE-HRPLANNER`) interacting with bonus-related files, broadening the scope of departments involved.

**Answer:** `YE-HRPLANNER`

**MITRE ATT&CK:** T1039 – Data from Network Shared Drive

---

### Flag 12 – Performance Review Access Validation

**Objective:** Confirm access to employee performance review material through user-level tooling.

```kusto
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-03T06:00:00) .. datetime(2025-12-03T08:00:00))
| where DeviceName == "sys1-dept"
| where ProcessCommandLine has_any (
    "Review_JavierR", "Review_CynthiaM", 
    "PerformanceReview", "CorpHR", "HR")
| project TimeGenerated, FileName, ProcessCommandLine,
          InitiatingProcessFileName,
          InitiatingProcessRemoteSessionDeviceName,
          AccountName
| order by TimeGenerated asc
```

**What This Reveals:** Confirms `YE-HRPLANNER` unintentionally accessed performance review files (`Review_JavierR.lnk`, `Review_CynthiaM.lnk`) via `powershell.exe` spawning `notepad.exe` — cross-department access to restricted HR records.

**Answer:** `2025-12-03T07:25:15.6288106Z`

**MITRE ATT&CK:** T1083 – File and Directory Discovery

---

### Flag 13 – Approved/Final Bonus Artifact Access

**Objective:** Confirm access to a finalized year-end bonus artifact with sensitive-read classification.

```kusto
// Step 1: Enumerate available ActionTypes on this device
DeviceEvents
| where TimeGenerated between (datetime(2025-12-01T00:00:00) .. datetime(2026-01-01T00:00:00))
| where DeviceName == "sys1-dept"
| summarize count() by ActionType
| order by count_ desc

// Step 2: Hunt for SensitiveFileRead events
DeviceEvents
| where TimeGenerated between (datetime(2025-12-01T00:00:00) .. datetime(2026-01-01T00:00:00))
| where DeviceName == "sys1-dept"
| where ActionType == "SensitiveFileRead"
| project TimeGenerated, ActionType, FileName, AdditionalFields,
          InitiatingProcessRemoteSessionDeviceName,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine,
          AccountName
| order by TimeGenerated asc
```

**What This Reveals:** `SensitiveFileRead` events in `DeviceEvents` (not `DeviceFileEvents`) capture file reads that bypass normal file creation telemetry — critical for detecting network share access where no local copy is created. `BonusMatrix_Q4_Approved.xlsx` was accessed over a file share with no local download.

**Answer:** `2025-12-03T07:25:39.1653621Z` — `BonusMatrix_Q4_Approved.xlsx`

**MITRE ATT&CK:** T1039 – Data from Network Shared Drive

---

### Flag 14 – Candidate Archive Creation Location

**Objective:** Identify where a suspicious candidate-related archive was created.

```kusto
DeviceFileEvents
| where TimeGenerated between (datetime(2025-12-01T00:00:00) .. datetime(2026-01-01T20:00:00))
| where DeviceName == "sys1-dept"
| where ActionType == "FileCreated"
| where FileName has_any (".zip", ".rar", ".7z")
| project TimeGenerated, FileName, FolderPath, ActionType,
          InitiatingProcessRemoteSessionDeviceName
| order by TimeGenerated asc
```

**What This Reveals:** Confirms a second archive (`Q4Candidate_Pack.zip`) was created in the Documents directory, indicating staged candidate data was prepared for exfiltration.

**Answer:** `C:\Users\5y51-D3p7\Documents\Q4Candidate_Pack.zip` — `2025-12-03T07:26:03.9765516Z`

**MITRE ATT&CK:** T1560.001 – Archive Collected Data: Archive via Utility

---

### Flag 15 – Outbound Transfer Attempt Timestamp

**Objective:** Confirm an outbound transfer attempt occurred after staging activity.

```kusto
DeviceNetworkEvents
| where DeviceName == "sys1-dept"
| where TimeGenerated between (datetime(2025-12-01T00:00:00) .. datetime(2026-01-01T00:00:00))
| where InitiatingProcessCommandLine has_any ("cmd.exe", "powershell.exe")
```

**What This Reveals:** Confirms an outbound network connection was initiated via PowerShell shortly after archive creation, consistent with a data transfer attempt.

**Answer:** `2025-12-03T07:26:28.5959592Z`

**MITRE ATT&CK:** T1567 – Exfiltration Over Web Service

---

### Flag 16 – Local Log Clearing Attempt Evidence

**Objective:** Identify command-line evidence of attempted local log clearing.

```kusto
DeviceProcessEvents
| where DeviceName == "sys1-dept"
| where TimeGenerated between (datetime(2025-12-01T00:00:00) .. datetime(2026-01-01T00:00:00))
| where ProcessCommandLine has_any ("wevtutil", "Clear-EventLog", "ConsoleHost_history.txt")
| where AccountDomain != "nt authority"
| where AccountName != "system"
| project TimeGenerated, ProcessCommandLine
```

**What This Reveals:** Confirms the attacker used `wevtutil` to clear the PowerShell Operational log — a targeted anti-forensics action to remove evidence of PowerShell-based activity.

**Answer:** `"wevtutil.exe" cl Microsoft-Windows-PowerShell/Operational` — `2025-12-03T08:18:58.7834148Z`

**MITRE ATT&CK:** T1070.001 – Indicator Removal: Clear Windows Event Logs

---

### Flag 17 – Second Endpoint Scope Confirmation

**Objective:** Identify the second endpoint involved in the chain based on similar telemetry patterns.

```kusto
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-01T00:00:00) .. datetime(2026-01-01T00:00:00))
| where ProcessCommandLine has_any ("BonusMatrix", "Bonus2025", "BonusFinal", "Bonus_Final", "BonusApproved")
| where ProcessCommandLine !has "Draft"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine,
          InitiatingProcessRemoteSessionDeviceName,
          AccountName, ProcessRemoteSessionDeviceName
| order by TimeGenerated asc
```

**What This Reveals:** Drops the DeviceName filter to hunt tenant-wide, revealing `main1-srvr` as a second compromised endpoint with the approved bonus file accessed via `YE-FINANCEREVIE`.

**Answer:** `main1-srvr`

**MITRE ATT&CK:** T1021.001 – Remote Services: Remote Desktop Protocol

---

### Flag 18 – Approved Bonus Artifact Access on Second Endpoint

**Objective:** Confirm the approved bonus artifact is accessed again on the second endpoint.

```kusto
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-04T00:00:00) .. datetime(2026-01-01T00:00:00))
| where DeviceName == "main1-srvr"
| where ProcessCommandLine has "BonusMatrix_Q4_Approved"
| project TimeGenerated, ProcessCreationTime, FileName, ProcessCommandLine,
          InitiatingProcessRemoteSessionDeviceName,
          AccountName
| order by TimeGenerated asc
```

**What This Reveals:** Confirms `BonusMatrix_Q4_Approved.xlsx` was accessed on `main1-srvr` — the `ProcessCreationTime` field (not `TimeGenerated`) is the flag answer, reflecting when the initiating process was spawned.

**Answer:** `2025-12-04T03:11:58.6027696Z`

**MITRE ATT&CK:** T1039 – Data from Network Shared Drive

---

### Flag 19 – Employee Scorecard Access on Second Endpoint

**Objective:** Confirm employee-related scorecard access occurs again on the second endpoint and identify the remote session device context.

```kusto
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-04T00:00:00) .. datetime(2026-01-01T00:00:00))
| where DeviceName == "main1-srvr"
| where ProcessCommandLine has "Scorecard"
| project TimeGenerated, ProcessRemoteSessionDeviceName, ProcessCreationTime, FileName, ProcessCommandLine,
          InitiatingProcessRemoteSessionDeviceName,
          AccountName
| order by TimeGenerated asc
```

**What This Reveals:** Confirms scorecard access repeated on the second endpoint, tied to the `YE-FINANCEREVIE` session — a Finance department device accessing HR candidate records is anomalous.

**Answer:** `YE-FINANCEREVIE`

**MITRE ATT&CK:** T1039 – Data from Network Shared Drive

---

### Flag 20 – Staging Directory Identification on Second Endpoint

**Objective:** Identify the directory used for consolidation of internal reference materials and archived content.

```kusto
DeviceFileEvents
| where TimeGenerated between (datetime(2025-12-04T00:00:00) .. datetime(2026-01-01T00:00:00))
| where DeviceName == "main1-srvr"
| where isnotempty(InitiatingProcessRemoteSessionDeviceName)
| where FileName has_any (".zip", ".rar", ".7z", ".tar", ".gz")
| project TimeGenerated, FileName, FolderPath, ActionType,
          InitiatingProcessRemoteSessionDeviceName,
          InitiatingProcessFileName
| order by TimeGenerated asc
```

**What This Reveals:** Identifies the staging directory on `main1-srvr` where the year-end review package was archived, confirming final data consolidation before exfiltration.

**Answer:** `C:\Users\Main1-Srvr\Documents\InternalReferences\ArchiveBundles\YearEnd_ReviewPackage_2025.zip` — `2025-12-04T03:15:29.2597235Z`

**MITRE ATT&CK:** T1560.001 – Archive Collected Data: Archive via Utility

---

### Flag 21 – Staging Activity Timing on Second Endpoint

**Objective:** Determine when staging activity occurred during the final phase on the second endpoint.

```kusto
DeviceFileEvents
| where TimeGenerated between (datetime(2025-12-04T00:00:00) .. datetime(2026-01-01T00:00:00))
| where DeviceName == "main1-srvr"
| where isnotempty(InitiatingProcessRemoteSessionDeviceName)
| where FileName has_any (".zip", ".rar", ".7z", ".tar", ".gz")
| project TimeGenerated, FileName, FolderPath, ActionType,
          InitiatingProcessRemoteSessionDeviceName,
          InitiatingProcessFileName
| order by TimeGenerated asc
```

**What This Reveals:** Pinpoints the exact timestamp of archive creation on the second endpoint, confirming the staging timeline relative to prior data access.

**Answer:** `2025-12-04T03:15:29.2597235Z`

**MITRE ATT&CK:** T1560.001 – Archive Collected Data: Archive via Utility

---

### Flag 22 – Outbound Connection Remote IP (Final Phase)

**Objective:** Identify the remote IP associated with the final outbound connection attempt.

```kusto
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-12-04T00:00:00) .. datetime(2026-01-01T00:00:00))
| where DeviceName == "main1-srvr"
| where isnotempty(InitiatingProcessRemoteSessionDeviceName)
| where RemoteUrl contains "httpbin.org"
```

**What This Reveals:** Confirms the final exfiltration attempt targeted `httpbin.org` (54.83.21.156) — a commonly abused public HTTP testing service used by attackers to validate outbound data transfer capability.

**Answer:** `54.83.21.156` — `2025-12-04T03:15:48.3479532Z`

**MITRE ATT&CK:** T1567 – Exfiltration Over Web Service

---

## Indicators of Compromise (IOCs)

| Type | Value | Context |
|------|-------|---------|
| IP Address | 49.147.192.23 | External attacker IP |
| IP Address | 192.168.0.110 | M1-ADMIN internal IP |
| IP Address | 54.83.21.156 | Exfiltration destination (httpbin.org) |
| Hostname | M1-ADMIN | Primary attacker machine |
| Hostname | M2-ADMIN | Secondary attacker machine |
| Hostname | YE-HELPDESKTECH | Compromised session device |
| Hostname | YE-HRPLANNER | Compromised session device |
| Hostname | YE-FINANCEREVIE | Compromised session device |
| Account | 5y51-d3p7 | Compromised user account |
| File | PayrollSupportTool.ps1 | Attacker PowerShell tool |
| File | export_stage.zip | Staged data archive |
| File | Q4Candidate_Pack.zip | Staged candidate data archive |
| File | YearEnd_ReviewPackage_2025.zip | Final exfil archive (main1-srvr) |
| File | BonusMatrix_Q4_Approved.xlsx | Targeted sensitive file |
| Registry Key | HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run | Persistence Run key |
| Scheduled Task | BonusReviewAssist | Persistence scheduled task |

---

## MITRE ATT&CK Mapping

| Technique ID | Technique | Flags |
|--------------|-----------|-------|
| T1078 | Valid Accounts | 1, 2 |
| T1021.001 | Remote Services: RDP | 2, 17 |
| T1059.001 | PowerShell | 3, 7, 15 |
| T1033 | System Owner/User Discovery | 4 |
| T1083 | File and Directory Discovery | 5, 12 |
| T1560.001 | Archive Collected Data: Archive via Utility | 6, 14, 20, 21 |
| T1071.001 | Application Layer Protocol: Web Protocols | 7 |
| T1547.001 | Registry Run Keys / Startup Folder | 8 |
| T1053.005 | Scheduled Task | 9 |
| T1039 | Data from Network Shared Drive | 10, 11, 13, 18, 19 |
| T1070.001 | Indicator Removal: Clear Windows Event Logs | 16 |
| T1567 | Exfiltration Over Web Service | 15, 22 |

---

## Investigation Statistics

| Metric | Value |
|--------|-------|
| Total Flags Investigated | 22 |
| Dwell Time | 3 days (Dec 1–4, 2025) |
| Systems Compromised | 2 (sys1-dept, main1-srvr) |
| Remote Session Devices | 5 (M1-ADMIN, M2-ADMIN, YE-HELPDESKTECH, YE-HRPLANNER, YE-FINANCEREVIE) |
| Sensitive Files Targeted | 5+ |
| Archives Created | 3 |
| Persistence Mechanisms | 2 (Registry Run key + Scheduled Task) |
| MITRE Techniques Identified | 12 |

---

## Document Information

| Field | Value |
|-------|-------|
| Hunt Name | Crosscheck |
| Classification | CONFIDENTIAL |
| Created | May 2026 |
| Primary Endpoint | sys1-dept |
| Secondary Endpoint | main1-srvr |
| Compromised Account | 5y51-d3p7 |
| Status | In Progress |
