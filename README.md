# Crosscheck (WIP)



Flag 1 – Initial Endpoint Association 
Objective:
Determine which endpoint first shows activity tied to the user context involved in the chain.
What to Hunt:
Process telemetry where a specific local account is observed. Use this to identify the associated device.
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-01T00:00:00) .. datetime(2026-01-01T20:00:00))
| where AccountName == "5y51-d3p7"


Identify the DeviceName in question: sys1-dept
Flag 2 – Remote Session Source Attribution
Objective:
Identify the remote session source information tied to the initiating access on the first endpoint.
What to Hunt:
Remote session metadata (source IP) for the remote session device involved in early activity on the first system.
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-01T00:00:00) .. datetime(2026-01-01T20:00:00))
| where AccountName == "5y51-d3p7"
| where DeviceName == "sys1-dept"
| where isnotempty(InitiatingProcessRemoteSessionIP)
| project TimeGenerated, InitiatingProcessRemoteSessionIP  
Provide the IP of the remote session accessing the system: 192.168.0.110 2025-12-01T03:13:34.3476301Z
Flag 3 – Support Script Execution Confirmation
Objective:
Confirm execution of a support-themed PowerShell script from a user-accessible directory.
What to Hunt:
PowerShell process creation referencing execution of a script located under the user profile (commonly Downloads).
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-01T00:00:00) .. datetime(2026-01-01T20:00:00))
| where AccountName == "5y51-d3p7"
| where DeviceName == "sys1-dept"
| where InitiatingProcessCommandLine contains "powershell.exe"
| where ProcessCommandLine contains @"\downloads"
What was the command used to execute the program?: "powershell.exe" -ExecutionPolicy Bypass -File C:\Users\5y51-D3p7\Downloads\PayrollSupportTool.ps1
Flag 4 – System Reconnaissance Initiation
Objective:
Identify the first reconnaissance action used to gather host and user context.
What to Hunt:
Execution of common reconnaissance utilities and command patterns used to enumerate identity, sessions, and active processes.
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-01T00:00:00) .. datetime(2026-01-01T20:00:00))
| where AccountName == "5y51-d3p7"
| where DeviceName == "sys1-dept"
| where ProcessCommandLine has_any ("ipconfig", "net", "user", "arp", "nslookup", "whoami" ) 
| project TimeGenerated, AccountName, FileName, ProcessCommandLine
Identify the first recon command attempted*: "whoami.exe" /all 2025-12-03T06:12:03.7890991Z
Flag 5 – Sensitive Bonus-Related File Exposure
Objective:
Identify the first sensitive year-end bonus-related file that was accessed during exploration.


What to Hunt:
Process activity indicating discovery behavior around bonus-related content, and confirm which sensitive file is involved.
DeviceFileEvents
| where TimeGenerated between (datetime(2025-12-01T00:00:00) .. datetime(2026-01-01T20:00:00))
| where DeviceName == "sys1-dept"
| where FileName contains "bonus"
Which sensitive file was likely targeted by actor(s)? BonusMatrix_Draft_v3.xlsx 2025-12-03T07:24:42.9603372Z
Flag 6 – Data Staging Activity Confirmation
Objective:
Confirm that sensitive data was prepared for movement by staging into an export/archive output.
What to Hunt:
File creation activity consistent with archived/exported content and extract the initiating process identifier.
DeviceFileEvents
| where TimeGenerated between (datetime(2025-10-01T00:00:00) .. datetime(2026-01-01T20:00:00))
| where DeviceName == "sys1-dept"
| where ActionType == "FileCreated"
| where FileName has_any (".rar", ".zip", ".7z", ".tar", ".gz", ".cab")
| project TimeGenerated, DeviceName, FileName, FolderPath, 
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessId, InitiatingProcessUniqueId
| order by TimeGenerated asc
Identify the ID of the initiating unique process* 2533274790396713 C:\Users\5y51-D3p7\Documents\export_stage.zip 2025-12-03T06:27:10.6828355Z
Flag 7 – Outbound Connectivity Test
Objective:
Confirm that outbound access was tested prior to any attempted transfer.


What to Hunt:
A PowerShell-driven network connection to a benign external endpoint and determine the earliest reach attempt.

DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-12-01T00:00:00) .. datetime(2025-12-04T20:00:00))
| where DeviceName == "sys1-dept"
| where InitiatingProcessAccountName contains "5y51-d3p7"
| where InitiatingProcessCommandLine has_any ("curl", "wget", "http", "Invoke-WebRequest", "iwr", "curl.exe")
or InitiatingProcessFileName in~ ("curl.exe", "powershell.exe", "pwsh.exe")
| project TimeGenerated, ActionType, InitiatingProcessCommandLine, RemoteIP, RemoteUrl
When was the first outbound connection attempt initiated?* 2025-12-03T06:27:31.1857946Z
Flag 8 – Registry-Based Persistence
Objective:
Identify evidence of persistence established via a user Run key.


What to Hunt:
Registry modifications under the standard user Run path that indicate an auto-start execution mechanism.
DeviceRegistryEvents
| where TimeGenerated between (datetime(2025-12-01T00:00:00) .. datetime(2025-12-04T20:00:00))
| where DeviceName == "sys1-dept" 
| where InitiatingProcessAccountName == "5y51-d3p7"
| where ActionType has_any ("RegistryValueSet", "RegistryKeyCreated")
Provide the associated RegistryKey value *2025-12-03T06:27:59.603716Z
HKEY_CURRENT_USER\S-1-5-21-805396643-3920266184-3816603331-500\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
Flag 9 – Scheduled Task Persistence
Objective:
Confirm a scheduled task was created or used to automate recurring execution.


What to Hunt:
Scheduled task creation/execution via command line, focusing on the task name used.
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-01T00:00:00) .. datetime(2025-12-04T20:00:00))
| where DeviceName == "sys1-dept"
| where InitiatingProcessAccountName contains "5y51-d3p7"
| where InitiatingProcessCommandLine has_any ("curl", "wget", "http", "Invoke-WebRequest", "iwr", "curl.exe")
or InitiatingProcessFileName in~ ("curl.exe", "powershell.exe", "pwsh.exe")
| project TimeGenerated, ActionType, InitiatingProcessCommandLine, ProcessCommandLine
What was the Task Name value tied to this particular activity?* 2025-12-03T06:28:28.1020219Z
BonusReviewAssist 
Flag 10 – Secondary Access to Employee Scorecard Artifact
Objective:
Identify evidence that a different remote session context accessed an employee-related scorecard file.


What to Hunt:
File telemetry involving an employee scorecard artifact and determine which remote session device is associated.
DeviceFileEvents
| where TimeGenerated between (datetime(2025-12-01T00:00:00) .. datetime(2026-01-01T20:00:00))
| where DeviceName == "sys1-dept"
| where FileName has_any ("scorecard", "review")
| project TimeGenerated, FileName, FolderPath, ActionType,
          InitiatingProcessAccountName,
          InitiatingProcessRemoteSessionDeviceName,
          InitiatingProcessRemoteSessionIP
| order by TimeGenerated asc 
Identify the other remote session user that attempted to access employee related files: YE-HELPDESKTECH
Flag 11 – Bonus Matrix Activity by a New Remote Session Context
Objective:
Identify another remote session device name that is associated with higher level related activities later in the chain.


What to Hunt:
File events related to bonus payout related artifacts and extract the remote session device metadata.


Hint:
1. Utilize previous findings
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
Identify the other remote session department that attempted to access sensitive payout files YE-HRPLANNER
Flag 12 – Performance Review Access Validation
Objective:
Confirm access to employee performance review material through user-level tooling.


What to Hunt:
Process telemetry showing access to the performance review directory and correlate repeated access behavior across departments/sessions.


Hints:
1. Utilize previous findings 
2. Unintentional access of employee performance review records
3. File is in a different directory
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
Identify the timestamp of a process that points to an access of a similar employee related file 2025-12-03T07:25:15.6288106Z
Flag 13 – Approved/Final Bonus Artifact Access
Objective:
Confirm access to a finalized year-end bonus artifact with sensitive-read classification.


What to Hunt:
Events indicating sensitive reads tied to the remote session context responsible for the approved file access.


Hint:
1. Final version of the file
Identify the timestamp pointing to unauthorized access of a sensitive file*














































