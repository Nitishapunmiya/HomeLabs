# Detecting Windows Scheduled Task Persistence using Splunk SIEM

> **SOC Home Lab Project** demonstrating how a Scheduled Task can be abused for persistence, how Windows telemetry is collected using Splunk Universal Forwarder, and how the activity is detected, investigated, and visualized in Splunk.

> **Note:** This lab uses a harmless payload (opening a text file in Notepad) to safely demonstrate the persistence technique.

---

# Project Overview

This project simulates a common Windows persistence technique where an attacker who has already obtained Administrator privileges creates a Scheduled Task to automatically execute a payload whenever a user logs in.

Instead of executing malware, the scheduled task launches PowerShell which opens a harmless text file (`persistence.txt`) in Notepad. The focus of this project is understanding the attack lifecycle, collecting Windows telemetry, detecting the activity in Splunk, and performing a SOC-style investigation.

---

# Objectives

- Simulate Scheduled Task persistence.
- Configure Splunk Universal Forwarder.
- Collect Task Scheduler Operational logs.
- Detect the attack in Splunk.
- Investigate generated events.
- Build SPL queries.
- Create a dashboard.
- Map findings to MITRE ATT&CK.

---

# Lab Architecture

```
Windows Victim
      │
      │  Splunk Universal Forwarder
      ▼
Splunk Enterprise
      │
      ├── Detection
      ├── Investigation
      └── Dashboard
```

---

# Tools Used

- Windows 11
- Splunk Enterprise
- Splunk Universal Forwarder
- Windows Task Scheduler
- PowerShell
- Event Viewer
- Command Prompt

---

# Splunk Universal Forwarder Configuration

## Install

Install Splunk Universal Forwarder on the Windows machine and connect it to your Splunk Enterprise instance.


## Configure inputs.conf

Location:

```text
C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf
```

```ini
[WinEventLog://Application]
disabled = 0
index = main

[WinEventLog://Security]
disabled = 0
index = main

[WinEventLog://System]
disabled = 0
index = main

[WinEventLog://Microsoft-Windows-TaskScheduler/Operational]
disabled = 0
index = main
start_from = oldest
current_only = 0
```

Restart the Universal Forwarder after saving the file.

---

# Attack Scenario

Assume the attacker has already compromised the Windows machine and gained Administrator privileges.

Instead of exploiting the system repeatedly, the attacker establishes **persistence** so their payload executes automatically after every user logon.

The attacker creates a scheduled task named **Windows Update Service** to blend in with legitimate Windows tasks.

The scheduled task launches **PowerShell**, which then opens a harmless text file in Notepad.

---

# Payload

Create:

```text
C:\Users\Public\demo\persistence.txt
```

Contents:

```text
SOC Home Lab

Persistence simulation successful.
```

This replaces a real malicious payload with a safe demonstration.

---

# Scheduled Task Creation

Initially the task was created using the **SYSTEM** account.

Although the task executed successfully, the Notepad window was not visible because the SYSTEM account runs in a different Windows session from the interactive user.

For demonstration purposes, the task was recreated under the logged-in user so the payload was visible while preserving the same persistence technique.

Command used:

```cmd
schtasks /create /tn "Windows Update Service" /sc ONLOGON /tr "powershell.exe -NoProfile -Command \"Start-Process notepad.exe -ArgumentList 'C:\Users\Public\demo\persistence.txt'\""
```

**What this command does**

- Creates a scheduled task.
- Uses a legitimate-looking task name.
- Executes PowerShell whenever a user logs in.
- PowerShell launches Notepad.
- Notepad opens the demonstration file.


---

# Detection

Task Scheduler Operational logging was enabled and collected by Splunk.

Useful Event IDs:

| Event ID | Description |
|-----------|-------------|
|106|Task registered|
|200|Action started|
|201|Action completed|
|102|Task completed|

---

# Splunk Queries

View all Task Scheduler logs:

```spl
index=main source="WinEventLog:Microsoft-Windows-TaskScheduler/Operational"
```

Task creation:

```spl
index=main source="WinEventLog:Microsoft-Windows-TaskScheduler/Operational" EventCode=106
```

Action started:

```spl
index=main source="WinEventLog:Microsoft-Windows-TaskScheduler/Operational" EventCode=200
```

Action completed:

```spl
index=main source="WinEventLog:Microsoft-Windows-TaskScheduler/Operational" EventCode=201
```

Specific task:

```spl
index=main source="WinEventLog:Microsoft-Windows-TaskScheduler/Operational" "Windows Update Service"
```

Timeline:

```spl
index=main source="WinEventLog:Microsoft-Windows-TaskScheduler/Operational"
| timechart count by EventCode
```

Statistics:

```spl
index=main source="WinEventLog:Microsoft-Windows-TaskScheduler/Operational"
| stats count by EventCode
```



# Investigation

During the investigation I verified:

- Time the scheduled task was created.
- User associated with the task.
- Task name.
- Trigger (User Logon).
- PowerShell execution.
- Executed command.
- Event IDs.
- Timeline of execution.

The PowerShell command uses `-NoProfile`, which prevents loading the user's PowerShell profile and is commonly observed in administrative automation and attacker tradecraft. By itself it is not malicious, but in combination with a newly created scheduled task it warrants investigation.

---

# Dashboard

A custom Splunk dashboard was created to visualize:

- Total Task Scheduler events
- Event ID distribution
- Timeline
- Scheduled task activity
- Detection trends



---

# MITRE ATT&CK

| Tactic | Technique |
|---------|-----------|
|Persistence|T1053.005 – Scheduled Task/Job|
|Execution|T1059.001 – PowerShell|

---

# Indicators of Compromise

- Scheduled Task named **Windows Update Service**
- PowerShell executed automatically
- User logon trigger
- Task Scheduler Operational events (106, 200, 201)

---

# Lessons Learned

- Scheduled Tasks are a common persistence mechanism.
- Task Scheduler Operational logs are valuable for detection.
- Splunk Universal Forwarder can collect these logs effectively.
- PowerShell should be investigated in context.
- Combining Windows telemetry with SPL queries enables effective detection and investigation.

---

# Future Improvements

- Detect encoded PowerShell.
- Detect malicious services.
- Detect registry persistence.
- Create Splunk alerts.
- Integrate Sysmon.
