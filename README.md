# Windows Endpoint Investigation & Threat Hunting

## Overview

A hands-on Windows endpoint investigation project demonstrating how to collect, analyse and correlate endpoint telemetry using Microsoft Sysmon, Windows Event Viewer and Windows PowerShell.

The laboratory covers process execution, PowerShell script-block logging, basic PowerShell threat hunting, scheduled-task lifecycle investigation and Windows authentication analysis. All controlled tests were performed on the author's own Windows endpoint.

## Objectives

- Understand Windows Security and Operational event logs.
- Install and verify Sysmon telemetry.
- Investigate process creation and termination.
- Analyse PowerShell Script Block Logging.
- Perform basic searches for selected PowerShell indicators.
- Identify and explain a self-generated false positive.
- Investigate scheduled-task creation, execution and deletion.
- Analyse Windows authentication failures.
- Preserve sanitised evidence and write evidence-based reports.

## Lab environment

| Component | Observed value |
|---|---|
| OS caption | Microsoft Windows 11 Home Single Language (WMI-reported) |
| OS build | 10.0.26300.9818 |
| Architecture | 64-bit |
| CPU | AMD Ryzen 5 5600H with Radeon Graphics |
| Installed RAM | 8 GB |
| Shell | Windows PowerShell 5.1 |
| Sysmon | Built-in Windows optional feature; service verified running |
| Main tools | Sysmon, Event Viewer, Get-WinEvent, PowerShell, AuditPol, Task Scheduler |

The registry ProductName value returned a Windows 10 label while WMI and the build information indicated a Windows 11 installation. The project records the observed values rather than silently reconciling that discrepancy.

## Investigation architecture

```text
                    LOCAL WINDOWS ENDPOINT
                              |
          +-------------------+---------------------+
          |                   |                     |
          v                   v                     v
        Sysmon         PowerShell Operational   Windows Security
      Event log             event log              event log
          |                   |                     |
          +-------------------+---------------------+
                              |
                              v
                    Task Scheduler Operational
                              |
                              v
                   Evidence correlation and review
                              |
                              v
                    Sanitised CSVs and reports
```

## Investigations performed

### 1. Process creation and termination

A controlled PowerShell process was created and later correlated with Sysmon Event ID 1 (Process Create) and Event ID 5 (Process Terminated). The investigation examined executable path, command line, PID, Process GUID, parent process and SHA-256 hash information.

For the first controlled process, PID 23444, creation and termination events shared the same Process GUID. The observed duration between recorded timestamps was approximately 5.783 seconds. The sanitised event summary is in `evidence/sysmon/process-lifecycle.csv`.

### 2. PowerShell script-block logging

Script Block Logging was enabled temporarily through the Windows PowerShell policy registry setting. A harmless test script was executed, and its content was retrieved from PowerShell Operational Event ID 4104. The 4104 event process ID was correlated with Sysmon Event ID 1 and the later Sysmon Event ID 5.

The policy was restored to its original unconfigured state after the exercise. Logging can capture sensitive script contents; no secrets were intentionally used in the test.

### 3. PowerShell threat-hunting exercise

A Sysmon Event ID 1 search checked selected PowerShell command-line indicators. No matches were returned by that particular search. A separate Event ID 4104 search examined 40 script-block records and found one record matching selected strings associated with Base64 decoding, dynamic execution and remote download.

Inspection of the complete event showed that the matching content was the threat-hunting script itself, which contained the indicator strings as literals. The event was therefore classified as a self-generated false positive, not evidence that those operations had executed. The Sysmon process for the hunting script was correlated by PID and timestamp.

### 4. Scheduled-task lifecycle investigation

The lab temporarily enabled successful auditing for Other Object Access Events and enabled the Task Scheduler Operational channel. A harmless manually triggered task named `SOC-Lab-Test` ran `cmd.exe` to write a marker to a text file.

The investigation observed:

| Activity | Evidence |
|---|---|
| Task creation | Security Event ID 4698 |
| Task started | Task Scheduler Event ID 100 |
| Task process launch | Task Scheduler Event ID 129 |
| Action launched | Task Scheduler Event ID 200 |
| Action completed | Task Scheduler Event ID 201 |
| Task instance completed | Task Scheduler Event ID 102 |
| Process creation | Sysmon Event ID 1 |
| Task deletion | Security Event ID 4699 |

Task Scheduler reported PID 2920 for the action. Sysmon independently recorded PID 2920 as `cmd.exe`, with `svchost.exe` as its parent. The task returned code 0 and wrote `SOC-LAB-TASK-RAN` to the test output file. The task was then deleted. Temporary audit settings were restored to their original disabled states.

### 5. Windows authentication investigation

The Security log query examined 403 events over the selected 24-hour period:

| Event ID | Meaning | Count |
|---|---|---:|
| 4624 | Successful logon | 361 |
| 4625 | Failed logon | 7 |
| 4634 | Account logoff | 18 |
| 4648 | Explicit credentials used | 17 |

All seven failed logons targeted the same anonymised account and reported Logon Type 2 with status `0xc000006d` and substatus `0xc000006a` (incorrect password).

Five failures were associated with `svchost.exe` PID 2364 and loopback source context. The process was no longer running when investigated, and no corresponding historical Sysmon creation or termination event was found. Its hosted service could not be identified.

Two failures were associated with `AsusSoftwareManager.exe`. The executable was located in a Windows DriverStore package, had ASUS product metadata and a valid Authenticode signature. A later instance was correlated with Sysmon process telemetry. The precise reason for the authentication failures was not established.

No external brute-force attack or confirmed compromise was established by the collected evidence.

## Repository structure

```text
windows-endpoint-investigation/
â”œâ”€â”€ README.md
â”œâ”€â”€ .gitignore
â”œâ”€â”€ configs/
â”‚   â””â”€â”€ sysmon/README.md
â”œâ”€â”€ docs/
â”‚   â”œâ”€â”€ methodology.md
â”‚   â””â”€â”€ limitations.md
â”œâ”€â”€ evidence/
â”‚   â”œâ”€â”€ screenshots/README.md
â”‚   â”œâ”€â”€ sysmon/
â”‚   â”œâ”€â”€ task-scheduler/
â”‚   â””â”€â”€ windows-security/
â”œâ”€â”€ reports/
â”‚   â”œâ”€â”€ authentication-investigation.md
â”‚   â”œâ”€â”€ process-and-powershell-investigation.md
â”‚   â””â”€â”€ scheduled-task-investigation.md
â”œâ”€â”€ references/README.md
â””â”€â”€ scripts/
    â””â”€â”€ Test-ScriptBlockLogging.ps1
```

## Evidence handling

The repository uses sanitised CSV summaries and harmless test output. Raw EVTX files are not included. Review every file and screenshot for account names, machine names, local paths, IP addresses, tokens, passwords and other personal or sensitive information before publication.

## Limitations

This was a single-endpoint laboratory exercise, not an enterprise SOC deployment. The observed Sysmon configuration had network connection monitoring and image-load monitoring disabled and reported no custom rules installed. No malicious payload was executed and no real compromise was confirmed. The PowerShell hunting searches were limited indicator searches, not comprehensive threat detection.

See [`docs/limitations.md`](docs/limitations.md) and [`docs/methodology.md`](docs/methodology.md) for details.

## References

See [`references/README.md`](references/README.md) for official Microsoft documentation.

## Disclaimer

This project is for defensive cybersecurity education and portfolio demonstration. All controlled activity was performed on an authorised local endpoint.

## Reusable Investigation Scripts

Four reusable Windows PowerShell 5.1 investigation scripts are provided in `scripts/`:

- `Get-SysmonProcessLifecycle.ps1` â€” correlate Sysmon process creation and termination by Process GUID.
- `Find-PowerShellCommandLineIndicators.ps1` â€” search selected PowerShell command-line indicators; matches require manual review.
- `Get-AuthenticationFailureSummary.ps1` â€” summarise failed Windows logons from Event ID 4625.
- `Get-ScheduledTaskEventSummary.ps1` â€” summarise scheduled-task security and operational events.

Usage examples and parameter notes: [docs/script-usage.md](docs/script-usage.md).
