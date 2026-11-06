# Windows Endpoint Investigation & Threat Hunting

A hands-on, single-endpoint Windows investigation lab using Microsoft Sysmon, Windows PowerShell, Windows Security auditing, and Task Scheduler. The project demonstrates evidence collection, event interpretation, process correlation, false-positive review, and investigation reporting.

> This is a controlled educational lab, not an enterprise SOC deployment. No real malware or confirmed compromise was investigated.

## Objectives

- Inspect Windows Security and Operational event logs.
- Install and verify Sysmon telemetry on a Windows endpoint.
- Investigate process creation and termination.
- Enable PowerShell Script Block Logging temporarily and inspect Event ID 4104.
- Search selected PowerShell command-line and script-block indicators.
- Investigate a self-generated false positive.
- Investigate scheduled-task creation, execution, process activity, and deletion.
- Analyse failed Windows authentication events and document unresolved attribution.
- Preserve sanitised evidence and write reproducible investigation reports.

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
| Tools | Sysmon, Event Viewer, PowerShell, Get-WinEvent, AuditPol, Task Scheduler |

The registry ProductName value returned a Windows 10 label, while WMI and the reported build indicated a Windows 11 installation. The project records this observed discrepancy rather than silently reconciling it.

## Investigation architecture

    LOCAL WINDOWS ENDPOINT
              |
      +-------+--------+------------------+
      |                |                  |
      v                v                  v
    Sysmon         PowerShell        Windows Security
  Operational     Operational             Log
      log              log                 |
      |                |                  |
      +----------------+------------------+
                       |
                       v
             Task Scheduler Operational
                       |
                       v
             Evidence correlation/review
                       |
                       v
              Sanitised reports and CSVs

## Investigations performed

### 1. Process creation and termination

A controlled PowerShell process was investigated using Sysmon Event ID 1 (Process Create) and Event ID 5 (Process Terminated). The analysis examined image path, command line, PID, Process GUID, parent process, user context, and SHA-256 hash information.

For the first controlled process, PID 23444, the creation and termination events shared the same Process GUID. Their recorded timestamps were approximately 5.783 seconds apart. The sanitised event summary is in evidence/sysmon/process-lifecycle.csv.

### 2. PowerShell Script Block Logging

Script Block Logging was enabled temporarily through the Windows PowerShell policy registry setting. A harmless test script was executed and its content retrieved from PowerShell Operational Event ID 4104. The 4104 process ID was correlated with Sysmon Event ID 1 and the later Sysmon Event ID 5. The policy was restored to its original unconfigured state after the exercise.

PowerShell logging can capture sensitive script content. No secrets were intentionally used in the test.

### 3. PowerShell threat-hunting exercises

A Sysmon Event ID 1 search initially returned no selected command-line indicator matches. A later reusable-script run identified five matches for -ExecutionPolicy Bypass; four were attributable to PowerShell commands used during this lab.

The fifth event used the placeholder-looking path C:\path\to\your\script.ps1. The referenced path did not exist when checked. Sysmon recorded the child PowerShell process terminating about five seconds after creation. The parent-child relationship was reconstructed using Process GUIDs. The available evidence did not establish who initiated the command or whether the referenced file existed at execution time. It was not classified as confirmed malicious activity.

A separate Event ID 4104 search identified a match for strings associated with Base64 decoding, dynamic execution, and remote download. Inspection of the complete event showed that the content was the hunting script itself, which contained the indicator strings as literals. This was classified as a self-generated false positive, not evidence that those operations had executed.

These are limited indicator searches, not comprehensive detections. A match is an investigation lead and requires context.

### 4. Scheduled-task lifecycle investigation

The lab temporarily enabled successful auditing for Other Object Access Events and enabled the Task Scheduler Operational channel. A harmless, manually triggered task named SOC-Lab-Test ran cmd.exe to write a marker to a text file.

| Activity | Evidence |
|---|---|
| Task creation | Security Event ID 4698 |
| Task started | Task Scheduler Event ID 100 |
| Task action process launch | Task Scheduler Event ID 129 |
| Action launched | Task Scheduler Event ID 200 |
| Action completed | Task Scheduler Event ID 201 |
| Task instance completed | Task Scheduler Event ID 102 |
| Process creation | Sysmon Event ID 1 |
| Task deletion | Security Event ID 4699 |

Task Scheduler reported PID 2920; Sysmon independently recorded PID 2920 as cmd.exe, with svchost.exe as its parent. The task returned code 0 and wrote SOC-LAB-TASK-RAN to the test output file. The task was then deleted. Temporary audit settings were restored to their original disabled states.

### 5. Windows authentication investigation

The Security log query examined 403 events over the selected 24-hour period:

| Event ID | Meaning | Count |
|---|---|---:|
| 4624 | Successful logon | 361 |
| 4625 | Failed logon | 7 |
| 4634 | Account logoff | 18 |
| 4648 | Explicit credentials used | 17 |

All seven failed logons targeted the same anonymised account and reported Logon Type 2, status 0xc000006d, and substatus 0xc000006a (incorrect password).

Five failures were associated with svchost.exe PID 2364 and loopback source context. The process was no longer running when investigated, and no corresponding historical Sysmon creation or termination event was found. Its hosted service could not be identified.

Two failures were associated with AsusSoftwareManager.exe. The executable was located in a Windows DriverStore package, had ASUS product metadata and a valid Authenticode signature. A later instance was correlated with Sysmon process telemetry. The precise reason for the authentication failures was not established.

No external brute-force attack or confirmed compromise was established by the collected evidence.

## Investigation reports and evidence

The reports below contain the investigation narratives and analyst conclusions. The evidence links open the sanitised event exports committed with this project.

### Investigation reports

- [Process and PowerShell investigation](reports/process-and-powershell-investigation.md)
- [Scheduled-task investigation](reports/scheduled-task-investigation.md)
- [Authentication investigation](reports/authentication-investigation.md)

### Selected evidence

- [Sysmon process lifecycle — primary export](evidence/sysmon/process-lifecycle.csv)
- [Sysmon process lifecycle — reusable script output](evidence/sysmon/process-lifecycle-reusable-script.csv)
- [Scheduled-task execution events](evidence/task-scheduler/scheduled-task-execution-events.csv)
- [Scheduled-task process correlation](evidence/sysmon/scheduled-task-process-correlation.csv)
- [Windows authentication failures](evidence/windows-security/authentication-failures.csv)
- [All evidence files](evidence/)

## Repository structure

    windows-endpoint-investigation/
    |-- README.md
    |-- .gitignore
    |-- configs/
    |   `-- sysmon/README.md
    |-- docs/
    |   |-- limitations.md
    |   |-- methodology.md
    |   `-- script-usage.md
    |-- evidence/
    |   |-- screenshots/README.md
    |   |-- sysmon/
    |   |-- task-scheduler/
    |   |   `-- script-validation/
    |   `-- windows-security/
    |-- references/README.md
    |-- reports/
    |   |-- authentication-investigation.md
    |   |-- process-and-powershell-investigation.md
    |   `-- scheduled-task-investigation.md
    `-- scripts/
        |-- Find-PowerShellCommandLineIndicators.ps1
        |-- Get-AuthenticationFailureSummary.ps1
        |-- Get-ScheduledTaskEventSummary.ps1
        |-- Get-SysmonProcessLifecycle.ps1
        `-- Test-ScriptBlockLogging.ps1

## Reusable investigation scripts

The scripts directory contains four reusable Windows PowerShell 5.1 investigation utilities and the controlled Script Block Logging test script.

| Script | Purpose |
|---|---|
| Get-SysmonProcessLifecycle.ps1 | Correlates Sysmon process creation and termination by Process GUID. |
| Find-PowerShellCommandLineIndicators.ps1 | Searches selected PowerShell command-line indicators; matches require manual review. |
| Get-AuthenticationFailureSummary.ps1 | Summarises failed Windows logons from Event ID 4625. |
| Get-ScheduledTaskEventSummary.ps1 | Summarises scheduled-task Security and Operational events. |
| Test-ScriptBlockLogging.ps1 | Harmless test script used to validate Script Block Logging. |

Usage examples and parameter notes are in [docs/script-usage.md](docs/script-usage.md). These scripts are investigation aids, not an automated detection platform.

## Evidence handling

The repository contains sanitised CSV summaries and harmless test output. Raw EVTX files are not included. Review every file and screenshot for account names, machine names, local paths, IP addresses, tokens, passwords, and other sensitive information before publication.

The full PowerShell command-line hunt export is excluded by .gitignore because command lines can contain personal paths or other sensitive values.

## Limitations

This was a single-endpoint laboratory exercise, not an enterprise SOC deployment. The observed Sysmon configuration had network connection monitoring and image-load monitoring disabled and reported no custom rules installed. No malicious payload was executed and no real compromise was confirmed.

See [docs/limitations.md](docs/limitations.md), [docs/methodology.md](docs/methodology.md), and [docs/script-usage.md](docs/script-usage.md) for details.

## References

See [references/README.md](references/README.md) for official Microsoft documentation.

## Disclaimer

This project is for defensive cybersecurity education and portfolio demonstration. All controlled activity was performed on an authorised local endpoint.
