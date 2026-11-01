# Investigation Methodology

## 1. Environment assessment

The lab began by checking the operating-system caption and build, CPU, installed RAM, free storage, administrator access and available tools. The endpoint had 8 GB RAM and ran Windows PowerShell 5.1.

## 2. Sysmon installation and verification

The built-in Windows Sysmon optional feature was enabled and the Sysmon service installed. The service state and `Microsoft-Windows-Sysmon/Operational` channel were checked. The `sysmon -c` output was reviewed to document the configuration actually in use.

## 3. Process investigation

A controlled PowerShell process was launched. Sysmon Event ID 1 was inspected for image, command line, PID, Process GUID, parent image and hash fields. Event ID 5 was correlated to the same Process GUID to verify process termination. A sanitised CSV summary was exported.

## 4. PowerShell logging

The `EnableScriptBlockLogging` policy was temporarily enabled. A new PowerShell session was started and a harmless script was executed. Its content was retrieved from PowerShell Operational Event ID 4104. The event's execution PID was compared with Sysmon Event ID 1, and the subsequent termination was checked. The policy was restored to its original unconfigured state.

## 5. PowerShell threat hunting

Two bounded searches were performed: selected command-line indicators in Sysmon Event ID 1, and selected strings in PowerShell Event ID 4104. One 4104 match was inspected in full and identified as the hunting script itself. This was documented as a self-generated false positive; no malicious operation was proven.

## 6. Scheduled-task investigation

The original audit settings were recorded. Success auditing for Other Object Access Events was temporarily enabled, and the Task Scheduler Operational channel was enabled. A harmless manual-only task wrote a marker to a text file. Security Event IDs 4698 and 4699, Task Scheduler events 100, 102, 129, 200 and 201, and Sysmon Event ID 1 were examined. The task process was correlated using PID and timestamp. The task was deleted, evidence exported, and both temporary audit settings restored to their original disabled states.

## 7. Authentication investigation

The Security log was queried for Event IDs 4624, 4625, 4634 and 4648 over a 24-hour interval. Seven Event ID 4625 records were examined with account values anonymised in the export. Status, substatus, logon type, caller process, logon process, authentication package and source-address classification were reviewed. The ASUS executable's metadata, Authenticode status and SHA-256 hash were checked. The old `svchost.exe` PID could not be mapped to a service because the process had exited and no matching historical Sysmon process event was available.

## 8. Evidence handling

Evidence was exported as CSV summaries separated by source: Sysmon, Task Scheduler and Windows Security. Raw EVTX files were not included in the public evidence set. Reports were written in Markdown.

## 9. Investigation principles

- Treat indicator matches as leads, not verdicts.
- Correlate records across sources where possible.
- Prefer Process GUID to PID alone for Sysmon process-lifecycle correlation.
- Distinguish observations, inferences and unknowns.
- Record false positives and telemetry gaps.
- Restore temporary audit and logging changes after lab exercises.
