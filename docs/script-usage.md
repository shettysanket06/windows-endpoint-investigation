# Reusable Investigation Scripts

These utilities were tested in the local Windows PowerShell 5.1 lab. Run from an elevated PowerShell session when the target event log requires administrator access.

## Execution policy note

The scripts are unsigned. If the local execution policy blocks a script, use a process-scoped invocation rather than changing the machine policy:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "FULL_PATH_TO_SCRIPT"
```

This invocation uses a temporary policy setting for the child PowerShell process. Review a script before running it.

## 1. Sysmon process lifecycle

File: `scripts/Get-SysmonProcessLifecycle.ps1`

Example:

```powershell
.\Get-SysmonProcessLifecycle.ps1 -ProcessGuid "{PROCESS-GUID}" -StartTime "2026-11-01 15:45:00" -ExportPath "evidence\sysmon\process-lifecycle.csv"
```

Retrieves Sysmon process creation and termination records and correlates them by Process GUID.

## 2. PowerShell command-line indicator hunt

File: `scripts/Find-PowerShellCommandLineIndicators.ps1`

Example:

```powershell
.\Find-PowerShellCommandLineIndicators.ps1 -LastHours 24 -ExportPath "evidence\sysmon\hunt-results.csv"
```

Searches selected command-line indicators in Sysmon Event ID 1. Matches are investigation leads, not proof of malicious activity. Review exported command lines for usernames, local paths, secrets and tokens before sharing.

## 3. Authentication failure summary

File: `scripts/Get-AuthenticationFailureSummary.ps1`

Example:

```powershell
.\Get-AuthenticationFailureSummary.ps1 -LastHours 24
```

Queries Windows Security Event ID 4625 and outputs an anonymised summary of failed logons.

## 4. Scheduled-task event summary

File: `scripts/Get-ScheduledTaskEventSummary.ps1`

Example:

```powershell
.\Get-ScheduledTaskEventSummary.ps1 -TaskName "SOC-Lab-Test" -StartTime "2026-11-01 16:25:00" -ExportDirectory "evidence\task-scheduler\script-validation"
```

Queries relevant Windows Security and Task Scheduler Operational events. Results depend on audit settings, channel state and event retention.

## Scope and limitations

These are standalone investigation utilities, not a SIEM, continuous monitoring service or automated incident-response platform. Event availability depends on the local Windows logging and audit configuration.
