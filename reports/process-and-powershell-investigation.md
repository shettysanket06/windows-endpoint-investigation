# Process Execution and PowerShell Investigation

## Objective

Investigate Windows process execution, correlate Sysmon process telemetry with PowerShell Script Block Logging, and evaluate selected PowerShell threat-hunting indicators.

## Controlled process lifecycle

A harmless PowerShell command with a unique marker was executed.

- Sysmon Event ID 1: process PID 23444 created at 2026-11-01 15:48:19.259.
- Sysmon Event ID 5: process PID 23444 terminated at 2026-11-01 15:48:25.042.
- The Process GUID matched across both records.
- Observed duration: approximately 5.783 seconds.

The sanitised summary is stored in `evidence/sysmon/process-lifecycle.csv`.

## Script Block Logging validation

Script Block Logging was temporarily enabled. The harmless `Test-ScriptBlockLogging.ps1` script was recorded in PowerShell Event ID 4104:

- Record ID: 92984.
- Process ID: 23536.
- Script Block ID: `86ba6e32-a89e-4ebd-b88e-15ef248f9f01`.

Sysmon Event ID 1 recorded PID 23536 with `cmd.exe` as parent. A later Sysmon Event ID 5 recorded termination of the same process GUID.

## Threat-hunting exercise

A bounded Sysmon Event ID 1 search returned no selected command-line indicator matches. A separate search of 40 PowerShell Event ID 4104 records found one match at Record ID 93017, PID 16124.

Inspection of the complete script block showed it was the hunting script itself. It contained literal strings such as `FromBase64String`, `DownloadString` and `Invoke-Expression` in its detection patterns. The match was therefore classified as a self-generated false positive, not evidence those operations were executed.

Sysmon Event ID 1 recorded PID 16124 at 16:14:17 with `cmd.exe` as parent. The 4104 event occurred at 16:16:23.

## Conclusion

The lab demonstrated Sysmon process creation and termination, PowerShell Script Block Logging, cross-source correlation and false-positive investigation. No malicious PowerShell execution was confirmed.
