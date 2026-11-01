# Project Limitations

## Sysmon coverage

The observed Sysmon configuration reported SHA-256 hashing, network connection monitoring disabled, image loading disabled, DNS lookup enabled and no custom rules installed. The project therefore does not demonstrate Sysmon Event ID 3 network-connection analysis, Event ID 7 image-load analysis or custom Sysmon XML filtering.

## PowerShell hunting

The PowerShell queries searched a limited set of strings and command-line options. They are not comprehensive detections. One 4104 match was caused by the threat-hunting script containing the literal strings being searched. The full event was inspected and classified as a self-generated false positive. No malicious PowerShell activity was confirmed.

## Scheduled-task exercise

Only one harmless, manually triggered scheduled task was created and deleted. This validates event collection and lifecycle investigation but does not demonstrate actual malicious persistence, evasion or enterprise-wide monitoring.

## Authentication findings

Seven failed logons were found. Two were associated with an ASUS Software Manager executable that had ASUS product metadata and a valid digital signature. Its precise authentication failure cause was not established. Five were associated with `svchost.exe` PID 2364 and loopback source context. The process had exited, and no matching historical Sysmon creation or termination event was available; its hosted service remains unidentified.

The evidence did not establish an external brute-force attack or confirmed compromise.

## Evidence format and privacy

Sanitised CSV summaries are included instead of raw EVTX exports. Some original event fields and context are therefore not available to a public reviewer. Account identifiers and network addresses were redacted or anonymised. All remaining files and screenshots must be reviewed before publication.

## Infrastructure

This was a single Windows endpoint lab. It did not include a central SIEM, Active Directory domain, multiple endpoints, continuous monitoring, enterprise incident-response automation or live malware execution.

## Reproducibility

The work was performed through interactive PowerShell commands. Not every command has yet been consolidated into a reusable script. The repository should not be described as a one-click automated investigation platform.

## Operating-system identification

WMI reported a Windows 11 Home Single Language caption, while the registry ProductName value returned a Windows 10 label. The observed build was 10.0.26300.9818. Both observations are recorded rather than silently reconciling the mismatch.
