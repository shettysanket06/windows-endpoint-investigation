# Scheduled Task Investigation

## Objective
Investigate the creation, execution and deletion of a controlled Windows scheduled task.

## Environment
Windows 11 endpoint, Sysmon and Windows Security auditing.

## Findings

| Activity | Evidence |
|---|---|
| Task creation | Security Event ID 4698 |
| Task started | Task Scheduler Event ID 100 |
| Process launched | Task Scheduler Event ID 129 |
| Process creation | Sysmon Event ID 1 |
| Action completed | Task Scheduler Event ID 201 |
| Task completed | Task Scheduler Event ID 102 |
| Task deletion | Security Event ID 4699 |

## Process correlation

- Task: SOC-Lab-Test
- Process: cmd.exe
- Process ID: 2920
- Parent: svchost.exe
- Process GUID: {50a33978-1b84-6ae7-9b08-00000000cb07}
- Execution result: 0 (success)

## Conclusion

A harmless manually triggered scheduled task was created, executed and deleted.

Its creation and deletion were recorded in Windows Security logs. Its execution was recorded in Task Scheduler Operational logs and correlated with Sysmon process telemetry.

The investigation demonstrated scheduled-task lifecycle analysis and cross-source event correlation.

## Limitations

This was a controlled laboratory exercise. It does not demonstrate detection of an actual malicious persistence mechanism.

## Evidence files

- scheduled-task-security-events.csv
- scheduled-task-execution-events.csv
- scheduled-task-process-correlation.csv
- scheduled-task-output.txt
