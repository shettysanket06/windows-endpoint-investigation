# Sysmon Configuration Notes

The lab used the built-in Windows Sysmon optional feature. The service was verified as running with Automatic startup, and the event channel was `Microsoft-Windows-Sysmon/Operational`.

The observed `sysmon -c` output reported:

| Setting | Observed value |
|---|---|
| Hashing algorithms | SHA256 |
| Network connection monitoring | Disabled |
| Image loading | Disabled |
| DNS lookup | Enabled |
| Custom rules | None installed |

Sysmon Event IDs 1 and 5 were observed. No custom XML configuration was deployed. This document records the observed configuration; it is not an exported Sysmon XML file.
