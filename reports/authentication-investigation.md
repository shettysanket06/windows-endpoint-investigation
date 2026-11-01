# Windows Authentication Investigation

## Objective

Investigate failed Windows authentication attempts and determine whether the evidence indicates suspicious account access.

## Environment

- Operating system: Windows 11
- Log source: Windows Security Event Log
- Event ID: 4625
- Investigation period: 1 November 2026

## Findings

Seven failed authentication events were identified, all targeting the same anonymised account.

All seven events reported:
- Logon Type: 2 (Interactive)
- Status: 0xc000006d
- SubStatus: 0xc000006a

The SubStatus indicates an incorrect password.

## Process investigation

### ASUS Software Manager

Two failures were associated with AsusSoftwareManager.exe.

The executable was located within the Windows DriverStore package.

Metadata identified ASUSTeK COMPUTER INC., version 1.1.24.0. Its digital signature was valid.

The second instance was correlated with Sysmon process telemetry, with services.exe as its parent.

The precise cause of the failed authentication remains undetermined.

### svchost.exe

Five failures were associated with svchost.exe, PID 2364.

All five used User32 as the logon process, Negotiate as the authentication package and loopback as the source.

No matching historical Sysmon process creation or termination event was available. The associated Windows service could not be identified.

PID reuse cannot be excluded.

## Assessment

The available evidence does not establish an external brute-force attack or a confirmed security compromise.

The ASUS executable has strong indicators of legitimate software provenance, but its authentication behaviour remains unexplained.

The svchost.exe failures remain unattributed.

## Limitations

- The historical svchost process was no longer running.
- No Process GUID was available for its creation.
- The exact service hosted by that process could not be established.
- Authentication failure events alone do not establish malicious intent.

## Conclusion

The investigation identified seven failed authentication attempts and examined their associated processes.

The findings are inconclusive. No confirmed compromise was established.

Further investigation would require additional historical service and authentication context.

## Evidence

- evidence/evtx/authentication-failures.csv
- Previous Sysmon process investigations
- ASUS executable signature and hash assessment
