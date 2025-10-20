# Proposal: Introduce Alpha Build for AppLocker State Collector

- Change ID: introduce-alpha-build
- Author: TBD
- Status: Draft
- Related Docs: `AppLockerSpec.md`

## Summary
Deliver the first runnable alpha build of a Windows PowerShell 5.1 script (`Get-AppLockerState.ps1`) that implements the collection behavior defined in `AppLockerSpec.md`. It will:
- Collect the local effective AppLocker policy on a domain-joined device.
- Produce the specified outputs (pretty XML, enforcement summary, expanded rules CSV, EVTX+CSV event logs, AppIDSvc state, warnings, transcript) using local-time timestamps.
- Package results as a `.zip` with the same base name as the transcript log.
- Add the transcript log to the zip file at the end of execution.

## Motivation
Provide a consistent, one-command collection of AppLocker configuration and telemetry that supports investigations, audits, and troubleshooting. Establish the baseline implementation and artifact structure for future enhancements (e.g., beta/stable builds, CI packaging, signing).

## Scope
- Create a single script entry point (`Get-AppLockerState.ps1`) for Windows PowerShell 5.1.
- Require elevation (fail fast if not admin).
- Implement outputs and behaviors exactly as described in `AppLockerSpec.md`.
- Store transcript in Documents, write artifacts into a timestamped subfolder, and zip the folder at the end.

## Non-Goals
- PowerShell 7 support.
- GPO/LDAP policy retrieval.
- Code signing, installers, or MSI packages.
- CI/CD automation for releases (can be added later).

## Success Criteria
- Running the script in an elevated PowerShell 5.1 session on a domain-joined device produces:
  - `AppLockerPolicy.xml` (pretty-printed)
  - `EnforcementStatus.txt`
  - `RulesSummary.csv` (expanded columns including publisher version ranges and hash SHA256)
  - EVTX and CSV files for the four AppLocker channels
  - `ApplicationIdentityService.txt`
  - `warnings.txt` when non-fatal issues occur
  - Transcript log named `Get-AppLockerState-YYYY-MM-DD-HH-MM.log` in Documents
  - A zip named `Get-AppLockerState-YYYY-MM-DD-HH-MM.zip` in Documents that contains the output folder
- Non-admin runs fail fast (no partial collection).

## Risks and Mitigations
- Variations in AppLocker XML across OS versions → Implement tolerant parsing (minimal for alpha; add fallbacks later if needed).
- Large or missing event logs → Export best-effort and capture issues in `warnings.txt`.
- Environment differences (regional settings, restricted environments) → Keep to core Windows cmdlets/utilities.

## References
- `c:/Users/KevinKaminski/Documents/GitHub/Get-ApplockerState/AppLockerSpec.md`
- Windows AppLocker documentation (for rule semantics and event channels)
