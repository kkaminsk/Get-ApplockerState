# Get-ApplockerState
Script for collecting local information on a device about the AppLocker configuration.

## Prerequisites
- Windows: 10/11; Server 2016/2019/2022
- Shell: Windows PowerShell 5.1
- Permissions: Run elevated (Administrator)
- Recommended: Domain-joined device

## Usage (Alpha)
Run from an elevated Windows PowerShell 5.1 session in the repo root:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Get-AppLockerState.ps1
```

This will:
- Create a transcript in Documents: Get-AppLockerState-YYYY-MM-DD-HH-MM.log
- Create an output folder in Documents: Get-AppLockerState-YYYY-MM-DD-HH-MM/
- Zip the folder: Get-AppLockerState-YYYY-MM-DD-HH-MM.zip

## Outputs
In the timestamped output folder:
- AppLockerPolicy.xml (pretty-printed)
- EnforcementStatus.txt
- RulesSummary.csv (publisher/path/hash details incl. version ranges and SHA256)
- EVTX and CSV for:
  - Microsoft-Windows-AppLocker/EXE and DLL
  - Microsoft-Windows-AppLocker/MSI and Script
  - Microsoft-Windows-AppLocker/Packaged app-Deployment
  - Microsoft-Windows-AppLocker/Packaged app-Execution
- ApplicationIdentityService.txt
- SrpV2.reg
- SRPGP.reg
- warnings.txt (non-fatal issues)

## Troubleshooting
- Not elevated → script fails fast; rerun as Administrator.
- PowerShell 7 → not supported; use Windows PowerShell 5.1.
- Not domain-joined → collection proceeds; noted in warnings.txt.
