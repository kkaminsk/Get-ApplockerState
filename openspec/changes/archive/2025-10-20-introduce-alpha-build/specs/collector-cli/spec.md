# Capability: Collector CLI (Alpha)

## ADDED Requirements

### Requirement: R1 – Elevated PowerShell 5.1 only
The collector MUST run on Windows PowerShell 5.1 and require an elevated session; if not elevated, it MUST fail fast without proceeding.

#### Scenario: Non-admin run fails fast
- Given the user runs `Get-AppLockerState.ps1` in a non-elevated shell
- When the script starts
- Then it exits with an error and does not perform collection

### Requirement: R2 – Transcript log in Documents
The collector MUST start a transcript in the user’s Documents folder named `Get-AppLockerState-YYYY-MM-DD-HH-MM.log` using local time.

#### Scenario: Transcript file created
- Given an elevated run
- When the script starts
- Then a transcript file is created at the expected Documents path

### Requirement: R3 – Timestamped output folder
The collector MUST create an output folder `Get-AppLockerState-YYYY-MM-DD-HH-MM/` under Documents using local time.

#### Scenario: Output folder created
- Given an elevated run
- When the script initializes
- Then the folder exists under Documents with the expected name

### Requirement: R4 – Export effective AppLocker policy as pretty XML
The collector MUST export the effective policy (`Get-AppLockerPolicy -Effective -Xml`) and save a pretty-printed `AppLockerPolicy.xml` in the output folder.

#### Scenario: Pretty-printed policy exists
- Given an elevated run
- When collection completes
- Then `AppLockerPolicy.xml` exists and is indented for readability

### Requirement: R5 – Enforcement summary
The collector MUST write `EnforcementStatus.txt` listing each RuleCollection `Type: EnforcementMode`.

#### Scenario: Enforcement modes summarized
- Given an elevated run
- When collection completes
- Then `EnforcementStatus.txt` contains one line per RuleCollection with the mode

### Requirement: R6 – Expanded rules CSV
The collector MUST write `RulesSummary.csv` containing, per rule: `Collection, RuleId, Name, Action, RuleType, UserOrGroupSid, PublisherName, ProductName, BinaryName, MinVersion, MaxVersion, MinVersionInclusive, MaxVersionInclusive, Path, HashAlgorithm, Hashes, SourceFileNames`.

#### Scenario: Rules flattened to CSV
- Given an elevated run with at least one rule in each collection
- When collection completes
- Then `RulesSummary.csv` contains rows for Publisher, Path, and Hash rules with the fields populated (including SHA256 in `Hashes` where available)

### Requirement: R7 – AppLocker event logs (EVTX + CSV)
The collector MUST export EVTX via `wevtutil epl` and CSV via `Get-WinEvent` for:
- `Microsoft-Windows-AppLocker/EXE and DLL`
- `Microsoft-Windows-AppLocker/MSI and Script`
- `Microsoft-Windows-AppLocker/Packaged app-Deployment`
- `Microsoft-Windows-AppLocker/Packaged app-Execution`

#### Scenario: Event logs exported
- Given channels are present
- When collection completes
- Then corresponding `.evtx` and `.csv` files exist in the output folder

### Requirement: R8 – Warnings for non-fatal issues
The collector MUST continue on recoverable errors and append messages to `warnings.txt`.

#### Scenario: Missing channel recorded as warning
- Given a system without the “Packaged app-Deployment” channel
- When log export runs
- Then collection continues and a warning line is written to `warnings.txt`

### Requirement: R9 – Application Identity Service state
The collector MUST write `ApplicationIdentityService.txt` with the AppIDSvc service `Status` and `StartupType`.

#### Scenario: AppIDSvc state recorded
- Given an elevated run
- When collection completes
- Then `ApplicationIdentityService.txt` contains the current service status and startup type

### Requirement: R10 – Zip packaging
The collector MUST zip the output folder into `Get-AppLockerState-YYYY-MM-DD-HH-MM.zip` in Documents (same base name as the transcript log).

#### Scenario: Zip created
- Given an elevated run
- When collection completes
- Then a `.zip` exists in Documents and contains the entire output folder

### Requirement: R11 – Local time naming
The collector MUST use local time for all timestamped names.

#### Scenario: Local time used
- Given a known local timezone offset
- When the script runs
- Then folder/log/zip names reflect local time (not UTC)

### Requirement: R12 – Domain-join check warning only
The collector MUST warn (not fail) when the machine is not domain-joined.

#### Scenario: Not domain-joined
- Given a workgroup machine
- When the script runs
- Then collection proceeds and `warnings.txt` notes that the machine is not domain-joined

## Notes
- Requirements derived from `AppLockerSpec.md` to ensure behavior parity for the alpha build.
