# Tasks: introduce-alpha-build

1. Implement script entrypoint
   - Create `Get-AppLockerState.ps1` (Windows PowerShell 5.1).
   - Add elevation check (fail fast if not admin).
   - Start transcript in Documents with local-time naming per spec.
   - Create timestamped output folder under Documents.
   - Validation: Running non-admin exits with error; admin run creates log and folder.

2. Export effective AppLocker policy (pretty XML)
   - Use `Get-AppLockerPolicy -Effective -Xml` and pretty-print to `AppLockerPolicy.xml`.
   - Validation: XML is indented/readable; file present in output folder.

3. Summarize enforcement per RuleCollection
   - Write `EnforcementStatus.txt` as `Type: EnforcementMode` per collection.
   - Validation: Matches MMC AppLocker snap-in for sample system.

4. Generate expanded `RulesSummary.csv`
   - Columns: `Collection, RuleId, Name, Action, RuleType, UserOrGroupSid, PublisherName, ProductName, BinaryName, MinVersion, MaxVersion, MinVersionInclusive, MaxVersionInclusive, Path, HashAlgorithm, Hashes, SourceFileNames`.
   - Validation: Spot-check against `AppLockerPolicy.xml`; include SHA256 where available.

5. Export AppLocker event logs
   - Channels: EXE and DLL; MSI and Script; Packaged app-Deployment; Packaged app-Execution.
   - Export EVTX via `wevtutil epl` and CSV via `Get-WinEvent`.
   - Validation: EVTX and CSV files exist; if channels missing, `warnings.txt` contains messages.

6. Record Application Identity Service state
   - Write `ApplicationIdentityService.txt` with service Status and StartupType.
   - Validation: File contains values matching `Get-Service AppIDSvc` and `Win32_Service`.

7. Warnings handling
   - Any non-fatal issue appends a line to `warnings.txt` in the output folder.
   - Validation: Simulate missing logs to confirm warnings are recorded.

8. Zip packaging
   - Create `Get-AppLockerState-YYYY-MM-DD-HH-MM.zip` in Documents with the entire output folder.
   - Validation: Zip exists and includes all artifacts.

9. README update
   - Add a basic Usage section explaining prerequisites and how to run the script.
   - Validation: README renders correctly and references expected outputs.

10. Smoke tests on target OS versions
   - Validate on at least one Windows 10/11 and one Server (e.g., 2019) environment.
   - Validation: Artifacts created and contain expected content; no unhandled exceptions.

11. Prepare for alpha release (manual)
   - Tag naming guidance and manual GitHub Release notes (no automation in alpha).
   - Validation: Draft release instructions included in repository.
