# Proposal: Add Registry Scanning for SRP Keys

- Change ID: add-registry-scanning
- Author: TBD
- Status: Draft
- Related Specs: `collector-cli`

## Summary
This change enhances the `Get-AppLockerState.ps1` script by adding the capability to export two critical registry keys related to Software Restriction Policies (SRP) and AppLocker. This provides a more complete diagnostic snapshot by capturing the underlying registry settings that can influence AppLocker's behavior.

## Motivation
While the effective policy is the most important artifact, the raw registry keys provide deeper context for troubleshooting complex GPO inheritance issues or misconfigurations. Capturing these keys alongside the existing artifacts creates a comprehensive, self-contained diagnostic package.

## Scope
- **Export SrpV2 Key**: Export the `HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\SrpV2` registry key to `SrpV2.reg` within the timestamped output folder.
- **Export SRP GP Key**: Export the `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SRP\GP` registry key to `SRPGP.reg` within the timestamped output folder.
- **Error Handling**: If a key does not exist, the script will log a warning and continue without failing.

## Non-Goals
- Parsing or interpreting the contents of the exported `.reg` files.
- Collecting any other registry keys.

## Success Criteria
- After a successful run of `Get-AppLockerState.ps1`, the `SrpV2.reg` and `SRPGP.reg` files are present in the output directory.
- If a registry key is not found, a warning is displayed in the console (in yellow) and logged to `warnings.txt`, and the script completes successfully.

## References
- Existing script: `Get-AppLockerState.ps1`
- Existing spec: `openspec/specs/collector-cli/spec.md`
