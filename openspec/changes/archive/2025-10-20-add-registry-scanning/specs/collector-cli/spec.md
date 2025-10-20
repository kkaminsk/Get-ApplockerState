# Capability: Collector CLI

## ADDED Requirements

### Requirement: R13 – Export SrpV2 Registry Key
The collector MUST export the `HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\SrpV2` registry key to `SrpV2.reg` in the output folder.

#### Scenario: SrpV2 key exported
- Given an elevated run on a machine where the `SrpV2` key exists
- When the collection script runs
- Then `SrpV2.reg` is created in the output folder

#### Scenario: SrpV2 key missing
- Given an elevated run on a machine where the `SrpV2` key does not exist
- When the collection script runs
- Then a warning is logged to the console and `warnings.txt`, and the script continues

### Requirement: R14 – Export SRP GP Registry Key
The collector MUST export the `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SRP\GP` registry key to `SRPGP.reg` in the output folder.

#### Scenario: SRP GP key exported
- Given an elevated run on a machine where the `SRP\GP` key exists
- When the collection script runs
- Then `SRPGP.reg` is created in the output folder

#### Scenario: SRP GP key missing
- Given an elevated run on a machine where the `SRP\GP` key does not exist
- When the collection script runs
- Then a warning is logged to the console and `warnings.txt`, and the script continues
