# Tasks: add-registry-scanning

1. **Modify `collector-cli` spec**
   - Add two new requirements (R13, R14) for exporting the `SrpV2` and `SRP\GP` registry keys.
   - Include scenarios for both successful export and for when the keys are missing.
   - Validation: The spec file is updated with the new requirements.

2. **Implement `SrpV2` registry export**
   - Modify `Get-AppLockerState.ps1` to use `reg.exe export` to save the `HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\SrpV2` key to `SrpV2.reg` in the output folder.
   - Add a `try/catch` block to handle cases where the key does not exist, logging a warning to the console and `warnings.txt`.
   - Validation: Running the script produces `SrpV2.reg` if the key exists, or a warning if it does not.

3. **Implement `SRP\GP` registry export**
   - Modify `Get-AppLockerState.ps1` to use `reg.exe export` to save the `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SRP\GP` key to `SRPGP.reg` in the output folder.
   - Add a `try/catch` block for error handling and warnings, similar to the `SrpV2` export.
   - Validation: Running the script produces `SRPGP.reg` if the key exists, or a warning if it does not.

4. **Update `README.md`**
   - Add `SrpV2.reg` and `SRPGP.reg` to the list of outputs in the `README.md` file.
   - Validation: The README correctly lists the new files.

5. **Smoke Test**
   - Run the updated script in an elevated PowerShell 5.1 session.
   - Verify the `.reg` files are created or that warnings are appropriately logged if the keys are absent.
   - Validation: The script completes without unhandled errors and all expected artifacts are present.
