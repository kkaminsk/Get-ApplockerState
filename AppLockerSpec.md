To check the AppLocker policy on a domain-joined device using PowerShell, you can use the Get-AppLockerPolicy cmdlet. For the most accurate and comprehensive view of what is being enforced, you'll want to look at the "effective" policy. This takes into account local policies and any Group Policies (GPOs) applied from the domain.

Here's how to do it and what to look for:

### **1\. View the Effective AppLocker Policy**

To see the AppLocker policy that is currently in effect on the computer, run the following command in a PowerShell window with administrative privileges:

PowerShell

Get-AppLockerPolicy \-Effective

This command will output the policy object, which can be a bit difficult to read directly in the console. Store this output as AppLockerPolicy.txt.

### **2\. Export the Policy to XML for Better Readability**

For a much clearer view of the policy, it's highly recommended to export it to an XML file. This allows you to open the file in any text editor or XML viewer to examine the rules and enforcement settings.

PowerShell

Get-AppLockerPolicy \-Effective \-XML \> C:\\Temp\\AppLockerPolicy.xml

Review this method as I want readable XML formatting if possible.

---

### **What to Look for in the AppLocker Policy**

When you examine the XML output or the direct PowerShell object, you'll want to pay attention to a few key areas to understand the AppLocker configuration:

#### **Rule Collections**

AppLocker policies are organized into different rule collections for various file types. Look for sections like:

* **Exe**: Rules for executable files (.exe, .com).  
* **Msi**: Rules for Windows Installer files (.msi, .msp).  
* **Script**: Rules for scripts (.ps1, .bat, .cmd, .vbs, .js).  
* **PackagedApp**: Rules for modern Windows apps.  
* **Dll**: Rules for Dynamic Link Libraries (.dll, .ocx).

#### **Enforcement Mode**

Within each rule collection, you'll find the **EnforcementMode**. This is a critical setting that determines what AppLocker does when a user tries to run a file that is not explicitly allowed. The possible values are:

* **Enabled** (or **Enforce rules** in the GUI): AppLocker will block any files that are not allowed by a rule.  
* **Audit** (or **Audit only** in the GUI): AppLocker will not block any files. Instead, it will log an event to the Windows Event Log indicating that the file would have been blocked. This is often used for testing policies before full enforcement.6  
* **NotConfigured**: If no rules are defined for a rule collection and the enforcement mode is not configured, AppLocker will not enforce any rules for that file type.

Here's an example snippet of what you might see in the XML output, showing the enforcement mode for EXE files:

XML

\<RuleCollection Type\="Exe" EnforcementMode\="Enabled"\>

#### Create an EnforcementStatus.txt file and summarize the RuleCollection states.

#### **Rules**

Under each RuleCollection, you will see the individual rules. Each rule will have attributes that define how it identifies a file, such as:

* **Publisher Rule**: Identifies files based on their digital signature (Publisher, Product name, File name, and File version).  
* **Path Rule**: Identifies files based on the directory or file path they are located in.  
* **File Hash Rule**: Identifies a specific file based on its cryptographic hash.

Each rule will also specify an **Action** of either **Allow** or **Deny**.

By examining these components, you can get a complete picture of the AppLocker configuration on the domain-joined device.

Summarize the rules in an easy to read format.

Export all windows logs for AppLocker.

* EXE and DLL  
* MSI and Script  
* Packaged App Deployment  
* Packaged app Execution
 Log output to the documents folder as the Get-AppLockerState-YYYY-MM-DD-HH-MM.log.

---

# Get-AppLockerState - Comprehensive Collection Specification

This section defines an end-to-end, reproducible collection process for AppLocker state and related telemetry on a domain-joined Windows device.

## Supported Platforms and Requirements

- **Windows versions**: Windows 10, Windows 11, Windows Server 2016, 2019, 2022
- **PowerShell**: Windows PowerShell 5.1
- **Permissions**: Must run in an elevated PowerShell session (Administrator). If not elevated, the process must fail fast.
- **Scope**: Collects the local effective policy on the current domain-joined machine. No LDAP/domain-policy retrieval is performed.

## Output Locations and Naming

- **Timestamp**: Local time, format `yyyy-MM-dd-HH-mm`.
- **Transcript log (Documents root)**: `Get-AppLockerState-YYYY-MM-DD-HH-MM.log`
- **Output folder (Documents)**: `Get-AppLockerState-YYYY-MM-DD-HH-MM/`
  - `AppLockerPolicy.xml` (pretty-printed)
  - `EnforcementStatus.txt`
  - `RulesSummary.csv`
  - `Microsoft-Windows-AppLocker_EXE_and_DLL.evtx` and `.csv`
  - `Microsoft-Windows-AppLocker_MSI_and_Script.evtx` and `.csv`
  - `Microsoft-Windows-AppLocker_Packaged_app-Deployment.evtx` and `.csv`
  - `Microsoft-Windows-AppLocker_Packaged_app-Execution.evtx` and `.csv`
  - `ApplicationIdentityService.txt`
  - `warnings.txt` (if any warnings were produced)
- **Zip (Documents root)**: `Get-AppLockerState-YYYY-MM-DD-HH-MM.zip` (same base name as the transcript log), containing the entire output folder.

## Collection Steps

1. **Session Setup and Validation**
  - Verify Windows PowerShell 5.1.
  - Verify elevation; if not elevated, write a clear message to console and `warnings.txt`, then exit with an error code (no further collection).
  - Detect domain-join status. If not domain-joined, proceed but write a warning to `warnings.txt`.
  - Create the timestamped output folder under the current user’s Documents and start a PowerShell transcript in Documents using the required file name.

  ```powershell
  $docs   = [Environment]::GetFolderPath('MyDocuments')
  $stamp  = Get-Date -Format 'yyyy-MM-dd-HH-mm'
  $outDir = Join-Path $docs "Get-AppLockerState-$stamp"
  New-Item -ItemType Directory -Path $outDir -Force | Out-Null

  $logPath = Join-Path $docs  "Get-AppLockerState-$stamp.log"
  Start-Transcript -Path $logPath -Force

  # Elevation check (fail fast)
  $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  if (-not $isAdmin) {
    "Not running as Administrator. Exiting." | Tee-Object -FilePath (Join-Path $outDir 'warnings.txt') -Append
    Stop-Transcript | Out-Null
    exit 1
  }

  # Domain membership warning (do not fail)
  try {
    $partOfDomain = (Get-CimInstance Win32_ComputerSystem).PartOfDomain
    if (-not $partOfDomain) { "Machine is not domain-joined." | Tee-Object -FilePath (Join-Path $outDir 'warnings.txt') -Append }
  } catch { "Unable to determine domain membership: $($_.Exception.Message)" | Tee-Object -FilePath (Join-Path $outDir 'warnings.txt') -Append }
  ```

2. **Export Effective AppLocker Policy (Pretty XML)**
  - Export the effective policy with `Get-AppLockerPolicy -Effective -Xml`.
  - Pretty-print to `AppLockerPolicy.xml` for readability.

  ```powershell
  $policyXmlPath = Join-Path $outDir 'AppLockerPolicy.xml'
  [xml]$doc = (Get-AppLockerPolicy -Effective -Xml)
  $settings = New-Object System.Xml.XmlWriterSettings
  $settings.Indent = $true
  $writer = [System.Xml.XmlWriter]::Create($policyXmlPath, $settings)
  $doc.Save($writer)
  $writer.Close()
  ```

3. **Summarize Enforcement per RuleCollection**
  - Write `Type: EnforcementMode` for each `RuleCollection` to `EnforcementStatus.txt`.

  ```powershell
  $enfPath = Join-Path $outDir 'EnforcementStatus.txt'
  [xml]$x = Get-Content -Path $policyXmlPath
  $x.AppLockerPolicy.RuleCollection |
    ForEach-Object { "{0}: {1}" -f $_.Type, $_.EnforcementMode } |
    Set-Content -Path $enfPath -Encoding UTF8
  ```

4. **Export RulesSummary.csv (Expanded Schema)**
  - Flatten rules across collections with the following columns:
    - `Collection`, `RuleId`, `Name`, `Action`, `RuleType`, `UserOrGroupSid`
    - Publisher rules: `PublisherName`, `ProductName`, `BinaryName`, `MinVersion`, `MaxVersion`, `MinVersionInclusive`, `MaxVersionInclusive`
    - Path rules: `Path`
    - Hash rules: `HashAlgorithm`, `Hashes`, `SourceFileNames`

  ```powershell
  $csvPath = Join-Path $outDir 'RulesSummary.csv'
  [xml]$x = Get-Content -Path $policyXmlPath

  function Get-VersionRange {
    param($cond)
    # AppLocker XML expresses version ranges with LowSection/HighSection (and inclusivity flags)
    $min = $null; $max = $null; $minInc = $null; $maxInc = $null
    if ($cond.BinaryVersionRange) {
      $min    = $cond.BinaryVersionRange.LowSection.Version
      $max    = $cond.BinaryVersionRange.HighSection.Version
      $minInc = $cond.BinaryVersionRange.LowSection.Type  -eq 'Inclusive'
      $maxInc = $cond.BinaryVersionRange.HighSection.Type -eq 'Inclusive'
    }
    [pscustomobject]@{ Min=$min; Max=$max; MinInc=$minInc; MaxInc=$maxInc }
  }

  $rows = foreach ($rc in $x.AppLockerPolicy.RuleCollection) {
    $collection = $rc.Type
    foreach ($r in @($rc.FilePublisherRule + $rc.FilePathRule + $rc.FileHashRule)) {
      if (-not $r) { continue }
      $ruleType = $r.LocalName
      $sid = $r.UserOrGroupSid

      switch ($ruleType) {
        'FilePublisherRule' {
          $cond = $r.Conditions.PublisherCondition
          $vr = Get-VersionRange $cond
          [pscustomobject]@{
            Collection           = $collection
            RuleId               = $r.Id
            Name                 = $r.Name
            Action               = $r.Action
            RuleType             = $ruleType
            UserOrGroupSid       = $sid
            PublisherName        = $cond.PublisherName
            ProductName          = $cond.ProductName
            BinaryName           = $cond.BinaryName
            MinVersion           = $vr.Min
            MaxVersion           = $vr.Max
            MinVersionInclusive  = $vr.MinInc
            MaxVersionInclusive  = $vr.MaxInc
            Path                 = $null
            HashAlgorithm        = $null
            Hashes               = $null
            SourceFileNames      = $null
          }
        }
        'FilePathRule' {
          $path = $r.Conditions.FilePathCondition.Path
          [pscustomobject]@{
            Collection           = $collection
            RuleId               = $r.Id
            Name                 = $r.Name
            Action               = $r.Action
            RuleType             = $ruleType
            UserOrGroupSid       = $sid
            PublisherName        = $null
            ProductName          = $null
            BinaryName           = $null
            MinVersion           = $null
            MaxVersion           = $null
            MinVersionInclusive  = $null
            MaxVersionInclusive  = $null
            Path                 = $path
            HashAlgorithm        = $null
            Hashes               = $null
            SourceFileNames      = $null
          }
        }
        'FileHashRule' {
          $hashes = @($r.Conditions.FileHashCondition.FileHash)
          [pscustomobject]@{
            Collection           = $collection
            RuleId               = $r.Id
            Name                 = $r.Name
            Action               = $r.Action
            RuleType             = $ruleType
            UserOrGroupSid       = $sid
            PublisherName        = $null
            ProductName          = $null
            BinaryName           = $null
            MinVersion           = $null
            MaxVersion           = $null
            MinVersionInclusive  = $null
            MaxVersionInclusive  = $null
            Path                 = $null
            HashAlgorithm        = ($hashes | Select-Object -First 1).Algorithm
            Hashes               = ($hashes | ForEach-Object { $_.Hash }) -join '; '
            SourceFileNames      = ($hashes | ForEach-Object { $_.SourceFileName }) -join '; '
          }
        }
      }
    }
  }

  $rows | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
  ```

5. **Export AppLocker Event Logs (EVTX + CSV)**
  - Export EVTX via `wevtutil epl` and CSV via `Get-WinEvent` for each channel.
  - Missing channels should not fail the run; write warnings to `warnings.txt`.

  ```powershell
  $applockerLogs = @(
    'Microsoft-Windows-AppLocker/EXE and DLL',
    'Microsoft-Windows-AppLocker/MSI and Script',
    'Microsoft-Windows-AppLocker/Packaged app-Deployment',
    'Microsoft-Windows-AppLocker/Packaged app-Execution'
  )

  foreach ($log in $applockerLogs) {
    $safeName = ($log -replace '[^A-Za-z0-9]+','_')
    $evtx = Join-Path $outDir "$safeName.evtx"
    $csv  = Join-Path $outDir "$safeName.csv"

    try { wevtutil epl "$log" "$evtx" }
    catch { "Failed EVTX export for $log: $($_.Exception.Message)" | Tee-Object -FilePath (Join-Path $outDir 'warnings.txt') -Append }

    try {
      Get-WinEvent -LogName "$log" -ErrorAction Stop |
        Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8
    }
    catch { "Failed CSV export for $log: $($_.Exception.Message)" | Tee-Object -FilePath (Join-Path $outDir 'warnings.txt') -Append }
  }
  ```

6. **Record Application Identity Service (AppIDSvc) State**
  - Save the service status and startup type to `ApplicationIdentityService.txt`.

  ```powershell
  $appIdPath = Join-Path $outDir 'ApplicationIdentityService.txt'
  try {
    $svc = Get-Service -Name 'AppIDSvc' -ErrorAction Stop
    $cim = Get-CimInstance -ClassName Win32_Service -Filter "Name='AppIDSvc'"
    @(
      "Status:       $($svc.Status)",
      "StartupType:  $($cim.StartMode)"
    ) | Set-Content -Path $appIdPath -Encoding UTF8
  } catch {
    "AppIDSvc not found or inaccessible: $($_.Exception.Message)" | Tee-Object -FilePath (Join-Path $outDir 'warnings.txt') -Append
  }
  ```

7. **Package Output (Zip)**
  - Create a zip in Documents with the same base name as the transcript log.

  ```powershell
  $zipPath = Join-Path $docs "Get-AppLockerState-$stamp.zip"
  if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
  Compress-Archive -Path $outDir -DestinationPath $zipPath
  ```

8. **Finish**
  - Stop the transcript and return success.

  ```powershell
  Stop-Transcript | Out-Null
  ```

## Validation

- **Enforcement modes**: Compare `EnforcementStatus.txt` with the AppLocker MMC snap-in.
- **Rules**: Spot-check `RulesSummary.csv` entries against `AppLockerPolicy.xml`.
- **Logs**: Open EVTX files in Event Viewer to confirm expected events exist.
- **AppIDSvc**: Ensure the service state aligns with policy enforcement expectations.

## Troubleshooting

- **Not elevated**: The run must exit immediately. Rerun as Administrator.
- **No AppLocker events**: Policy may not be applied, or auditing/enforcement may be disabled.
- **PowerShell 7**: Not supported for collection (use Windows PowerShell 5.1).
- **Non-domain device**: Collection continues, but `warnings.txt` will note it.