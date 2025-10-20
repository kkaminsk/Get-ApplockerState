$ErrorActionPreference = 'Stop'

# Resolve Documents folder and timestamp
$docs   = [Environment]::GetFolderPath('MyDocuments')
$stamp  = Get-Date -Format 'yyyy-MM-dd-HH-mm'
$outDir = Join-Path $docs "Get-AppLockerState-$stamp"
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

# Start transcript in Documents root
$logPath = Join-Path $docs  "Get-AppLockerState-$stamp.log"
Start-Transcript -Path $logPath -Force | Out-Null

try {
    # PowerShell 5.1 check
    $psv = $PSVersionTable.PSVersion
    if (-not ($psv.Major -eq 5 -and $psv.Minor -ge 1)) {
        "Unsupported PowerShell version: $($psv.ToString()). Requires Windows PowerShell 5.1." |
            Tee-Object -FilePath (Join-Path $outDir 'warnings.txt') -Append | ForEach-Object { Write-Warning $_ }
        Stop-Transcript | Out-Null
        exit 1
    }

    # Elevation check (fail fast)
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        "Not running as Administrator. Exiting." |
            Tee-Object -FilePath (Join-Path $outDir 'warnings.txt') -Append | ForEach-Object { Write-Warning $_ }
        Stop-Transcript | Out-Null
        exit 1
    }

    # Domain membership warning (do not fail)
    try {
        $partOfDomain = (Get-CimInstance Win32_ComputerSystem).PartOfDomain
        if (-not $partOfDomain) {
            "Machine is not domain-joined." |
                Tee-Object -FilePath (Join-Path $outDir 'warnings.txt') -Append | ForEach-Object { Write-Warning $_ }
        }
    } catch {
        "Unable to determine domain membership: $($_.Exception.Message)" |
            Tee-Object -FilePath (Join-Path $outDir 'warnings.txt') -Append | ForEach-Object { Write-Warning $_ }
    }

    # 1) Export Effective AppLocker Policy (Pretty XML)
    $policyXmlPath = Join-Path $outDir 'AppLockerPolicy.xml'
    try {
        [xml]$doc = (Get-AppLockerPolicy -Effective -Xml)
        $settings = New-Object System.Xml.XmlWriterSettings
        $settings.Indent = $true
        $writer = [System.Xml.XmlWriter]::Create($policyXmlPath, $settings)
        $doc.Save($writer)
        $writer.Close()
    } catch {
        "Failed to export AppLocker policy: $($_.Exception.Message)" |
            Tee-Object -FilePath (Join-Path $outDir 'warnings.txt') -Append | ForEach-Object { Write-Warning $_ }
    }

    # 2) Summarize Enforcement per RuleCollection
    $enfPath = Join-Path $outDir 'EnforcementStatus.txt'
    try {
        [xml]$x = Get-Content -Path $policyXmlPath -ErrorAction Stop
        $lines = foreach ($rc in $x.AppLockerPolicy.RuleCollection) {
            '{0}: {1}' -f $rc.Type, $rc.EnforcementMode
        }
        if ($lines) { $lines | Set-Content -Path $enfPath -Encoding UTF8 }
    } catch {
        "Failed to summarize enforcement modes: $($_.Exception.Message)" |
            Tee-Object -FilePath (Join-Path $outDir 'warnings.txt') -Append | ForEach-Object { Write-Warning $_ }
    }

    # 3) Export RulesSummary.csv (Expanded Schema)
    $csvPath = Join-Path $outDir 'RulesSummary.csv'
    try {
        if (-not $x) { [xml]$x = Get-Content -Path $policyXmlPath -ErrorAction Stop }

        function Get-VersionRange {
            param($cond)
            $min = $null; $max = $null; $minInc = $null; $maxInc = $null
            if ($cond -and $cond.BinaryVersionRange) {
                $min    = $cond.BinaryVersionRange.LowSection.Version
                $max    = $cond.BinaryVersionRange.HighSection.Version
                $minInc = $cond.BinaryVersionRange.LowSection.Type  -eq 'Inclusive'
                $maxInc = $cond.BinaryVersionRange.HighSection.Type -eq 'Inclusive'
            }
            [pscustomobject]@{ Min=$min; Max=$max; MinInc=$minInc; MaxInc=$maxInc }
        }

        $rows = foreach ($rc in $x.AppLockerPolicy.RuleCollection) {
            $collection = $rc.Type

            # Publisher rules
            foreach ($r in @($rc.FilePublisherRule)) {
                if (-not $r) { continue }
                $sid = $r.UserOrGroupSid
                $cond = $r.Conditions.FilePublisherCondition
                if (-not $cond) { $cond = $r.Conditions.PublisherCondition }
                $vr = Get-VersionRange $cond
                [pscustomobject]@{
                    Collection           = $collection
                    RuleId               = $r.Id
                    Name                 = $r.Name
                    Action               = $r.Action
                    RuleType             = 'FilePublisherRule'
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

            # Path rules
            foreach ($r in @($rc.FilePathRule)) {
                if (-not $r) { continue }
                $sid = $r.UserOrGroupSid
                $path = $r.Conditions.FilePathCondition.Path
                [pscustomobject]@{
                    Collection           = $collection
                    RuleId               = $r.Id
                    Name                 = $r.Name
                    Action               = $r.Action
                    RuleType             = 'FilePathRule'
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

            # Hash rules
            foreach ($r in @($rc.FileHashRule)) {
                if (-not $r) { continue }
                $sid = $r.UserOrGroupSid
                $hashes = @($r.Conditions.FileHashCondition.FileHash)
                [pscustomobject]@{
                    Collection           = $collection
                    RuleId               = $r.Id
                    Name                 = $r.Name
                    Action               = $r.Action
                    RuleType             = 'FileHashRule'
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

        if ($rows) { $rows | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8 }
    } catch {
        "Failed to export RulesSummary.csv: $($_.Exception.Message)" |
            Tee-Object -FilePath (Join-Path $outDir 'warnings.txt') -Append | ForEach-Object { Write-Warning $_ }
    }

    # 4) Export AppLocker Event Logs (EVTX + CSV)
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

      try { wevtutil epl "$log" "$evtx" } catch {
        "Failed EVTX export for ${log}: $($_.Exception.Message)" |
          Tee-Object -FilePath (Join-Path $outDir 'warnings.txt') -Append | ForEach-Object { Write-Warning $_ }
      }
      try {
        Get-WinEvent -LogName "$log" -ErrorAction Stop |
          Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8
      } catch {
        "Failed CSV export for ${log}: $($_.Exception.Message)" |
          Tee-Object -FilePath (Join-Path $outDir 'warnings.txt') -Append | ForEach-Object { Write-Warning $_ }
      }
    }

    # 5) Record AppIDSvc State
    $appIdPath = Join-Path $outDir 'ApplicationIdentityService.txt'
    try {
        $svc = Get-Service -Name 'AppIDSvc' -ErrorAction Stop
        $cim = Get-CimInstance -ClassName Win32_Service -Filter "Name='AppIDSvc'"
        @(
            "Status:       $($svc.Status)",
            "StartupType:  $($cim.StartMode)"
        ) | Set-Content -Path $appIdPath -Encoding UTF8
    } catch {
        "AppIDSvc not found or inaccessible: $($_.Exception.Message)" |
            Tee-Object -FilePath (Join-Path $outDir 'warnings.txt') -Append | ForEach-Object { Write-Warning $_ }
    }

    # 6) Export SRP Registry Keys
    try {
        $srpV2Path = Join-Path $outDir 'SrpV2.reg'
        reg.exe export 'HKLM\Software\Policies\Microsoft\Windows\SrpV2' "$srpV2Path" /y
    } catch {
        "Registry key 'HKLM\Software\Policies\Microsoft\Windows\SrpV2' not found or could not be exported: $($_.Exception.Message)" |
            Tee-Object -FilePath (Join-Path $outDir 'warnings.txt') -Append | ForEach-Object { Write-Warning $_ }
    }

    try {
        $srpGpPath = Join-Path $outDir 'SRPGP.reg'
        reg.exe export 'HKLM\System\CurrentControlSet\Control\SRP\GP' "$srpGpPath" /y
    } catch {
        "Registry key 'HKLM\System\CurrentControlSet\Control\SRP\GP' not found or could not be exported: $($_.Exception.Message)" |
            Tee-Object -FilePath (Join-Path $outDir 'warnings.txt') -Append | ForEach-Object { Write-Warning $_ }
    }

    # 7) Zip output folder in Documents with same base as transcript
    try {
        $zipPath = Join-Path $docs "Get-AppLockerState-$stamp.zip"
        if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
        Compress-Archive -Path $outDir -DestinationPath $zipPath
    } catch {
        "Failed to create zip: $($_.Exception.Message)" |
            Tee-Object -FilePath (Join-Path $outDir 'warnings.txt') -Append | ForEach-Object { Write-Warning $_ }
    }

} finally {
    try { Stop-Transcript | Out-Null } catch { }
}
