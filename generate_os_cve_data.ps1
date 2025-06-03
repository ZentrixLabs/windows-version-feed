# Windows Versions and CVE Data Extraction Script
# Author: Patch Validation

# Get current date and format for CVRF ID (e.g., 2025-May)
$date = Get-Date -Format "yyyy-MM-dd"
$monthAbbr = (Get-Culture).DateTimeFormat.GetAbbreviatedMonthName((Get-Date).Month)
$month = "$($date.Substring(0,4))-$monthAbbr"

# Try to fetch CVRF data
try {
    $cvrf = Invoke-RestMethod "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/$month"
}
catch {
    if ($_.Exception.Response.StatusCode.value__ -eq 404) {
        $prevMonthDate = (Get-Date).AddMonths(-1)
        $prevMonthAbbr = (Get-Culture).DateTimeFormat.GetAbbreviatedMonthName($prevMonthDate.Month).Substring(0,3)
        $month = "$($prevMonthDate.Year)-$prevMonthAbbr"

        Write-Warning "Current month not found. Falling back to: $month"
        Write-Host "Fallback URL: https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/$month"
        $cvrf = Invoke-RestMethod "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/$month"
    }
    else {
        throw
    }
}

$doc = $cvrf.cvrfdoc

# Build dynamic OS list
$osProducts = $doc.ProductTree.FullProductName | Where-Object {
    $_.'#text' -match 'Windows Server|Windows 10|Windows 11'
} | Select-Object ProductID, @{Name='ProductName';Expression={$_.'#text'}}

if (-not $osProducts) {
    Write-Warning "No OS products found."
    exit
}

# Version mapping
$versionMap = @{}
foreach ($product in $osProducts) {
    $name = $product.ProductName
    $version = 'Unknown'

    $serverMatch = [regex]::Match($name, 'Windows Server\s*(\d{4})', 'IgnoreCase')
    $win10Match = [regex]::Match($name, 'Windows 10\s+Version\s+([\dA-Z]+)', 'IgnoreCase')
    $win11Match = [regex]::Match($name, 'Windows 11\s+Version\s+([\dA-Z]+)', 'IgnoreCase')

    if ($serverMatch.Success) {
        $version = $serverMatch.Groups[1].Value
    }
    elseif ($win10Match.Success) {
        $version = $win10Match.Groups[1].Value
    }
    elseif ($win11Match.Success) {
        $version = $win11Match.Groups[1].Value
    }
    elseif ($name -like '*Windows Server 2022*') {
        $version = 'LTSC'
    }

    $versionMap[$name] = $version
    Write-Host "DEBUG: Mapping $name -> $version"
}

$osProductIds = $osProducts.ProductID
$kbCveMap = @()
$uniqueEntries = @{}

foreach ($vuln in $cvrf.cvrfdoc.Vulnerability) {
    $cve = $vuln.CVE
    $baseScore = ($vuln.CVSSScoreSets.ScoreSet | Select-Object -First 1).BaseScore
    $exploitStatus = ($vuln.Threats.Threat | Where-Object { $_.Type -eq 'Exploit Status' }).Description

    $affectedProductIds = $vuln.ProductStatuses.Status | Where-Object { $_.Type -eq 'Known Affected' } | Select-Object -ExpandProperty ProductID
    $matchingProductIds = $affectedProductIds | Where-Object { $_ -in $osProductIds }

    if ($matchingProductIds) {
        $remediations = $vuln.Remediations.Remediation | Where-Object {
            $_.Type -eq 'Vendor Fix' -and ($_.SubType -in @('Security Update', 'Security HotPatch Update', 'Release Notes'))
        }

        foreach ($rem in $remediations) {
            $kb = $rem.Description
            $fixedBuild = $rem.FixedBuild
            $remProductIds = $rem.ProductID

            foreach ($remProductId in $remProductIds) {
                if ($remProductId -in $osProductIds) {
                    $product = $osProducts | Where-Object { $_.ProductID -eq $remProductId }
                    $entryKey = "$cve-$kb-$remProductId"

                    if (-not $uniqueEntries.ContainsKey($entryKey)) {
                        $uniqueEntries[$entryKey] = $true
                        $kbCveMap += [PSCustomObject]@{
                            CVE           = $cve
                            KB            = $kb
                            ProductID     = $remProductId
                            ProductName   = $product.ProductName
                            FixedBuild    = $fixedBuild
                            Severity      = $baseScore
                            ExploitStatus = $exploitStatus
                            PublishedDate = ($vuln.RevisionHistory.Revision | Where-Object { $_.Number -eq '1.0' }).Date
                        }
                    }
                }
            }
        }
    }
}

# Build OS dataset
$osData = @()
$osGroups = $kbCveMap | Where-Object { $_.KB -ne 'Release Notes' } | Group-Object -Property {
    $name = $_.ProductName
    switch -Wildcard ($name) {
        '*Windows Server 2022, 23H2*' { 'Windows Server 2022 23H2' }
        '*Windows Server 2022*' { 'Windows Server 2022' }
        '*Windows Server 2016*' { 'Windows Server 2016' }
        '*Windows Server 2019*' { 'Windows Server 2019' }
        '*Windows Server 2025*' { 'Windows Server 2025' }
        '*Windows 10*' { 
            if ($name -match 'Windows 10 Version ([\dA-Z]+)') { "Windows 10 Version $($matches[1])" } else { 'Windows 10' }
        }
        '*Windows 11*' { 
            if ($name -match 'Windows 11 Version ([\dA-Z]+)') { "Windows 11 Version $($matches[1])" } else { 'Windows 11' }
        }
        default { $name }
    }
}

foreach ($group in $osGroups) {
    $osName = $group.Name
    if ($osName -like '*HLK*') { continue }

    $latestEntry = $group.Group | Sort-Object FixedBuild -Descending | Select-Object -First 1
    if (-not $latestEntry) { continue }
    $name = $latestEntry.ProductName
    if (-not $name) { continue }

    $version = $versionMap[$name] ?? 'Unknown'

    $osData += [PSCustomObject]@{
        os          = $osName
        version     = $version
        build       = $latestEntry.FixedBuild -replace '^10\.0\.', ''
        latestKB    = "KB$($latestEntry.KB)"
        releaseDate = ($latestEntry.PublishedDate -replace 'T.*', '')
    }
}

if ($osData.Count -gt 0) {
    $osData | ConvertTo-Json | Out-File -FilePath 'windows-versions.json' -Encoding UTF8
    Copy-Item -Path 'windows-versions.json' -Destination 'windows-versions-current.json' -Force
}

# CVE-to-KB mapping
$cveData = @()
$uniqueCVEs = $kbCveMap | Where-Object { $_.KB -ne 'Release Notes' } | Select-Object -ExpandProperty CVE -Unique

foreach ($cve in $uniqueCVEs) {
    $cveEntries = $kbCveMap | Where-Object { $_.CVE -eq $cve -and $_.KB -ne 'Release Notes' }
    $osGroups = $cveEntries | Group-Object -Property {
        $name = $_.ProductName
        switch -Wildcard ($name) {
            '*Windows Server 2016*' { 'Windows Server 2016' }
            '*Windows Server 2019*' { 'Windows Server 2019' }
            '*Windows Server 2022*' { 'Windows Server 2022' }
            '*Windows Server 2025*' { 'Windows Server 2025' }
            '*Windows 10*' { 
                if ($name -match 'Windows 10 Version ([\dA-Z]+)') { "Windows 10 Version $($matches[1])" } else { 'Windows 10' }
            }
            '*Windows 11*' { 
                if ($name -match 'Windows 11 Version ([\dA-Z]+)') { "Windows 11 Version $($matches[1])" } else { 'Windows 11' }
            }
            default { $name }
        }
    }

    $cveMapping = [PSCustomObject]@{ cve = $cve; patches = @() }
    foreach ($group in $osGroups) {
        $latestEntry = $group.Group | Sort-Object FixedBuild -Descending | Select-Object -First 1
        if (-not $latestEntry) { continue }
        $name = $latestEntry.ProductName
        if (-not $name) { continue }

        $version = $versionMap[$name] ?? 'Unknown'

        $cveMapping.patches += [PSCustomObject]@{
            os = $group.Name
            version = $version
            kb = "KB$($latestEntry.KB)"
            fixedBuild = $latestEntry.FixedBuild -replace '^10\.0\.', ''
            severity = $latestEntry.Severity
            exploitStatus = $latestEntry.ExploitStatus
        }
    }
    if ($cveMapping.patches.Count -gt 0) {
        $cveData += $cveMapping
    }
}

if ($cveData.Count -gt 0) {
    $monthForFile = "$($month.Substring(0,4))-$($month.Substring(5))"
    $monthlyCveFile = "CVE_KB_Mapping_$monthForFile.json"
    $cveData | ConvertTo-Json -Depth 3 | Out-File -FilePath $monthlyCveFile -Encoding UTF8
    Copy-Item -Path $monthlyCveFile -Destination 'CVE_KB_Mapping_current.json' -Force
}

Write-Host "Script completed. Files generated:"
Get-ChildItem
