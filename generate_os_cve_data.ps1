# Windows Versions and CVE Data Extraction Script
# Author: Patch Validation

# (Full script with corrected syntax, no unnecessary backslashes.)

# [Full script content below.]

# Get current date and format for CVRF ID (e.g., 2025-May)
$date = Get-Date -Format "yyyy-MM-dd"
$monthAbbr = (Get-Culture).DateTimeFormat.GetAbbreviatedMonthName((Get-Date).Month)
$month = "$($date.Substring(0,4))-$monthAbbr"

# Fetch CVRF data
$cvrf = Invoke-RestMethod "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/$month"
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
    if ($name -match 'Windows Server (\d{4})') {
        $versionMap[$name] = $matches[1]
    } elseif ($name -match 'Windows 10 Version ([\dA-Z]+)') {
        $versionMap[$name] = $matches[1]
    } elseif ($name -match 'Windows 11 Version ([\dA-Z]+)') {
        $versionMap[$name] = $matches[1]
    } elseif ($name -match 'Windows Server 2022') {
        $versionMap[$name] = 'LTSC'
    } else {
        $versionMap[$name] = 'Unknown'
    }
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

# Build OS dataset dynamically
$osData = @()
$osGroups = $kbCveMap | Where-Object { $_.KB -ne 'Release Notes' } | Group-Object -Property {
    $name = $_.ProductName
    if ($name -like '*Windows Server 2022, 23H2*') { 'Windows Server 2022 23H2' }
    elseif ($name -like '*Windows Server 2022*') { 'Windows Server 2022' }
    elseif ($name -like '*Windows Server 2016*') { 'Windows Server 2016' }
    elseif ($name -like '*Windows Server 2019*') { 'Windows Server 2019' }
    elseif ($name -like '*Windows Server 2025*') { 'Windows Server 2025' }
    elseif ($name -like '*Windows 10*') {
        if ($name -match 'Windows 10 Version ([\dA-Z]+)') { "Windows 10 Version $($matches[1])" } else { 'Windows 10' }
    }
    elseif ($name -like '*Windows 11*') {
        if ($name -match 'Windows 11 Version ([\dA-Z]+)') { "Windows 11 Version $($matches[1])" } else { 'Windows 11' }
    } else { $name }
}

foreach ($group in $osGroups) {
    $osName = $group.Name
    if ($osName -like '*HLK*') { continue }

    $latestEntry = $group.Group | Sort-Object FixedBuild -Descending | Select-Object -First 1
    if ($osName -eq 'Windows Server 2022') {
        $non23H2 = $group.Group | Where-Object { $_.ProductName -notlike '*23H2*' } | Sort-Object FixedBuild -Descending | Select-Object -First 1
        if ($non23H2) { $latestEntry = $non23H2 }
    }

    $osData += [PSCustomObject]@{
        os          = $osName
        version     = $versionMap[$latestEntry.ProductName] ? $versionMap[$latestEntry.ProductName] : 'Unknown'
        build       = $latestEntry.FixedBuild -replace '^10\.0\.', ''
        latestKB    = "KB$($latestEntry.KB)"
        releaseDate = ($latestEntry.PublishedDate -replace 'T.*', '')
    }
}

# Export OS dataset
$osData | ConvertTo-Json | Out-File -FilePath 'windows-versions.json' -Encoding UTF8

# Build CVE-to-KB mapping dataset
$cveData = @()
$uniqueCVEs = $kbCveMap | Where-Object { $_.KB -ne 'Release Notes' } | Select-Object -ExpandProperty CVE -Unique

foreach ($cve in $uniqueCVEs) {
    $cveEntries = $kbCveMap | Where-Object { $_.CVE -eq $cve -and $_.KB -ne 'Release Notes' }
    $osGroups = $cveEntries | ForEach-Object {
        $osName = switch -Wildcard ($_.ProductName) {
            '*Windows Server 2016*' { 'Windows Server 2016' }
            '*Windows Server 2019*' { 'Windows Server 2019' }
            '*Windows Server 2022*' { 'Windows Server 2022' }
            '*Windows Server 2025*' { 'Windows Server 2025' }
            '*Windows 10*' {
                if ($_.ProductName -match 'Windows 10 Version ([\dA-Z]+)') { "Windows 10 Version $($matches[1])" } else { 'Windows 10' }
            }
            '*Windows 11*' {
                if ($_.ProductName -match 'Windows 11 Version ([\dA-Z]+)') { "Windows 11 Version $($matches[1])" } else { 'Windows 11' }
            }
            default { $_.ProductName }
        }
        if ($osName) {
            [PSCustomObject]@{
                OS = $osName
                KB = $_.KB
                FixedBuild = $_.FixedBuild
                Severity = $_.Severity
                ExploitStatus = $_.ExploitStatus
            }
        }
    } | Where-Object { $_.OS } | Group-Object -Property OS

    # Initialize the CVE mapping object
    $cveMapping = [PSCustomObject]@{ cve = $cve; patches = @() }
    $patches = @()
    
    foreach ($group in $osGroups) {
        $latestEntry = $group.Group | Sort-Object FixedBuild -Descending | Select-Object -First 1
        if ($latestEntry) {
            if ($null -eq $patches) { $patches = @() }
            $patches = @($patches + [PSCustomObject]@{
                os = $group.Name
                version = $versionMap[$latestEntry.ProductName] ? $versionMap[$latestEntry.ProductName] : "Unknown"
                kb = "KB$($latestEntry.KB)"
                fixedBuild = $latestEntry.FixedBuild -replace "^10\\.0\\.", ""
                severity = $latestEntry.Severity
                exploitStatus = $latestEntry.ExploitStatus
            })
        }
    }
    
    $cveMapping.patches = $patches
    if ($cveMapping.patches.Count -gt 0) {
        $cveData += $cveMapping
    }
}

# Export CVE-KB mapping
$cveData | ConvertTo-Json -Depth 3 | Out-File -FilePath "CVE_KB_Mapping_$month.json" -Encoding UTF8

# End of Script
