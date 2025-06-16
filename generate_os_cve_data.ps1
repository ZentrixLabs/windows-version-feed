# Windows Versions and CVE Data Extraction Script
# Author: Patch Validation

# Get current date and format for CVRF ID (e.g., 2025-Jun)
$date = Get-Date -Format "yyyy-MM-dd"
$monthAbbr = (Get-Culture).DateTimeFormat.GetAbbreviatedMonthName((Get-Date).Month).Substring(0,3)
$month = "$($date.Substring(0,4))-$monthAbbr"

# Initialize debug log
$debugLog = "cvrf_mapping_debug_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
Write-Host "Debug log: $debugLog"
"Script started at $(Get-Date)" | Out-File -FilePath $debugLog -Append

# Try to fetch CVRF data
try {
    Write-Host "Attempting to fetch: https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/$month"
    $cvrf = Invoke-RestMethod "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/$month" -ErrorAction Stop
    "Successfully fetched CVRF data for $month" | Out-File -FilePath $debugLog -Append
}
catch {
    if ($_.Exception.Response.StatusCode.value__ -eq 404) {
        $prevMonthDate = (Get-Date).AddMonths(-1)
        $prevMonthAbbr = (Get-Culture).DateTimeFormat.GetAbbreviatedMonthName($prevMonthDate.Month).Substring(0,3)
        $month = "$($prevMonthDate.Year)-$prevMonthAbbr"
        Write-Warning "Current month not found. Falling back to: $month"
        Write-Host "Fallback URL: https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/$month"
        "404 for $month, falling back to $month" | Out-File -FilePath $debugLog -Append
        $cvrf = Invoke-RestMethod "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/$month" -ErrorAction Stop
        "Successfully fetched CVRF data for $month" | Out-File -FilePath $debugLog -Append
    }
    else {
        "Error fetching CVRF data: $($_.Exception.Message)" | Out-File -FilePath $debugLog -Append
        throw
    }
}

$doc = $cvrf.cvrfdoc

# Build dynamic OS list, excluding unwanted products
$osProducts = $doc.ProductTree.FullProductName | Where-Object {
    $_.'#text' -match 'Windows Server|Windows 10|Windows 11' -and
    $_.'#text' -notmatch 'Windows Server 2025|Preview|Insider|Windows HLK'
} | Select-Object ProductID, @{Name='ProductName';Expression={$_.'#text'}}

if (-not $osProducts) {
    Write-Warning "No OS products found."
    "No OS products found in CVRF data" | Out-File -FilePath $debugLog -Append
    exit
}
"Found $($osProducts.Count) OS products" | Out-File -FilePath $debugLog -Append

# Version mapping with build range validation
$versionMap = @{}
$buildRanges = @{
    'Windows Server 2016' = '10.0.14393.'
    'Windows Server 2019' = '10.0.17763.'
    'Windows Server 2022' = '10.0.20348.'
    'Windows 10 Version' = '10.0.1[89]0..'
    'Windows 11 Version' = '10.0.2[23]...'
}

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
        $version = '2022' # Use '2022' instead of 'LTSC' for consistency
    }

    $versionMap[$product.ProductID] = @{ Name = $name; Version = $version }
    Write-Host "DEBUG: Mapping ProductID $($product.ProductID): $name -> $version"
    "Mapped ProductID $($product.ProductID): $name -> $version" | Out-File -FilePath $debugLog -Append
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
            $_.Type -eq 'Vendor Fix' -and ($_.SubType -in @('Security Update', 'Security HotPatch Update'))
        }

        foreach ($rem in $remediations) {
            $kb = $rem.Description
            $fixedBuild = $rem.FixedBuild
            $remProductIds = $rem.ProductID

            foreach ($remProductId in $remProductIds) {
                if ($remProductId -in $osProductIds) {
                    $product = $osProducts | Where-Object { $_.ProductID -eq $remProductId }
                    $productName = $product.ProductName
                    $entryKey = "$cve-$kb-$remProductId"

                    # Validate build number against expected OS range
                    $osKey = switch -Wildcard ($productName) {
                        '*Windows Server 2016*' { 'Windows Server 2016' }
                        '*Windows Server 2019*' { 'Windows Server 2019' }
                        '*Windows Server 2022*' { 'Windows Server 2022' }
                        '*Windows 10*' { 'Windows 10 Version' }
                        '*Windows 11*' { 'Windows 11 Version' }
                        default { 'Unknown' }
                    }

                    if ($osKey -ne 'Unknown' -and $fixedBuild -notmatch $buildRanges[$osKey]) {
                        Write-Warning "Invalid build $fixedBuild for $productName (ProductID: $remProductId, KB: $kb, CVE: $cve)"
                        "Invalid build $fixedBuild for $productName (ProductID: $remProductId, KB: $kb, CVE: $cve)" | Out-File -FilePath $debugLog -Append
                        continue
                    }

                    if (-not $uniqueEntries.ContainsKey($entryKey)) {
                        $uniqueEntries[$entryKey] = $true
                        $kbCveMap += [PSCustomObject]@{
                            CVE           = $cve
                            KB            = $kb
                            ProductID     = $remProductId
                            ProductName   = $productName
                            FixedBuild    = $fixedBuild
                            Severity      = $baseScore
                            ExploitStatus = $exploitStatus
                            PublishedDate = ($vuln.RevisionHistory.Revision | Where-Object { $_.Number -eq '1.0' }).Date
                        }
                        Write-Host "DEBUG: Mapped CVE $cve to KB $kb for ProductID $remProductId ($productName)"
                        "Mapped CVE $cve to KB $kb for ProductID $remProductId ($productName)" | Out-File -FilePath $debugLog -Append
                    }
                }
            }
        }
    }
}

# Export kbCveMap to kb_cve_data.csv
try {
    Write-Host "Exporting kbCveMap to kb_cve_data.csv"
    $kbCveMap | Export-Csv -Path 'kb_cve_data.csv' -NoTypeInformation -Force -ErrorAction Stop
    "Successfully exported $($kbCveMap.Count) entries to kb_cve_data.csv" | Out-File -FilePath $debugLog -Append
}
catch {
    Write-Warning "Failed to export kb_cve_data.csv: $($_.Exception.Message)"
    "Failed to export kb_cve_data.csv: $($_.Exception.Message)" | Out-File -FilePath $debugLog -Append
    throw
}

# Build OS dataset
$osData = @()
$osGroups = $kbCveMap | Where-Object { $_.KB -ne 'Release Notes' } | Group-Object -Property {
    $name = $_.ProductName
    switch -Wildcard ($name) {
        '*Windows Server 2016*' { 'Windows Server 2016' }
        '*Windows Server 2019*' { 'Windows Server 2019' }
        '*Windows Server 2022*' { 
            if ($name -like '*23H2*') { 'Windows Server 2022 23H2' } else { 'Windows Server 2022' }
        }
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

    $version = $versionMap[$latestEntry.ProductID].Version ?? 'Unknown'

    $osData += [PSCustomObject]@{
        os          = $osName
        version     = $version
        build       = $latestEntry.FixedBuild -replace '^10\.0\.', ''
        latestKB    = "KB$($latestEntry.KB)"
        releaseDate = ($latestEntry.PublishedDate -replace 'T.*', '')
    }
}

if ($osData.Count -gt 0) {
    try {
        Write-Host "Exporting osData to windows-versions.json"
        $osData | ConvertTo-Json | Out-File -FilePath 'windows-versions.json' -Encoding UTF8 -ErrorAction Stop
        Copy-Item -Path 'windows-versions.json' -Destination 'windows-versions-current.json' -Force -ErrorAction Stop
        "Successfully exported osData to windows-versions.json" | Out-File -FilePath $debugLog -Append
    }
    catch {
        Write-Warning "Failed to export windows-versions.json: $($_.Exception.Message)"
        "Failed to export windows-versions.json: $($_.Exception.Message)" | Out-File -FilePath $debugLog -Append
        throw
    }
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
            '*Windows Server 2022*' { 
                if ($name -like '*23H2*') { 'Windows Server 2022 23H2' } else { 'Windows Server 2022' }
            }
            '*Windows 10*' { 
                if ($name -match 'Windows 10 Version ([\dA-Z]+)') { "Windows 10 Version $($matches[1])" } else { 'Windows 10' }
            }
            '*Windows 11*' { 
                if ($name -match 'Windows 11 Version ([\dA-Z]+)') { "Windows 11 Version $($matches[1])" } else { 'Windows 11' }
        }
            default { $name }
    }

    $cveMapping = [PSCustomObject]@{ cve = $cve; patches = @() }
    foreach ($group in $osGroups) {
        $latestEntry = $group.Group | Sort-Object FixedBuild -Descending | Select-Object -First 1
        if (-not $latestEntry) { continue }
        $name = $latestEntry.ProductName
        if (-not $name) { continue }

        $version = $versionMap[$latestEntry.ProductID].Version ?? 'Unknown'

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
    try {
        $monthForFile = "$($month.Substring(0,4))-$($month.Substring(5))"
        $monthlyCveFile = "CVE_KB_Mapping_$monthForFile.json"
        Write-Host "Exporting cveData to $monthlyCveFile"
        $cveData | ConvertTo-Json -Depth 3 | Out-File -FilePath $monthlyCveFile -Encoding UTF8 -ErrorAction Stop
        Copy-Item -Path $monthlyCveFile -Destination 'CVE_KB_Mapping_current.json' -Force -ErrorAction Stop
        "Successfully exported cveData to $monthlyCveFile" | Out-File -FilePath $debugLog -Append
    }
    catch {
        Write-Warning "Failed to export $monthlyCveFile: $($_.Exception.Message)"
        "Failed to export $monthlyCveFile: $($_.Exception.Message)" | Out-File -FilePath $debugLog -Append
        throw
    }
}

Write-Host "Script completed. Files generated:"
Get-ChildItem
"Script completed at $(Get-Date)" | Out-File -FilePath $debugLog -Append
