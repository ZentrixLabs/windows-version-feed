# Get current date and format for CVRF ID (e.g., 2025-May)
$date = Get-Date -Format "yyyy-MM-dd"
$monthAbbr = (Get-Culture).DateTimeFormat.GetAbbreviatedMonthName((Get-Date).Month)
$month = "$($date.Substring(0,4))-$monthAbbr"  # e.g., 2025-May


# Grab latest update for May 2025
$cvrf = Invoke-RestMethod "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/$month"
$doc = $cvrf.cvrfdoc

# Define server versions for filtering
$serverVersions = @(
    "*Windows Server 2016*",
    "*Windows Server 2019*",
    "*Windows Server 2022*",
    "*Windows Server 2025*"
)

# Hardcode version mappings (since not in $kbCveMap)
$versionMap = @{
    "Windows Server 2025" = "LTSC"
    "Windows Server 2022" = "LTSC"
    "Windows Server 2019" = "1809"
    "Windows Server 2016" = "1607"
}

# Build $serverProducts dynamically
$serverProducts = $doc.ProductTree.FullProductName | Where-Object {
    $productName = $_.'#text'
    $serverVersions | ForEach-Object { if ($productName -like $_) { $true } }
} | Select-Object ProductID, @{Name='ProductName';Expression={$_.'#text'}}

if (-not $serverProducts) {
    Write-Warning "No server products found for specified versions."
    exit
}
# Extract product IDs for filtering
$serverProductIds = $serverProducts.ProductID

# Initialize KB-to-CVE mapping
$kbCveMap = @()

# Track unique entries to avoid duplicates
$uniqueEntries = @{}

# Iterate through vulnerabilities
foreach ($vuln in $cvrf.cvrfdoc.Vulnerability) {
    $cve = $vuln.CVE
    $baseScore = ($vuln.CVSSScoreSets.ScoreSet | Select-Object -First 1).BaseScore
    $exploitStatus = ($vuln.Threats.Threat | Where-Object { $_.Type -eq "Exploit Status" }).Description

    # Get affected product IDs
    $affectedProductIds = $vuln.ProductStatuses.Status | Where-Object { $_.Type -eq "Known Affected" } | Select-Object -ExpandProperty ProductID

    # Check if any affected product IDs match server products
    $matchingProductIds = $affectedProductIds | Where-Object { $_ -in $serverProductIds }
    if ($matchingProductIds) {
        # Get remediations
        $remediations = $vuln.Remediations.Remediation | Where-Object {
            $_.Type -eq "Vendor Fix" -and ($_.SubType -in @("Security Update", "Security HotPatch Update", "Release Notes"))
        }

        foreach ($rem in $remediations) {
            $kb = $rem.Description
            $fixedBuild = $rem.FixedBuild
            $remProductIds = $rem.ProductID

            # Only include remediations for server products
            foreach ($remProductId in $remProductIds) {
                if ($remProductId -in $serverProductIds) {
                    $product = $serverProducts | Where-Object { $_.ProductID -eq $remProductId }
                    $entryKey = "$cve-$kb-$remProductId"

                    # Avoid duplicates
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
                            PublishedDate = $vuln.RevisionHistory.Revision | Where-Object { $_.Number -eq "1.0" } | Select-Object -ExpandProperty Date
                        }
                    }
                }
            }
        }
    }
}

# Build OS dataset from $kbCveMap
$osData = @()
$osGroups = $kbCveMap | Where-Object { $_.KB -ne "Release Notes" } | Group-Object -Property { 
    # Simplify ProductName to base OS
    if ($_.ProductName -like "*Windows Server 2016*") { "Windows Server 2016" }
    elseif ($_.ProductName -like "*Windows Server 2019*") { "Windows Server 2019" }
    elseif ($_.ProductName -like "*Windows Server 2022, 23H2*") { "Windows Server 2022 23H2" }  # Handle 23H2 separately
    elseif ($_.ProductName -like "*Windows Server 2022*") { "Windows Server 2022" }
    elseif ($_.ProductName -like "*Windows Server 2025*") { "Windows Server 2025" }
    else { $_.ProductName }
}

foreach ($group in $osGroups) {
    $osName = $group.Name
    # Skip HLK products
    if ($osName -like "*HLK*") { continue }

    # Find the KB with the highest build number (excluding 23H2 for Server 2022 unless it's the target)
    $latestEntry = $group.Group | Sort-Object FixedBuild -Descending | Select-Object -First 1
    if ($osName -eq "Windows Server 2022") {
        # Prefer non-23H2 entries for Server 2022 (e.g., KB5058385 over KB5058384)
        $non23H2 = $group.Group | Where-Object { $_.ProductName -notlike "*23H2*" } | Sort-Object FixedBuild -Descending | Select-Object -First 1
        if ($non23H2) { $latestEntry = $non23H2 }
    }

    $osData += [PSCustomObject]@{
        os          = $osName
        version     = $versionMap[$osName] ? $versionMap[$osName] : "Unknown"
        build       = $latestEntry.FixedBuild
        latestKB    = $latestEntry.KB
        releaseDate = $latestEntry.PublishedDate
    }
}

# Build OS dataset from $kbCveMap
$osData = @()

# Get unique OS names, excluding HLK products and Server 2022 23H2
$osNames = $kbCveMap | Where-Object { $_.KB -ne "Release Notes" } | ForEach-Object {
    # Simplify ProductName to base OS
    if ($_.ProductName -like "*Windows Server 2016*") { "Windows Server 2016" }
    elseif ($_.ProductName -like "*Windows Server 2019*") { "Windows Server 2019" }
    elseif ($_.ProductName -like "*Windows Server 2022, 23H2*") { "Windows Server 2022 23H2" }
    elseif ($_.ProductName -like "*Windows Server 2022*") { "Windows Server 2022" }
    elseif ($_.ProductName -like "*Windows Server 2025*") { "Windows Server 2025" }
} | Sort-Object -Unique | Where-Object { $_ -notlike "*HLK*" -and $_ -ne "Windows Server 2022 23H2" }

foreach ($osName in $osNames) {
    # Find the KB with the highest build number for this OS, excluding 23H2 for Server 2022
    $latestEntry = $kbCveMap | Where-Object { 
        ($_.ProductName -like "*$osName*" -and $_.KB -ne "Release Notes") -and 
        ($osName -ne "Windows Server 2022" -or $_.ProductName -notlike "*23H2*")
    } | Sort-Object FixedBuild -Descending | Select-Object -First 1

    if ($latestEntry) {
        $osData += [PSCustomObject]@{
            os          = $osName
            version     = $versionMap[$osName] ? $versionMap[$osName] : "Unknown"
            build       = $latestEntry.FixedBuild -replace "^10\.0\.", ""
            latestKB    = "KB$($latestEntry.KB)"
            releaseDate = ($latestEntry.PublishedDate -replace "T.*", "")
        }
    }
}

# Output results
if ($kbCveMap) {
    # Display all mappings
    $kbCveMap | Sort-Object CVE, KB, ProductName | Format-Table -AutoSize
    # Export to CSV
    $kbCveMap | Export-Csv -Path "Server_KB_CVE_Map_$month.csv" -NoTypeInformation

    # Highlight high-risk CVEs
    $highRisk = $kbCveMap | Where-Object { $_.ExploitStatus -match "Exploitation Detected|Exploitation More Likely" } | Sort-Object CVE, ProductName -Unique
    if ($highRisk) {
        Write-Output "High-Risk CVEs (Exploitation Detected or More Likely):"
        $highRisk | Format-Table CVE, KB, ProductName, Severity, ExploitStatus -AutoSize
    }
} else {
    Write-Warning "No KB-to-CVE mappings found for specified Windows Server versions."
}

# Output results
if ($kbCveMap) {
    # Display all mappings
    $kbCveMap | Sort-Object CVE, KB, ProductName | Format-Table -AutoSize
    # Export to CSV
    $kbCveMap | Export-Csv -Path "kb_cve_data.csv" -NoTypeInformation

    # Highlight high-risk CVEs
    $highRisk = $kbCveMap | Where-Object { $_.ExploitStatus -match "Exploitation Detected|Exploitation More Likely" } | Sort-Object CVE, ProductName -Unique
    if ($highRisk) {
        Write-Output "High-Risk CVEs (Exploitation Detected or More Likely):"
        $highRisk | Format-Table CVE, KB, ProductName, Severity, ExploitStatus -AutoSize
    }
} else {
    Write-Warning "No KB-to-CVE mappings found for specified Windows Server versions."
}

# Summarize unique KBs and their associated OS with latest KB status
Write-Output "Unique KBs and Associated OS:"
$uniqueKBs = $kbCveMap.KB | Sort-Object -Unique
foreach ($kb in $uniqueKBs) {
    $osList = $kbCveMap | Where-Object { $_.KB -eq $kb } | Select-Object -ExpandProperty ProductName -Unique | Sort-Object
    $kbStatus = ""
    $expectedBuild = ""

    # Check if KB is latest for any OS in the derived dataset
    $matchingOs = $osData | Where-Object { $_.latestKB -eq "KB$kb" }
    if ($matchingOs) {
        $osNames = $matchingOs.os -join ", "
        $builds = $matchingOs.build -join ", "
        $kbStatus = " (Latest for $osNames)"
        $expectedBuild = " (Expected Build: $builds)"
    } elseif ($kb -eq "Release Notes") {
        $kbStatus = " (Non-standard update for HLK products)"
    } else {
        $kbStatus = " (Not latest for any OS)"
    }

    Write-Output "$kb`: $($osList -join ', ')$kbStatus$expectedBuild"
}

# Summarize unique CVEs
$uniqueCVEs = $kbCveMap.CVE | Sort-Object -Unique
Write-Output "Unique CVEs: $($uniqueCVEs -join ', ')"

# Output derived OS dataset for reference
Write-Output "`nDerived OS Dataset:"
$osData | Format-Table os, version, build, latestKB, releaseDate -AutoSize

# Export OS dataset to JSON
$osData | ConvertTo-Json | Out-File -FilePath "OS_Dataset_$month.json" -Encoding UTF8

# Add this after the existing $osData export in the script

# Build CVE-to-KB mapping dataset
$cveData = @()

# Get unique CVEs, excluding HLK products
$uniqueCVEs = $kbCveMap | Where-Object { $_.KB -ne "Release Notes" } | Select-Object -ExpandProperty CVE -Unique

foreach ($cve in $uniqueCVEs) {
    # Get all entries for this CVE, excluding HLK and Server 2022 23H2
    $cveEntries = $kbCveMap | Where-Object { 
        $_.CVE -eq $cve -and 
        $_.KB -ne "Release Notes" -and 
        $_.ProductName -notlike "*Windows Server 2022, 23H2*"
    }

    # Group by simplified OS name
    $osGroups = $cveEntries | ForEach-Object {
        $osName = switch -Wildcard ($_.ProductName) {
            "*Windows Server 2016*" { "Windows Server 2016" }
            "*Windows Server 2019*" { "Windows Server 2019" }
            "*Windows Server 2022*" { "Windows Server 2022" }
            "*Windows Server 2025*" { "Windows Server 2025" }
            default { $null }
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

    $cveMapping = [PSCustomObject]@{
        cve = $cve
        patches = @()
    }

    foreach ($group in $osGroups) {
        $osName = $group.Name
        # Select the entry with the latest KB for this OS
        $latestEntry = $group.Group | Sort-Object FixedBuild -Descending | Select-Object -First 1

        # Map to latest KB for the OS
        $latestKB = switch ($osName) {
            "Windows Server 2016" { "5058383" }
            "Windows Server 2019" { "5058392" }
            "Windows Server 2022" { "5058385" }
            "Windows Server 2025" { "5058411" }
        }

        # Only include if the KB matches the latest for the OS
        if ($latestEntry.KB -eq $latestKB) {
            $cveMapping.patches += [PSCustomObject]@{
                os = $osName
                kb = "KB$($latestEntry.KB)"
                fixedBuild = $latestEntry.FixedBuild -replace "^10\.0\.", ""
                severity = $latestEntry.Severity
                exploitStatus = $latestEntry.ExploitStatus
            }
        }
    }

    if ($cveMapping.patches.Count -gt 0) {
        $cveData += $cveMapping
    }
}

# Output CVE-to-KB mapping for reference
Write-Output "`nCVE-to-KB Mapping Dataset:"
$cveData | ForEach-Object {
    Write-Output "CVE: $($_.cve)"
    $_.patches | Format-Table os, kb, fixedBuild, severity, exploitStatus -AutoSize
}

# Export CVE-to-KB mapping to JSON
$cveData | ConvertTo-Json -Depth 3 | Out-File -FilePath "CVE_KB_Mapping_$month.json" -Encoding UTF8
