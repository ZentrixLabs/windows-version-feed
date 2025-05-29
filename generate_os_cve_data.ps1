# generate_os_cve_data.ps1
# Generates windows-versions.json and CVE_KB_Mapping_2025-May.json for Windows Server OSes

# Set month variable based on current date
$month = Get-Date -Format "yyyy-MMMM"

# Sample versionMap (replace with actual data loading if needed)
$versionMap = @{
    "Windows Server 2016" = "1607"
    "Windows Server 2019" = "1809"
    "Windows Server 2022" = "LTSC"
    "Windows Server 2025" = "LTSC"
}

# Placeholder for $kbCveMap loading (replace with actual data source)
# Example: $kbCveMap = Import-Csv -Path "path/to/kb_cve_data.csv"
# For now, assume $kbCveMap is populated with the structure from previous data
if (-not $kbCveMap) {
    Write-Error "kbCveMap is not populated. Please load the data source."
    exit 1
}

# Build OS dataset
$osData = @()
$osNames = $kbCveMap | Where-Object { $_.KB -ne "Release Notes" } | ForEach-Object {
    if ($_.ProductName -like "*Windows Server 2016*") { "Windows Server 2016" }
    elseif ($_.ProductName -like "*Windows Server 2019*") { "Windows Server 2019" }
    elseif ($_.ProductName -like "*Windows Server 2022, 23H2*") { "Windows Server 2022 23H2" }
    elseif ($_.ProductName -like "*Windows Server 2022*") { "Windows Server 2022" }
    elseif ($_.ProductName -like "*Windows Server 2025*") { "Windows Server 2025" }
} | Sort-Object -Unique | Where-Object { $_ -notlike "*HLK*" -and $_ -ne "Windows Server 2022 23H2" }

foreach ($osName in $osNames) {
    $latestEntry = $kbCveMap | Where-Object { 
        ($_.ProductName -like "*$osName*" -and $_.KB -ne "Release Notes") -and 
        ($osName -ne "Windows Server 2022" -or $_.ProductName -notlike "*23H2*")
    } | Sort-Object FixedBuild -Descending | Select-Object -First 1

    if ($latestEntry) {
        $osData += [PSCustomObject]@{
            os = $osName
            version = $versionMap[$osName] ? $versionMap[$osName] : "Unknown"
            build = $latestEntry.FixedBuild -replace "^10\.0\.", ""
            latestKB = "KB$($latestEntry.KB)"
            releaseDate = ($latestEntry.PublishedDate -replace "T.*", "")
        }
    }
}

# Output OS dataset for reference
Write-Output "`nDerived OS Dataset:"
$osData | Format-Table os, version, build, latestKB, releaseDate -AutoSize

# Export OS dataset to windows-versions.json
try {
    $osData | ConvertTo-Json | Out-File -FilePath "./windows-versions.json" -Encoding UTF8
    Write-Output "Exported windows-versions.json successfully."
}
catch {
    Write-Error "Failed to export windows-versions.json: $_"
    exit 1
}

# Build CVE-to-KB mapping dataset
$cveData = @()
$uniqueCVEs = $kbCveMap | Where-Object { $_.KB -ne "Release Notes" } | Select-Object -ExpandProperty CVE -Unique

foreach ($cve in $uniqueCVEs) {
    $cveEntries = $kbCveMap | Where-Object { 
        $_.CVE -eq $cve -and 
        $_.KB -ne "Release Notes" -and 
        $_.ProductName -notlike "*Windows Server 2022, 23H2*"
    }

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
        $latestEntry = $group.Group | Sort-Object FixedBuild -Descending | Select-Object -First 1

        $latestKB = switch ($osName) {
            "Windows Server 2016" { "5058383" }
            "Windows Server 2019" { "5058392" }
            "Windows Server 2022" { "5058385" }
            "Windows Server 2025" { "5058411" }
        }

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

# Export CVE-to-KB mapping to CVE_KB_Mapping_$month.json
try {
    $cveData | ConvertTo-Json -Depth 3 | Out-File -FilePath "./CVE_KB_Mapping_$month.json" -Encoding UTF8
    Write-Output "Exported CVE_KB_Mapping_$month.json successfully."
}
catch {
    Write-Error "Failed to export CVE_KB_Mapping_$month.json: $_"
    exit 1
}
