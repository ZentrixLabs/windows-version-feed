# Try to fetch CVRF data with fallback
try {
    Write-Host "Attempting to fetch: https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/$month"
    $response = Invoke-WebRequest -Uri "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/$month" -ErrorAction Stop
    $xmlRaw = $response.Content
    "Successfully fetched CVRF XML data for $month" | Out-File -FilePath $debugLog -Append
}
catch {
    if ($_.Exception.Response.StatusCode.value__ -eq 404) {
        $prevMonthDate = (Get-Date).AddMonths(-1)
        $prevMonthAbbr = (Get-Culture).DateTimeFormat.GetAbbreviatedMonthName($prevMonthDate.Month).Substring(0,3)
        $month = "$($prevMonthDate.Year)-$prevMonthAbbr"
        Write-Warning "Current month not found. Falling back to: $month"
        Write-Host "Fallback URL: https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/$month"
        "404 for $month, falling back to $month" | Out-File -FilePath $debugLog -Append
        $response = Invoke-WebRequest -Uri "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/$month" -ErrorAction Stop
        $xmlRaw = $response.Content
        "Successfully fetched fallback CVRF XML data for $month" | Out-File -FilePath $debugLog -Append
    } else {
        "Error fetching CVRF data: $($_.Exception.Message)" | Out-File -FilePath $debugLog -Append
        throw
    }
}

# Attempt to parse XML with fallback logic for malformed entries
try {
    [xml]$cvrfXml = $xmlRaw
    $cvrf = $cvrfXml
    "Successfully parsed CVRF XML content" | Out-File -FilePath $debugLog -Append
}
catch {
    Write-Warning "Failed to parse full XML. Attempting regex-based fallback extraction."
    "Malformed XML, entering regex-based fallback" | Out-File -FilePath $debugLog -Append

    # Regex fallback for KB blocks
    $fallbackEntries = @()
    $kbBlocks = Select-String -InputObject $xmlRaw -Pattern '<Remediation[^>]*>.*?</Remediation>' -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value }

    foreach ($block in $kbBlocks) {
        $kb = [regex]::Match($block, '<Description>(KB\d+)</Description>').Groups[1].Value
        $fixedBuild = [regex]::Match($block, '<FixedBuild>([^<]+)</FixedBuild>').Groups[1].Value
        $productIds = [regex]::Matches($block, '<ProductID>([^<]+)</ProductID>') | ForEach-Object { $_.Groups[1].Value }
        $vulnBlock = ($xmlRaw -split '</Remediation>') | Where-Object { $_ -like "*$kb*" } | Select-String -Pattern '<Vulnerability[^>]*CVE="([^"]+)' | ForEach-Object { $_.Matches[0].Groups[1].Value }

        foreach ($cve in $vulnBlock) {
            foreach ($pid in $productIds) {
                $productName = ($osProducts | Where-Object { $_.ProductID -eq $pid }).ProductName
                $severity = 'N/A (fallback)'
                $exploitStatus = 'N/A (fallback)'
                $publishedDate = $date

                $cveEscaped = [Regex]::Escape($cve)
                $fullVulnPattern = "<Vulnerability[^>]*CVE\s*=\s*\"{0}\"[^>]*>.*?</Vulnerability>" -f $cveEscaped
                $fullVulnMatch = [regex]::Match($xmlRaw, $fullVulnPattern, [System.Text.RegularExpressions.RegexOptions]::Singleline)
                if ($fullVulnMatch.Success) {
                    $vulnText = $fullVulnMatch.Value
                    $severityMatch = [regex]::Match($vulnText, "<cvss:BaseScore>([^<]+)</cvss:BaseScore>")
                    if ($severityMatch.Success) { $severity = $severityMatch.Groups[1].Value }

                    $exploitMatch = [regex]::Match($vulnText, "<Threat[^>]+Type=\"Exploit Status\"[^>]*>.*?<Description>(.*?)</Description>", [System.Text.RegularExpressions.RegexOptions]::Singleline)
                    if ($exploitMatch.Success) { $exploitStatus = $exploitMatch.Groups[1].Value }

                    $publishedMatch = [regex]::Match($vulnText, "<Revision[^>]*Number=\"1.0\"[^>]*>.*?<Date>(.*?)</Date>", [System.Text.RegularExpressions.RegexOptions]::Singleline)
                    if ($publishedMatch.Success) { $publishedDate = $publishedMatch.Groups[1].Value }
                }

                $fallbackEntries += [PSCustomObject]@{
                    CVE           = $cve
                    KB            = $kb
                    ProductID     = $pid
                    ProductName   = $productName
                    FixedBuild    = $fixedBuild
                    Severity      = $severity
                    ExploitStatus = $exploitStatus
                    PublishedDate = $publishedDate
                }
            }
        }
    }

    $fallbackEntries | Export-Csv "fallback_kb_data.csv" -NoTypeInformation -Force
    "Exported fallback KB data to fallback_kb_data.csv" | Out-File -FilePath $debugLog -Append
}

# Use fallback entries if XML parse failed
if (-not $cvrf.cvrfdoc -and $fallbackEntries.Count -gt 0) {
    Write-Warning "Using fallback entries as primary CVE-KB map"
    $kbCveMap = $fallbackEntries
}

Write-Host "Resilient parsing step complete."
"Parsing completed at $(Get-Date)" | Out-File -FilePath $debugLog -Append
