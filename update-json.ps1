# update-json.ps1

$uri = "https://learn.microsoft.com/en-us/windows/release-health/windows-server-release-info"
$response = Invoke-WebRequest -Uri $uri
$html = $response.ParsedHtml

$rows = $html.getElementsByTagName("tr")

# Store the latest valid update per OS
$latestUpdates = @{}

foreach ($row in $rows) {
    $cells = $row.getElementsByTagName("td")
    if ($cells.Count -ge 5) {
        $os = $cells.Item(0).innerText.trim()
        $build = $cells.Item(1).innerText.trim()
        $dateText = $cells.Item(2).innerText.trim()
        $kb = $cells.Item(3).innerText.trim()
        $description = $cells.Item(4).innerText.trim()

        # Only include regular Cumulative or Security updates
        if (
            $os -match "Windows Server (20(16|19|22|25))" -and
            $description -match "Cumulative Update" -and
            $description -notmatch "Preview|Out-of-band|OOB|Optional"
        ) {
            $date = [datetime]::Parse($dateText)

            if (-not $latestUpdates.ContainsKey($os) -or $date -gt $latestUpdates[$os].releaseDate) {
                $latestUpdates[$os] = [PSCustomObject]@{
                    os          = $os
                    version     = "LTSC"
                    build       = $build
                    latestKB    = $kb
                    releaseDate = $date
                }
            }
        }
    }
}

# Convert to sorted list by OS name
$data = $latestUpdates.Values | Sort-Object os

# Format date and export
$data | ForEach-Object {
    $_.releaseDate = $_.releaseDate.ToString("yyyy-MM-dd")
}

$json = $data | ConvertTo-Json -Depth 3
Set-Content -Path "windows-versions.json" -Value $json
