$uri = "https://learn.microsoft.com/en-us/windows/release-health/windows-server-release-info"
$response = Invoke-WebRequest -Uri $uri
$html = $response.ParsedHtml

$rows = $html.getElementsByTagName("tr")

$allUpdates = @()

foreach ($row in $rows) {
    $cells = $row.getElementsByTagName("td")
    if ($cells.Count -ge 6) {
        $os = $cells.Item(0).innerText.Trim()
        $servicing = $cells.Item(1).innerText.Trim()
        $dateText = $cells.Item(2).innerText.Trim()
        $fullBuild = $cells.Item(3).innerText.Trim()
        $kb = $cells.Item(4).innerText.Trim()
        $description = $cells.Item(5).innerText.Trim()

        if (
            $os -match "Windows Server (20(16|19|22|25))" -and
            $description -match "Cumulative Update" -and
            $description -notmatch "Preview|Out-of-band|OOB|Optional"
        ) {
            $date = [datetime]::Parse($dateText)
            $majorBuild = $fullBuild.Split(".")[0]  # e.g., 20348

            $allUpdates += [PSCustomObject]@{
                os          = $os
                build       = $majorBuild
                fullBuild   = $fullBuild
                kb          = $kb
                releaseDate = $date
            }
        }
    }
}

# Pick latest update per OS+build combo
$latestUpdates = $allUpdates |
    Group-Object os, build |
    ForEach-Object {
        $_.Group | Sort-Object releaseDate -Descending | Select-Object -First 1
    } |
    Sort-Object os

# Add version and format date
$latestUpdates | ForEach-Object {
    $_ | Add-Member -NotePropertyName version -NotePropertyValue "LTSC"
    $_.releaseDate = $_.releaseDate.ToString("yyyy-MM-dd")
}

# Save JSON
$json = $latestUpdates | ConvertTo-Json -Depth 3 -Compress:$false
Set-Content -Path "windows-versions.json" -Value $json -Encoding UTF8
