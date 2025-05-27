# update-json.ps1

$uri = "https://learn.microsoft.com/en-us/windows/release-health/windows-server-release-info"
$response = Invoke-WebRequest -Uri $uri
$html = $response.ParsedHtml

$rows = $html.getElementsByTagName("tr")

$data = @()

foreach ($row in $rows) {
    $cells = $row.getElementsByTagName("td")
    if ($cells.Count -ge 4) {
        $os = $cells.Item(0).innerText.trim()
        $build = $cells.Item(1).innerText.trim()
        $date = $cells.Item(2).innerText.trim()
        $kb = $cells.Item(3).innerText.trim()

        # Filter for relevant Windows Server versions
        if ($os -match "Windows Server (20(16|19|22|25))") {
            $data += [PSCustomObject]@{
                os          = $os
                version     = "LTSC"
                build       = $build
                latestKB    = $kb
                releaseDate = [datetime]::Parse($date).ToString("yyyy-MM-dd")
            }
        }
    }
}

$json = $data | ConvertTo-Json -Depth 3
Set-Content -Path "windows-versions.json" -Value $json
