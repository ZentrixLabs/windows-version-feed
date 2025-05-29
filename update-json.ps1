$uri = "https://learn.microsoft.com/en-us/windows/release-health/windows-server-release-info"
$response = Invoke-WebRequest -Uri $uri -UseBasicParsing
$html = $response.Content

$pattern = '<tr>\s*<td>(?<os>.*?)</td>\s*<td>(?<servicing>.*?)</td>\s*<td>(?<date>.*?)</td>\s*<td>(?<build>.*?)</td>\s*<td>(?<kb>KB\d+)</td>\s*<td>(?<description>.*?)</td>\s*</tr>'
$matches = [regex]::Matches($html, $pattern, 'IgnoreCase')

$updates = @()

foreach ($match in $matches) {
    $os = $match.Groups['os'].Value.Trim()
    $servicing = $match.Groups['servicing'].Value.Trim()
    $dateText = $match.Groups['date'].Value.Trim()
    $fullBuild = $match.Groups['build'].Value.Trim()
    $kb = $match.Groups['kb'].Value.Trim()
    $description = $match.Groups['description'].Value.Trim()

    if (
        $os -match "Windows Server (20(16|19|22|25))" -and
        $description -match "Cumulative Update" -and
        $description -notmatch "Preview|Out-of-band|OOB|Optional"
    ) {
        $date = [datetime]::Parse($dateText)
        $majorBuild = $fullBuild.Split(".")[0]

        $updates += [PSCustomObject]@{
            os          = $os
            build       = $majorBuild
            fullBuild   = $fullBuild
            kb          = $kb
            releaseDate = $date
        }
    }
}

# Deduplicate: Get latest by os+build
$latest = $updates |
    Group-Object os, build |
    ForEach-Object {
        $_.Group | Sort-Object releaseDate -Descending | Select-Object -First 1
    } |
    Sort-Object os

# Add version and format
$latest | ForEach-Object {
    $_ | Add-Member -NotePropertyName version -NotePropertyValue "LTSC"
    $_.releaseDate = $_.releaseDate.ToString("yyyy-MM-dd")
}

# Save JSON
$json = $latest | ConvertTo-Json -Depth 3
Set-Content -Path "windows-versions.json" -Value $json -Encoding UTF8
