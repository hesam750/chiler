[CmdletBinding()]
param(
    [string]$DeviceIP = "169.254.61.68"
)

function Get-WebPage([string]$url) {
    try {
        $response = Invoke-WebRequest -Uri $url -Method Get -UseBasicParsing
        Write-Host "GET $url - Status: $($response.StatusCode)"
        return $response.Content
    } catch {
        Write-Host "GET $url - Error: $($_.Exception.Message)"
        return $null
    }
}

Write-Host "=== Reading PGD Device Status ==="

# Read the main PGD page
$pgdContent = Get-WebPage "http://$DeviceIP/pgd/index.htm"

if ($pgdContent) {
    # Try to extract temperature information from the PGD page
    Write-Host "PGD Page Content (first 500 chars):"
    Write-Host $pgdContent.Substring(0, [Math]::Min(500, $pgdContent.Length))
    
    # Look for temperature patterns
    if ($pgdContent -match "(?i)(temperature|temp|derece|°C)") {
        Write-Host "Temperature-related content found!"
        # Extract the relevant section
        $tempMatch = $pgdContent -match "(?s)(.{0,200}(temperature|temp|derece|°C).{0,200})"
        if ($tempMatch) {
            Write-Host "Possible temperature info: $($Matches[1])"
        }
    }
} else {
    Write-Host "Could not access PGD interface"
}

Write-Host "=== Status Check Complete ==="