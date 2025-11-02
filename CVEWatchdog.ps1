param(
    [Parameter(Mandatory=$true)]
    [string]$ApiUrl,
    [switch]$Wildcards,
    [switch]$DebugMatching
)

$ErrorActionPreference = "Stop"

$CVSS_LEVELS = @{
    "Critical" = 9.0
    "High"     = 7.0
    "Medium"   = 4.0
    "Low"      = 0.1
}

function Get-InstalledSoftware {
    Write-Host "📦 Scanning installed software..." -ForegroundColor Cyan
    
    $software = @()
    $ignored = 0

    $path64 = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
    $uninstall64 = Get-ItemProperty $path64 | Where-Object { $_.DisplayName -and $_.DisplayVersion }

    $path32 = "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    $uninstall32 = Get-ItemProperty $path32 -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -and $_.DisplayVersion }

    foreach ($item in $uninstall64 + $uninstall32) {
        if ($item.DisplayName -match "^(Windows|Microsoft)") { 
            $ignored++
            continue 
        }
        $software += [PSCustomObject]@{
            Name    = $item.DisplayName
            Version = $item.DisplayVersion
        }
    }

    $software = $software | Sort-Object -Property Name -Unique
    
    Write-Host "✅ Found $($software.Count) installed software entries (ignoring $ignored Windows/Microsoft entries)" -ForegroundColor Green
    return @{ 
        software = @($software)
        ignored = $ignored
    }
}

function Get-ProductNameVariations {
    param(
        [string]$SoftwareName,
        [string]$Version
    )
    
    $tier1List = [System.Collections.ArrayList]@()
    $tier2List = [System.Collections.ArrayList]@()
    $tier3List = [System.Collections.ArrayList]@()
    $tier4List = [System.Collections.ArrayList]@()
    $tier5List = [System.Collections.ArrayList]@()
    
    $allVariations = [System.Collections.Generic.HashSet[string]]::new()
    $words = $SoftwareName.Split(" ", [StringSplitOptions]::RemoveEmptyEntries)
    
    # Helper function to add variation
    function Add-Variation {
        param([string]$value, [System.Collections.ArrayList]$list)
        if ($value -and $value.Trim().Length -gt 1 -and $value -notmatch "^\d+$") {
            if ($allVariations.Add($value)) {
                [void]$list.Add($value)
            }
        }
    }
    
    # TIER 1: FULL NAME VARIATIONS
    Add-Variation $SoftwareName $tier1List
    Add-Variation $SoftwareName.ToLower() $tier1List
    
    if ($Version -match "^(\d+)") {
        Add-Variation "$SoftwareName $($Matches[1])" $tier1List
        Add-Variation (($SoftwareName.ToLower()) + " $($Matches[1])") $tier1List
    }
    
    # TIER 2: CLEANED VARIATIONS
    $step1 = $SoftwareName -replace "\s*\(.*?(x64|x86|32-bit|64-bit|arm64|arm|amd64).*?\)", ""
    $step1 = $step1 -replace "\s*(-|_)*(x64|x86|32-bit|64-bit|arm64|arm|amd64)$", ""
    
    $step2 = $SoftwareName -replace "\s*\([^)]*(?:Preview|ESR|Beta|RC|Alpha|Pre-release|Community|Enterprise|Professional)[^)]*\)", ""
    $step3 = $SoftwareName -replace "\s*\([^)]*\)", ""
    
    foreach ($step in @($step1, $step2, $step3)) {
        if ($step -and $step.Trim()) {
            Add-Variation $step.Trim() $tier2List
            Add-Variation $step.Trim().ToLower() $tier2List
        }
    }
    
    # TIER 3: TWO-WORD VARIATIONS
    if ($words.Count -ge 2) {
        $twoWords = ($words[0..1] -join " ")
        Add-Variation $twoWords $tier3List
        Add-Variation $twoWords.ToLower() $tier3List
    }
    
    # TIER 4: COMPRESSED VARIATIONS
    $compressed1 = $SoftwareName -replace " ", ""
    $compressed2 = $SoftwareName -replace "[^a-zA-Z0-9]", "_"
    $compressed3 = $SoftwareName -replace "[^a-zA-Z0-9]", ""
    
    foreach ($variant in @($compressed1, $compressed2, $compressed3)) {
        Add-Variation $variant $tier4List
        Add-Variation $variant.ToLower() $tier4List
    }
    
    # TIER 5: TWO-WORD COMBINED
    if ($words.Count -ge 2) {
        $twoWordsCombined = $words[0] + $words[1]
        Add-Variation $twoWordsCombined.ToLower() $tier5List
        
        $twoWordsCombinedTitle = ([cultureinfo]::CurrentCulture.TextInfo.ToTitleCase($words[0])) + `
                                  ([cultureinfo]::CurrentCulture.TextInfo.ToTitleCase($words[1]))
        Add-Variation $twoWordsCombinedTitle $tier5List
    }
	
	if ($words.Count -ge 2) {
        Add-Variation $words[1] $tier5List
        Add-Variation $words[1].ToLower() $tier5List
    }
    
    if ($words.Count -ge 1) {
        Add-Variation $words[0] $tier5List
        Add-Variation $words[0].ToLower() $tier5List
    }
        
    return @{
        tier1 = @($tier1List)
        tier2 = @($tier2List)
        tier3 = @($tier3List)
        tier4 = @($tier4List)
        tier5 = @($tier5List)
    }
}

function Get-CVESFromAPI {
    param(
        [string]$SoftwareName,
        [string]$Version
    )
    
    $nameVariationsByTier = Get-ProductNameVariations -SoftwareName $SoftwareName -Version $Version
    
    if ($DebugMatching) {
        Write-Host "DEBUG - Name variations for '$SoftwareName':" -ForegroundColor DarkCyan
        foreach ($tier in @('tier1', 'tier2', 'tier3', 'tier4', 'tier5')) {
            if ($nameVariationsByTier[$tier].Count -gt 0) {
                Write-Host "  ${tier}:" -ForegroundColor DarkGray
                $nameVariationsByTier[$tier] | ForEach-Object {
                    Write-Host "    → $_" -ForegroundColor DarkGray
                }
            }
        }
    }
    
    foreach ($tier in @('tier1', 'tier2', 'tier3', 'tier4', 'tier5')) {
        foreach ($name in $nameVariationsByTier[$tier]) {
            try {
                $uri = "$ApiUrl/api/cve/search?software=$([Uri]::EscapeDataString($name))"
                if ($Version) { $uri += "&version=$([Uri]::EscapeDataString($Version))" }
                
                $response = Invoke-RestMethod -Uri $uri -Method Get -TimeoutSec 10 -ErrorAction SilentlyContinue
                
                if ($response.results.Count -gt 0) {
                    if ($DebugMatching) { 
                        Write-Host "✨ Matched API using: '$name' (from ${tier})" -ForegroundColor DarkGray
                    }
                    return @{ 
                        results = @($response.results)
                        matchedVariation = $name
                        matchedTier = $tier
                    }
                }
            }
            catch {}
        }
    }
    
    return $null
}

function Get-CVSSSeverity {
    param([float]$Score)

    if ($null -eq $Score) { return "Unknown" }
    if ($Score -ge $CVSS_LEVELS.Critical) { return "Critical" }
    elseif ($Score -ge $CVSS_LEVELS.High) { return "High" }
    elseif ($Score -ge $CVSS_LEVELS.Medium) { return "Medium" }
    elseif ($Score -ge $CVSS_LEVELS.Low) { return "Low" }
    else { return "None" }
}

function Format-CVETable {
    param([array]$CVEs)

    if (-not $CVEs) { return }

    $CVEs | ForEach-Object {
        [PSCustomObject]@{
            "CVE ID"      = $_.cve_id
            "Severity"    = Get-CVSSSeverity -Score $_.cvss_score
            "CVSS Score"  = if ($_.cvss_score) { "{0:F1}" -f $_.cvss_score } else { "N/A" }
            "Version"     = $_.version
            "Published"   = ($_.published -split "T")[0]
            "Description" = if ($_.description.Length -gt 80) {
                $_.description.Substring(0,77) + "..."
            } else {
                $_.description
            }
        }
    }
}

Write-Host "`n═════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "                CVEWatchdog                "
Write-Host "═════════════════════════════════════════`n" -ForegroundColor Cyan

Write-Host "🌐 Checking API connectivity..." -ForegroundColor Cyan
try {
    $health = Invoke-RestMethod -Uri "$ApiUrl/health" -Method Get -TimeoutSec 5
    Write-Host "✅ API connected - $($health.cves_indexed) CVEs indexed`n" -ForegroundColor Green
}
catch {
    Write-Host "❌ Cannot connect to API at $ApiUrl" -ForegroundColor Red
    exit 1
}

$softwareData = Get-InstalledSoftware
$software = $softwareData.software
$ignoredCount = $softwareData.ignored

Write-Host "`n🔍 Searching for vulnerabilities...`n" -ForegroundColor Cyan

$softwareWithCVEs = @()
$allCVEs = @()
$apiMatches = 0

foreach ($app in $software) {
    $cveResult = Get-CVESFromAPI -SoftwareName $app.Name -Version $app.Version
    $cves = $null
    
    if ($cveResult) {
        $cves = $cveResult.results
        $apiMatches++
    }

    if (-not $Wildcards -and $cves) {
        $cves = $cves | Where-Object { $_.version -ne "*" }
    }

    if ($cves) {
        Write-Host "⚠️  $($app.Name) ($($app.Version)) - $($cves.Count) CVE(s) detected" -ForegroundColor Yellow

        $softwareWithCVEs += [PSCustomObject]@{
            Name    = $app.Name
            Version = $app.Version
            CVEs    = $cves
        }

        $allCVEs += $cves
    }
    else {
        if ($DebugMatching) {
            Write-Host "✓ $($app.Name) ($($app.Version)) - No CVEs detected" -ForegroundColor Green
        }
    }
}

Write-Host "`n═════════════════════════════════════════"
Write-Host "            VULNERABILITY REPORT"
Write-Host "═════════════════════════════════════════`n"

if ($softwareWithCVEs.Count -eq 0) {
    Write-Host "✅ No vulnerabilities detected!" -ForegroundColor Green
}
else {
    foreach ($app in $softwareWithCVEs) {
        Write-Host "`n📌 $($app.Name) - Version: $($app.Version)" -ForegroundColor Magenta
        Write-Host ("─" * 100)

        Format-CVETable -CVEs $app.CVEs | Format-Table -AutoSize
    }
}

Write-Host "`n═════════════════════════════════════════"
Write-Host "               SUMMARY"
Write-Host "═════════════════════════════════════════`n"

$totalCVEs = $allCVEs.Count
$criticalCount = ($allCVEs | Where-Object { (Get-CVSSSeverity -Score $_.cvss_score) -eq "Critical" }).Count
$highCount     = ($allCVEs | Where-Object { (Get-CVSSSeverity -Score $_.cvss_score) -eq "High" }).Count
$mediumCount   = ($allCVEs | Where-Object { (Get-CVSSSeverity -Score $_.cvss_score) -eq "Medium" }).Count
$lowCount      = ($allCVEs | Where-Object { (Get-CVSSSeverity -Score $_.cvss_score) -eq "Low" }).Count
$unknownCount  = ($allCVEs | Where-Object { (Get-CVSSSeverity -Score $_.cvss_score) -eq "Unknown" }).Count

Write-Host "Software scanned        : $($software.Count)"
Write-Host "Software ignored        : $ignoredCount"
Write-Host "API matches found       : $apiMatches"
Write-Host ""
Write-Host "Total CVEs found        : $totalCVEs" -ForegroundColor Cyan
Write-Host "Critical vulnerabilities: $criticalCount" -ForegroundColor Black
Write-Host "High vulnerabilities     : $highCount" -ForegroundColor Red
Write-Host "Medium vulnerabilities   : $mediumCount" -ForegroundColor Yellow
Write-Host "Low vulnerabilities      : $lowCount" -ForegroundColor Green

if ($unknownCount -gt 0) {
    Write-Host "Unknown vulnerabilities  : $unknownCount" -ForegroundColor Gray
}

Write-Host ""

$riskLevel = "🟢 LOW RISK"
$riskColor = "Green"

if ($criticalCount -gt 0)     { $riskLevel = "⚫️ CRITICAL RISK"; $riskColor = "Black" }
elseif ($highCount -gt 3)     { $riskLevel = "🔴 HIGH RISK";     $riskColor = "Red" }
elseif ($highCount -gt 0)     { $riskLevel = "🟠 MEDIUM RISK";   $riskColor = "Yellow" }

Write-Host "Overall Risk Assessment : " -NoNewline
Write-Host $riskLevel -ForegroundColor $riskColor
Write-Host "`n"