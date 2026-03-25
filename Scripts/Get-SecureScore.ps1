Function Get-SecureScore {
<#
    .SYNOPSIS
    Retrieves Microsoft Secure Score recommendations and current status.

    .DESCRIPTION
    Retrieves Secure Score control profiles, current scores, and derives statuses for recommendations.

    .PARAMETER OutputDir
    OutputDir is the parameter specifying the output directory.
    Default: Output\SecureScore

    .PARAMETER Encoding
    Encoding is the parameter specifying the encoding of the CSV output file.
    Default: UTF8

    .PARAMETER LogLevel
    Specifies the level of logging:
    None: No logging
    Minimal: Critical errors only
    Standard: Normal operational logging
    Debug: Verbose logging for debugging purposes
    Default: Standard

    .PARAMETER Category
    Category is the parameter specifying a specific control category to filter results.
    Default: All categories will be included if not specified.

    .PARAMETER Service
    Service is the parameter specifying a specific service to filter results (e.g., "Exchange", "SharePoint").
    Default: All services will be included if not specified.

    .PARAMETER StatusFilter
    StatusFilter is the parameter specifying which statuses to include in the output.
    Valid values: AtRisk, Partial, MeetsStandard, NotApplicable
    Default: All statuses will be included if not specified.
    
    .EXAMPLE
    Get-SecureScore
    Retrieves Secure Score recommendations and statuses.
    
    .EXAMPLE
    Get-SecureScore -OutputDir C:\Windows\Temp
    Retrieves Secure Score data and saves output to C:\Windows\Temp folder.

    .EXAMPLE
    Get-SecureScore -Category "Identity"
    Retrieves Secure Score recommendations filtered to the Identity category.

    .EXAMPLE
    Get-SecureScore -Service "Exchange"
    Retrieves Secure Score recommendations for Exchange only.

    .EXAMPLE
    Get-SecureScore -StatusFilter AtRisk
    Retrieves only the at-risk Secure Score recommendations.
#>

    [CmdletBinding()]
    param(
        [string]$OutputDir,
        [string]$Encoding = "UTF8",
        [string]$Category,
        [string]$Service,
        [ValidateSet('AtRisk', 'Partial', 'MeetsStandard', 'NotApplicable')]
        [string]$StatusFilter,
        [ValidateSet('None', 'Minimal', 'Standard', 'Debug')]
        [string]$LogLevel = 'Standard'
    )

    Init-Logging
    Init-OutputDir -Component "SecureScore" -FilePostfix "SecureScore" -CustomOutputDir $OutputDir

    Write-LogFile -Message "=== Starting Secure Score Collection ===" -Color "Cyan" -Level Standard

    $requiredScopes = @("SecurityEvents.Read.All")
    $graphAuth = Get-GraphAuthType -RequiredScopes $RequiredScopes

    if ($isDebugEnabled) {
        Write-LogFile -Message "[DEBUG] Graph authentication details:" -Level Debug
        Write-LogFile -Message "[DEBUG]   Required scopes: $($requiredScopes -join ', ')" -Level Debug
        Write-LogFile -Message "[DEBUG]   Authentication type: $($graphAuth.AuthType)" -Level Debug
        Write-LogFile -Message "[DEBUG]   Current scopes: $($graphAuth.Scopes -join ', ')" -Level Debug
        if ($graphAuth.MissingScopes.Count -gt 0) {
            Write-LogFile -Message "[DEBUG]   Missing scopes: $($graphAuth.MissingScopes -join ', ')" -Level Debug
        } else {
            Write-LogFile -Message "[DEBUG]   Missing scopes: None" -Level Debug
        }
    }

    try {
        Write-LogFile -Message "[INFO] Retrieving Secure Score data..." -Level Standard

        if ($Category) {
            Write-LogFile -Message "[INFO] Filtering results for category: $Category" -Level Standard
        }
        if ($Service) {
            Write-LogFile -Message "[INFO] Filtering results for service: $Service" -Level Standard
        }
        if ($StatusFilter) {
            Write-LogFile -Message "[INFO] Filtering results for status: $StatusFilter" -Level Standard
        }
        
        if ($isDebugEnabled) {
            Write-LogFile -Message "[DEBUG] Fetching all Secure Score control profiles..." -Level Debug
            $profilePerformance = Measure-Command {
                $profiles = Get-MgSecuritySecureScoreControlProfile -All
            }
            Write-LogFile -Message "[DEBUG] Profile retrieval took $([math]::round($profilePerformance.TotalSeconds, 2)) seconds" -Level Debug
            Write-LogFile -Message "[DEBUG] Found $($profiles.Count) control profiles" -Level Debug
        } else {
            $profiles = Get-MgSecuritySecureScoreControlProfile -All
        }

        if ($isDebugEnabled) {
            Write-LogFile -Message "[DEBUG] Fetching latest Secure Score..." -Level Debug
            $scorePerformance = Measure-Command {
                $latestScore = Get-MgSecuritySecureScore -Top 1
            }
            Write-LogFile -Message "[DEBUG] Score retrieval took $([math]::round($scorePerformance.TotalSeconds, 2)) seconds" -Level Debug
        } else {
            $latestScore = Get-MgSecuritySecureScore -Top 1
        }

        Write-LogFile -Message "[INFO] Found $($profiles.Count) control profiles" -Level Standard

        $controlScoresHash = @{}
        $latestScore.ControlScores | ForEach-Object {
            $controlScoresHash[$_.ControlName] = $_.Score
        }

        $results = @()
        $atRiskCount = 0
        $meetsStandardCount = 0
        $partialCount = 0
        $notApplicableCount = 0

        foreach ($profile in $profiles) {
            if ($isDebugEnabled) {
                Write-LogFile -Message "[DEBUG] Processing profile: $($profile.Title)" -Level Debug
                Write-LogFile -Message "[DEBUG]   Profile ID: $($profile.Id)" -Level Debug
            }

            if ($Category -and $profile.ControlCategory -notlike "*$Category*") {
                if ($isDebugEnabled) {
                    Write-LogFile -Message "[DEBUG]   Skipping profile (category filter): $($profile.ControlCategory)" -Level Debug
                }
                continue
            }

            if ($Service -and $profile.Service -notlike "*$Service*") {
                if ($isDebugEnabled) {
                    Write-LogFile -Message "[DEBUG]   Skipping profile (service filter): $($profile.Service)" -Level Debug
                }
                continue
            }

            try {
                $fullProfile = Get-MgSecuritySecureScoreControlProfile -SecureScoreControlProfileId $profile.Id
                $state = $fullProfile.ControlStateUpdates | Select-Object -Last 1 -ExpandProperty State
                if (-not $state) { $state = "Default" }
            } catch {
                Write-LogFile -Message "[WARNING] Error fetching full profile for $($profile.Id): $($_.Exception.Message)" -Color "Yellow" -Level Standard
                $state = "Error"
            }

            $currentScore = $controlScoresHash[$profile.Id]
            if ($null -eq $currentScore) { $currentScore = 0 }

            if ($null -eq $controlScoresHash[$profile.Id] -and $state -eq "Default") {
                $status = "Not applicable"
                $notApplicableCount++
            } elseif ($state -in @("Ignored", "ThirdParty", "Reviewed")) {
                $status = "Not applicable (overridden: $state)"
                $notApplicableCount++
            } elseif ($currentScore -eq $profile.MaxScore) {
                $status = "Meets standard"
                $meetsStandardCount++
            } elseif ($currentScore -gt 0) {
                $status = "Partial"
                $partialCount++
            } else {
                $status = "At risk"
                $atRiskCount++
            }

            if ($StatusFilter) {
                $includeResult = $false
                switch ($StatusFilter) {
                    "AtRisk" { if ($status -eq "At risk") { $includeResult = $true } }
                    "Partial" { if ($status -eq "Partial") { $includeResult = $true } }
                    "MeetsStandard" { if ($status -eq "Meets standard") { $includeResult = $true } }
                    "NotApplicable" { if ($status -like "Not applicable*") { $includeResult = $true } }
                }
                if (-not $includeResult) { continue }
            }

            $scoreGap = $profile.MaxScore - $currentScore
            $results += [PSCustomObject]@{
                Category          = $profile.ControlCategory
                Title             = $profile.Title
                Service           = $profile.Service
                Status            = $status
                CurrentScore      = $currentScore
                MaxScore          = $profile.MaxScore
                ScoreGap          = $scoreGap
                State             = $state
                ActionType        = $fullProfile.ActionType
                ActionUrl         = $fullProfile.ActionUrl
                ImplementationCost = $fullProfile.ImplementationCost
                UserImpact        = $fullProfile.UserImpact
                Tier              = $fullProfile.Tier
                Rank              = $fullProfile.Rank
                Deprecated        = $fullProfile.Deprecated
                Threats           = ($fullProfile.Threats -join "; ")
                Remediation       = $fullProfile.Remediation
                RemediationImpact = $fullProfile.RemediationImpact
                LastModifiedDateTime = $fullProfile.LastModifiedDateTime
            }
        }

        if ($results.Count -gt 0) {
            $results | Export-Csv -Path $script:outputFile -NoTypeInformation -Encoding $Encoding
            Write-LogFile -Message "[INFO] Exported $($results.Count) recommendations to $($script:outputFile)" -Level Standard
        } else {
            Write-LogFile -Message "[WARNING] No Secure Score data found matching the specified criteria" -Color "Yellow" -Level Standard
        }

        if ($isDebugEnabled) {
            Write-LogFile -Message "[DEBUG] Score analysis completed:" -Level Debug
            Write-LogFile -Message "[DEBUG]   Total profiles processed: $($profiles.Count)" -Level Debug
            Write-LogFile -Message "[DEBUG]   Results after filtering: $($results.Count)" -Level Debug
        }

        $summary = [ordered]@{
            "Secure Score Overview" = [ordered]@{
                "Current Score" = $latestScore.CurrentScore
                "Maximum Score" = $latestScore.MaxScore
                "Percentage" = if ($latestScore.MaxScore -gt 0) { [math]::Round(($latestScore.CurrentScore / $latestScore.MaxScore) * 100, 2) } else { 0 }
                "As of Date" = $latestScore.CreatedDateTime
            }
            "Recommendations Summary" = [ordered]@{
                "Total Recommendations" = $profiles.Count
                "At Risk" = $atRiskCount
                "Partial" = $partialCount
                "Meets Standard" = $meetsStandardCount
                "Not Applicable" = $notApplicableCount
            }
        }

        Write-Summary -Summary $summary -Title "Secure Score Summary"
    }
    catch {
        Write-LogFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Color "Red" -Level Minimal
        if ($isDebugEnabled) {
            Write-LogFile -Message "[DEBUG] Error details:" -Level Debug
            Write-LogFile -Message "[DEBUG]   Exception type: $($_.Exception.GetType().Name)" -Level Debug
            Write-LogFile -Message "[DEBUG]   Error message: $($_.Exception.Message)" -Level Debug
            Write-LogFile -Message "[DEBUG]   Stack trace: $($_.ScriptStackTrace)" -Level Debug
        }
        throw
    }
}