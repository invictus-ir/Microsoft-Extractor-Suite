function Get-RiskyUsers {
<#
    .SYNOPSIS
    Retrieves the risky users. 

    .DESCRIPTION
    Retrieves the risky users from the Entra ID Identity Protection, which marks an account as being at risk based on the pattern of activity for the account.

    .PARAMETER OutputDir
    OutputDir is the parameter specifying the output directory.
    Default: Output\RiskyEvents

    .PARAMETER Encoding
    Encoding is the parameter specifying the encoding of the CSV output file.
    Default: UTF8

    .PARAMETER UserIds
    An array of User IDs to retrieve risky user information for.
    If not specified, retrieves all risky users.

    .PARAMETER LogLevel
    Specifies the level of logging:
    None: No logging
    Minimal: Critical errors only
    Standard: Normal operational logging
    Default: Standard
    
    .EXAMPLE
    Get-RiskyUsers
    Retrieves all risky users.
	
    .EXAMPLE
    Get-RiskyUsers -Encoding utf32
    Retrieves all risky users and exports the output to a CSV file with UTF-32 encoding.
		
    .EXAMPLE
    Get-RiskyUsers -OutputDir C:\Windows\Temp
    Retrieves all risky users and saves the output to the C:\Windows\Temp folder.

    .EXAMPLE
    Get-RiskyUsers -UserIds "user-id-1","user-id-2"
    Retrieves risky user information for the specified User IDs.
#>
    [CmdletBinding()]
    param(
        [string]$OutputDir = "Output\RiskyEvents",
        [string]$Encoding = "UTF8",
        [string[]]$UserIds,
        [ValidateSet('None', 'Minimal', 'Standard')]
        [string]$LogLevel = 'Standard'
    )

    Set-LogLevel -Level ([LogLevel]::$LogLevel)
    Write-LogFile -Message "=== Starting Risky Users Collection ===" -Color "Cyan" -Level Minimal

    $requiredScopes = @("IdentityRiskEvent.Read.All","IdentityRiskyUser.Read.All")
    $graphAuth = Get-GraphAuthType -RequiredScopes $RequiredScopes

    if (!(test-path $OutputDir)) {
        New-Item -ItemType Directory -Force -Name $OutputDir > $null
    }
    else {
        if (!(Test-Path -Path $OutputDir)) {
            Write-Error "[Error] Custom directory invalid: $OutputDir exiting script" -ErrorAction Stop
            Write-LogFile -Message "[Error] Custom directory invalid: $OutputDir exiting script" -Level Minimal
        }
    }

    $results = @()
    $count = 0
    $riskSummary = @{
        High = 0
        Medium = 0
        Low = 0
        None = 0
        AtRisk = 0
        NotAtRisk = 0
        Remediated = 0
        Dismissed = 0
    }
    
    try {
        $results = @()
        $baseUri = "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers"

        if ($UserIds) {
            foreach ($userId in $UserIds) {
                $encodedUserId = [System.Web.HttpUtility]::UrlEncode($userId)
                $uri = "$baseUri`?`$filter=userPrincipalName eq '$encodedUserId'"
                Write-LogFile -Message "[INFO] Retrieving risky user for UPN: $userId" -Level Standard

                try {
                    $response = Invoke-MgGraphRequest -Method GET -Uri $uri

                    if ($response.value -and $response.value.Count -gt 0) {
                        foreach ($user in $response.value) {
                            $results += [PSCustomObject]@{
                                Id                          = $user.Id
                                IsDeleted                   = $user.IsDeleted
                                IsProcessing                = $user.IsProcessing
                                RiskDetail                  = $user.RiskDetail
                                RiskLastUpdatedDateTime     = $user.RiskLastUpdatedDateTime
                                RiskLevel                   = $user.RiskLevel
                                RiskState                   = $user.RiskState
                                UserDisplayName             = $user.UserDisplayName
                                UserPrincipalName           = $user.UserPrincipalName
                                AdditionalProperties = $user.AdditionalProperties -join ", "
                            }
                            
                            if ($user.RiskLevel) { $riskSummary[$user.RiskLevel]++ }
                            if ($user.RiskState -eq "atRisk") { $riskSummary.AtRisk++ }
                            elseif ($user.RiskState -eq "notAtRisk") { $riskSummary.NotAtRisk++ }
                            elseif ($user.RiskState -eq "remediated") { $riskSummary.Remediated++ }
                            elseif ($user.RiskState -eq "dismissed") { $riskSummary.Dismissed++ }
                            $count++
                        }
                    } else {
                        Write-LogFile -Message "[INFO] User ID $userId not found or not risky." -Level Standard
                    }
                } catch {
                    Write-LogFile -Message "[ERROR] Failed to retrieve data for User ID $userId : $($_.Exception.Message)" -Color "Red" -Level Minimal
                }
            }
        }
        else {
            $uri = "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers"
            do {
                $response = Invoke-MgGraphRequest -Method GET -Uri $uri

                if ($response.value) {
                    foreach ($user in $response.value) {
                        $results += [PSCustomObject]@{
                            Id                          = $user.Id
                            IsDeleted                   = $user.IsDeleted
                            IsProcessing                = $user.IsProcessing
                            RiskDetail                  = $user.RiskDetail
                            RiskLastUpdatedDateTime     = $user.RiskLastUpdatedDateTime
                            RiskLevel                   = $user.RiskLevel
                            RiskState                   = $user.RiskState
                            UserDisplayName             = $user.UserDisplayName
                            UserPrincipalName           = $user.UserPrincipalName
                            AdditionalProperties        = $user.AdditionalProperties -join ", "
                        }

                        if ($user.RiskLevel) { $riskSummary[$user.RiskLevel]++ }
                        if ($user.RiskState -eq "atRisk") { $riskSummary.AtRisk++ }
                        elseif ($user.RiskState -eq "confirmedSafe") { $riskSummary.NotAtRisk++ }
                        elseif ($user.RiskState -eq "remediated") { $riskSummary.Remediated++ }
                        elseif ($user.RiskState -eq "dismissed") { $riskSummary.Dismissed++ }
                        $count++
                    }
                }
                $uri = $response.'@odata.nextLink'
            } while ($uri -ne $null)
        }
    } catch {
        Write-LogFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Color "Red" -Level Minimal
        throw
    }

    $date = Get-Date -Format "yyyyMMddHHmm"
    $filePath = "$OutputDir\$($date)-RiskyUsers.csv"

    if ($results.Count -gt 0) {
        $results | Export-Csv -Path $filePath -NoTypeInformation -Encoding $Encoding
        Write-LogFile -Message "[INFO] A total of $count Risky Users found" -Level Standard
        
        Write-LogFile -Message "`nSummary of Risky Users:" -Color "Cyan" -Level Standard 
        Write-LogFile -Message "----------------------------------------" -Level Standard
        Write-LogFile -Message "Total Risky Users: $count" -Level Standard
        Write-LogFile -Message "  - High Risk: $($riskSummary.High)" -Level Standard
        Write-LogFile -Message "  - Medium Risk: $($riskSummary.Medium)" -Level Standard
        Write-LogFile -Message "  - Low Risk: $($riskSummary.Low)" -Level Standard

        Write-LogFile -Message "`nRisk States:" -Level Standard
        Write-LogFile -Message "  - At Risk: $($riskSummary.AtRisk)" -Level Standard
        Write-LogFile -Message "  - Confirmed Safe: $($riskSummary.NotAtRisk)" -Level Standard
        Write-LogFile -Message "  - Remediated: $($riskSummary.Remediated)" -Level Standard
        Write-LogFile -Message "  - Dismissed: $($riskSummary.Dismissed)" -Level Standard

        Write-LogFile -Message "`nExported Files:" -Level Standard
        Write-LogFile -Message "  - $filePath" -Level Standard
        } else {
        Write-LogFile -Message "[INFO] No Risky Users found" -Color "Yellow" -Level Standard
    }
}

function Get-RiskyDetections {
<#
    .SYNOPSIS
    Retrieves the risky detections from the Entra ID Identity Protection.

    .DESCRIPTION
    Retrieves the risky detections from the Entra ID Identity Protection.

    .PARAMETER OutputDir
    OutputDir is the parameter specifying the output directory.
    Default: Output\RiskyEvents

    .PARAMETER Encoding
    Encoding is the parameter specifying the encoding of the CSV output file.
    Default: UTF8

    .PARAMETER UserIds
    An array of User IDs to retrieve risky detections information for.
    If not specified, retrieves all risky detections.

    .PARAMETER LogLevel
    Specifies the level of logging:
    None: No logging
    Minimal: Critical errors only
    Standard: Normal operational logging
    Default: Standard
        
    .EXAMPLE
    Get-RiskyDetections
    Retrieves all the risky detections.
	
    .EXAMPLE
    Get-RiskyDetections -Encoding utf32
    Retrieves the risky detections and exports the output to a CSV file with UTF-32 encoding.
		
    .EXAMPLE
    Get-RiskyDetections -OutputDir C:\Windows\Temp
    Retrieves the risky detections and saves the output to the C:\Windows\Temp folder.
    
    .EXAMPLE
    Get-RiskyDetections -UserIds "user-id-1","user-id-2"
    Retrieves risky detections for the specified User IDs.
#>
    [CmdletBinding()]
    param(
        [string]$OutputDir= "Output\RiskyEvents",
        [string]$Encoding = "UTF8",
        [string[]]$UserIds,
        [ValidateSet('None', 'Minimal', 'Standard')]
        [string]$LogLevel = 'Standard'
    )

    Set-LogLevel -Level ([LogLevel]::$LogLevel)
    Write-LogFile -Message "=== Starting Risky Detections Collection ===" -Color "Cyan" -Level Minimal

    $requiredScopes = @("IdentityRiskEvent.Read.All","IdentityRiskyUser.Read.All")
    $graphAuth = Get-GraphAuthType -RequiredScopes $RequiredScopes

    if (!(test-path $OutputDir)) {
        New-Item -ItemType Directory -Force -Name $OutputDir > $null
    }
    else {
        if (!(Test-Path -Path $OutputDir)) {
            Write-Error "[Error] Custom directory invalid: $OutputDir exiting script" -ErrorAction Stop
            Write-LogFile -Message "[Error] Custom directory invalid: $OutputDir exiting script" -Level Minimal
        }
    }

    $results = @()
    $count = 0
    $riskSummary = @{
        High = 0
        Medium = 0 
        Low = 0
        AtRisk = 0
        NotAtRisk = 0
        Remediated = 0
        Dismissed = 0
        UniqueUsers = @{}
        UniqueCountries = @{}
        UniqueCities = @{}
    }

    try {
        $baseUri = "https://graph.microsoft.com/v1.0/identityProtection/riskDetections"

        if ($UserIds) {
            foreach ($userId in $UserIds) {
                $encodedUserId = [System.Web.HttpUtility]::UrlEncode($userId)
                $uri = "$baseUri`?`$filter=UserPrincipalName eq '$encodedUserId'"
                Write-LogFile -Message "[INFO] Retrieving risky detections for User ID: $userId" -Level Standard

                do {
                    $response = Invoke-MgGraphRequest -Method GET -Uri $uri

                    if ($response.value) {
                        foreach ($detection in $response.value) {
                            $results += [PSCustomObject]@{
                                Activity = $detection.Activity
                                ActivityDateTime = $detection.ActivityDateTime
                                AdditionalInfo = $detection.AdditionalInfo
                                CorrelationId = $detection.CorrelationId
                                DetectedDateTime = $detection.DetectedDateTime
                                IPAddress = $detection.IPAddress
                                Id = $detection.Id
                                LastUpdatedDateTime = $detection.LastUpdatedDateTime
                                City = $detection.Location.City
                                CountryOrRegion = $detection.Location.CountryOrRegion
                                State = $detection.Location.State
                                RequestId = $detection.RequestId
                                RiskDetail = $detection.RiskDetail
                                RiskEventType = $detection.RiskEventType
                                RiskLevel = $detection.RiskLevel
                                RiskState = $detection.RiskState
                                DetectionTimingType = $detection.DetectionTimingType
                                Source = $detection.Source
                                TokenIssuerType = $detection.TokenIssuerType
                                UserDisplayName = $detection.UserDisplayName
                                UserId = $detection.UserId
                                UserPrincipalName = $detection.UserPrincipalName
                                AdditionalProperties = $detection.AdditionalProperties -join ", "
                            }

                            if ($detection.RiskLevel) { $riskSummary[$detection.RiskLevel]++ }
                            if ($detection.RiskState -eq "atRisk") { $riskSummary.AtRisk++ }
                            elseif ($detection.RiskState -eq "confirmedSafe") { $riskSummary.NotAtRisk++ }
                            elseif ($detection.RiskState -eq "remediated") { $riskSummary.Remediated++ }
                            elseif ($detection.RiskState -eq "dismissed") { $riskSummary.Dismissed++ }

                            if ($detection.UserPrincipalName) { $riskSummary.UniqueUsers[$detection.UserPrincipalName] = $true }
                            if ($detection.Location.CountryOrRegion) { $riskSummary.UniqueCountries[$detection.Location.CountryOrRegion] = $true }
                            if ($detection.Location.City) { $riskSummary.UniqueCities[$detection.Location.City] = $true }

                            $count++
                        }
                    }

                    $uri = $response.'@odata.nextLink'
                } while ($uri -ne $null)
            }
        }
        else {
            do {
                $response = Invoke-MgGraphRequest -Method GET -Uri $baseUri

                if ($response.value) {
                    foreach ($detection in $response.value) {
                        $results += [PSCustomObject]@{
                            Activity = $detection.Activity
                            ActivityDateTime = $detection.ActivityDateTime
                            AdditionalInfo = $detection.AdditionalInfo
                            CorrelationId = $detection.CorrelationId
                            DetectedDateTime = $detection.DetectedDateTime
                            IPAddress = $detection.IPAddress
                            Id = $detection.Id
                            LastUpdatedDateTime = $detection.LastUpdatedDateTime
                            City = $detection.Location.City
                            CountryOrRegion = $detection.Location.CountryOrRegion
                            State = $detection.Location.State
                            RequestId = $detection.RequestId
                            RiskDetail = $detection.RiskDetail
                            RiskEventType = $detection.RiskEventType
                            RiskLevel = $detection.RiskLevel
                            RiskState = $detection.RiskState
                            DetectionTimingType = $detection.DetectionTimingType
                            Source = $detection.Source
                            TokenIssuerType = $detection.TokenIssuerType
                            UserDisplayName = $detection.UserDisplayName
                            UserId = $detection.UserId
                            UserPrincipalName = $detection.UserPrincipalName
                            AdditionalProperties = $detection.AdditionalProperties -join ", "
                        }

                        if ($detection.RiskLevel) { $riskSummary[$detection.RiskLevel]++ }
                        if ($detection.RiskState -eq "atRisk") { $riskSummary.AtRisk++ }
                        elseif ($detection.RiskState -eq "confirmedSafe") { $riskSummary.NotAtRisk++ }
                        elseif ($detection.RiskState -eq "remediated") { $riskSummary.Remediated++ }
                        elseif ($detection.RiskState -eq "dismissed") { $riskSummary.Dismissed++ }

                        if ($detection.UserPrincipalName) { $riskSummary.UniqueUsers[$detection.UserPrincipalName] = $true }
                        if ($detection.Location.CountryOrRegion) { $riskSummary.UniqueCountries[$detection.Location.CountryOrRegion] = $true }
                        if ($detection.Location.City) { $riskSummary.UniqueCities[$detection.Location.City] = $true }

                        $count++
                    }
                }

                $baseUri = $response.'@odata.nextLink'
            } while ($baseUri -ne $null)
        }
    } catch {
        Write-LogFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Color "Red" -Level Minimal
        Write-LogFile -Message "[ERROR (Continued)] Check the below, as the target tenant may not be licenced for this feature $($_.ErrorDetails.Message)" -Color "Red" -Level Minimal
        throw
    }

    $date = Get-Date -Format "yyyyMMddHHmm"
    $filePath = "$OutputDir\$($date)-RiskyDetections.csv"

    if ($results.Count -gt 0) {
        $results | Export-Csv -Path $filePath -NoTypeInformation -Encoding $Encoding

        Write-LogFile -Message "`nSummary of Risky Detections:" -Color "Cyan" -Level Standard 
        Write-LogFile -Message "----------------------------------------" -Level Standard
        Write-LogFile -Message "Total Risky Detections: $count" -Level Standard
        Write-LogFile -Message "  - High Risk: $($riskSummary.High)" -Level Standard
        Write-LogFile -Message "  - Medium Risk: $($riskSummary.Medium)" -Level Standard
        Write-LogFile -Message "  - Low Risk: $($riskSummary.Low)" -Level Standard

        Write-LogFile -Message "`nRisk States:" -Level Standard
        Write-LogFile -Message "  - At Risk: $($riskSummary.AtRisk)" -Level Standard
        Write-LogFile -Message "  - Confirmed Safe: $($riskSummary.NotAtRisk)" -Level Standard
        Write-LogFile -Message "  - Remediated: $($riskSummary.Remediated)" -Level Standard
        Write-LogFile -Message "  - Dismissed: $($riskSummary.Dismissed)" -Level Standard

        Write-LogFile -Message "`nAffected Resources:" -Level Standard 
        Write-LogFile -Message "  - Unique Users: $($riskSummary.UniqueUsers.Count)" -Level Standard
        Write-LogFile -Message "  - Unique Countries: $($riskSummary.UniqueCountries.Count)" -Level Standard

        Write-LogFile -Message "`nExported Files:" -Level Standard
        Write-LogFile -Message "  - $filePath" -Level Standard
    } else {
        Write-LogFile -Message "[INFO] No Risky Detections found" -Color "Yellow" -Level Standard
    }
}