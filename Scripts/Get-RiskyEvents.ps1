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
    Debug: Verbose logging for debugging purposes
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
        [ValidateSet('None', 'Minimal', 'Standard', 'Debug')]
        [string]$LogLevel = 'Standard'
    )

    Set-LogLevel -Level ([LogLevel]::$LogLevel)
    $isDebugEnabled = $script:LogLevel -eq [LogLevel]::Debug

    Write-LogFile -Message "=== Starting Risky Users Collection ===" -Color "Cyan" -Level Minimal

    if ($isDebugEnabled) {
        Write-LogFile -Message "[DEBUG] PowerShell Version: $($PSVersionTable.PSVersion)" -Level Debug
        Write-LogFile -Message "[DEBUG] Input parameters:" -Level Debug
        Write-LogFile -Message "[DEBUG]   OutputDir: '$OutputDir'" -Level Debug
        Write-LogFile -Message "[DEBUG]   Encoding: '$Encoding'" -Level Debug
        Write-LogFile -Message "[DEBUG]   UserIds: '$($UserIds -join ', ')'" -Level Debug
        Write-LogFile -Message "[DEBUG]   UserIds count: $($UserIds.Count)" -Level Debug
        Write-LogFile -Message "[DEBUG]   LogLevel: '$LogLevel'" -Level Debug
        
        $graphModules = Get-Module -Name Microsoft.Graph* -ErrorAction SilentlyContinue
        if ($graphModules) {
            Write-LogFile -Message "[DEBUG] Microsoft Graph Modules loaded:" -Level Debug
            foreach ($module in $graphModules) {
                Write-LogFile -Message "[DEBUG]   - $($module.Name) v$($module.Version)" -Level Debug
            }
        } else {
            Write-LogFile -Message "[DEBUG] No Microsoft Graph modules loaded" -Level Debug
        }
    }

    $requiredScopes = @("IdentityRiskEvent.Read.All","IdentityRiskyUser.Read.All")
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
    if (!(test-path $OutputDir)) {
        New-Item -ItemType Directory -Force -Path $OutputDir > $null
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
            if ($isDebugEnabled) {
                Write-LogFile -Message "[DEBUG] Processing scenario: Specific users" -Level Debug
                Write-LogFile -Message "[DEBUG] Users to process: $($UserIds -join ', ')" -Level Debug
            }
            foreach ($userId in $UserIds) {
                $encodedUserId = [System.Web.HttpUtility]::UrlEncode($userId)
                $uri = "$baseUri`?`$filter=userPrincipalName eq '$encodedUserId'"
                Write-LogFile -Message "[INFO] Retrieving risky user for UPN: $userId" -Level Standard
        
                try {
                    $response = Invoke-MgGraphRequest -Method GET -Uri $uri
        
                    if ($isDebugEnabled) {
                        Write-LogFile -Message "[DEBUG]   Response received:" -Level Debug
                        Write-LogFile -Message "[DEBUG]     Value count: $($response.value.Count)" -Level Debug
                        Write-LogFile -Message "[DEBUG]     Has @odata.nextLink: $($null -ne $response.'@odata.nextLink')" -Level Debug
                    }
        
                    if ($response.value -and $response.value.Count -gt 0) {
                        if ($isDebugEnabled) {
                            Write-LogFile -Message "[DEBUG]   Found $($response.value.Count) risky user records" -Level Debug
                        }
                        foreach ($user in $response.value) {
                            if ($isDebugEnabled) {
                                $userIdentifier = if ([string]::IsNullOrEmpty($user.UserPrincipalName)) {
                                    if (![string]::IsNullOrEmpty($user.UserDisplayName)) {
                                        "DisplayName: $($user.UserDisplayName)"
                                    } elseif (![string]::IsNullOrEmpty($user.Id)) {
                                        "ID: $($user.Id)"
                                    } else {
                                        "[Unknown User]"
                                    }
                                } else {
                                    $user.UserPrincipalName
                                }
                                Write-LogFile -Message "[DEBUG]     Processing user record:" -Level Debug
                                Write-LogFile -Message "[DEBUG]       User: $userIdentifier" -Level Debug
                                Write-LogFile -Message "[DEBUG]       Risk Level: $($user.RiskLevel)" -Level Debug
                                Write-LogFile -Message "[DEBUG]       Risk State: $($user.RiskState)" -Level Debug
                                Write-LogFile -Message "[DEBUG]       Risk Detail: $($user.RiskDetail)" -Level Debug
                                Write-LogFile -Message "[DEBUG]       Last Updated: $($user.RiskLastUpdatedDateTime)" -Level Debug
                            }
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

                            if ($isDebugEnabled) {
                                Write-LogFile -Message "[DEBUG]     Updated summary counts - Total: $count, RiskLevel: $($user.RiskLevel), RiskState: $($user.RiskState)" -Level Debug
                            }
                        }
                    } else {
                        Write-LogFile -Message "[INFO] User ID $userId not found or not risky." -Level Standard
                    }
                } catch {
                    Write-LogFile -Message "[ERROR] Failed to retrieve data for User ID $userId : $($_.Exception.Message)" -Color "Red" -Level Minimal
                    if ($isDebugEnabled) {
                        Write-LogFile -Message "[DEBUG]   Error details for user $userId :" -Level Debug
                        Write-LogFile -Message "[DEBUG]     Exception type: $($_.Exception.GetType().Name)" -Level Debug
                        Write-LogFile -Message "[DEBUG]     Error message: $($_.Exception.Message)" -Level Debug
                        Write-LogFile -Message "[DEBUG]     Stack trace: $($_.ScriptStackTrace)" -Level Debug
                    }
                }
            }
        }
        else {
            $uri = "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers"
            if ($isDebugEnabled) {
                Write-LogFile -Message "[DEBUG] Processing scenario: All risky users" -Level Debug
                Write-LogFile -Message "[DEBUG] Base URI: $uri" -Level Debug
            }
            do {
                $response = Invoke-MgGraphRequest -Method GET -Uri $uri
                if ($isDebugEnabled) {
                    Write-LogFile -Message "[DEBUG]     Value count: $($response.value.Count)" -Level Debug
                    Write-LogFile -Message "[DEBUG]     Has @odata.nextLink: $($null -ne $response.'@odata.nextLink')" -Level Debug
                }

                if ($response.value) {
                    if ($isDebugEnabled) {
                        Write-LogFile -Message "[DEBUG]   Processing $($response.value.Count) users from page $pageCount" -Level Debug
                    }
                    foreach ($user in $response.value) {
                        if ($isDebugEnabled) {
                            $userIdentifier = if ([string]::IsNullOrEmpty($user.UserPrincipalName)) {
                                if (![string]::IsNullOrEmpty($user.UserDisplayName)) {
                                    "DisplayName: $($user.UserDisplayName)"
                                } elseif (![string]::IsNullOrEmpty($user.Id)) {
                                    "ID: $($user.Id)"
                                } else {
                                    "[Unknown User]"
                                }
                            } else {
                                $user.UserPrincipalName
                            }
                            Write-LogFile -Message "[DEBUG]     Processing user: $userIdentifier" -Level Debug
                            Write-LogFile -Message "[DEBUG]       Risk Level: $($user.RiskLevel)" -Level Debug
                            Write-LogFile -Message "[DEBUG]       Risk State: $($user.RiskState)" -Level Debug
                        }
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
        if ($isDebugEnabled) {
            Write-LogFile -Message "[DEBUG] Error details:" -Level Debug
            Write-LogFile -Message "[DEBUG]   Exception type: $($_.Exception.GetType().Name)" -Level Debug
            Write-LogFile -Message "[DEBUG]   Error message: $($_.Exception.Message)" -Level Debug
            Write-LogFile -Message "[DEBUG]   Stack trace: $($_.ScriptStackTrace)" -Level Debug
        }
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
    Debug: Verbose logging for debugging purposes
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
        [ValidateSet('None', 'Minimal', 'Standard', 'Debug')]
        [string]$LogLevel = 'Standard'
    )

    Set-LogLevel -Level ([LogLevel]::$LogLevel)
    $isDebugEnabled = $script:LogLevel -eq [LogLevel]::Debug

    if ($isDebugEnabled) {
        Write-LogFile -Message "[DEBUG] PowerShell Version: $($PSVersionTable.PSVersion)" -Level Debug
        Write-LogFile -Message "[DEBUG] Input parameters:" -Level Debug
        Write-LogFile -Message "[DEBUG]   OutputDir: '$OutputDir'" -Level Debug
        Write-LogFile -Message "[DEBUG]   Encoding: '$Encoding'" -Level Debug
        Write-LogFile -Message "[DEBUG]   UserIds: '$($UserIds -join ', ')'" -Level Debug
        Write-LogFile -Message "[DEBUG]   UserIds count: $($UserIds.Count)" -Level Debug
        Write-LogFile -Message "[DEBUG]   LogLevel: '$LogLevel'" -Level Debug
        
        $graphModules = Get-Module -Name Microsoft.Graph* -ErrorAction SilentlyContinue
        if ($graphModules) {
            Write-LogFile -Message "[DEBUG] Microsoft Graph Modules loaded:" -Level Debug
            foreach ($module in $graphModules) {
                Write-LogFile -Message "[DEBUG]   - $($module.Name) v$($module.Version)" -Level Debug
            }
        } else {
            Write-LogFile -Message "[DEBUG] No Microsoft Graph modules loaded" -Level Debug
        }
    }

    Write-LogFile -Message "=== Starting Risky Detections Collection ===" -Color "Cyan" -Level Minimal

    $requiredScopes = @("IdentityRiskEvent.Read.All","IdentityRiskyUser.Read.All")
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

    if (!(test-path $OutputDir)) {
        New-Item -ItemType Directory -Force -Path $OutputDir > $null
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
            if ($isDebugEnabled) {
                Write-LogFile -Message "[DEBUG] Processing scenario: Specific users" -Level Debug
                Write-LogFile -Message "[DEBUG] Users to process: $($UserIds -join ', ')" -Level Debug
            }
            foreach ($userId in $UserIds) {
                $encodedUserId = [System.Web.HttpUtility]::UrlEncode($userId)
                $uri = "$baseUri`?`$filter=UserPrincipalName eq '$encodedUserId'"
                Write-LogFile -Message "[INFO] Retrieving risky detections for User ID: $userId" -Level Standard

                do {
                    $response = Invoke-MgGraphRequest -Method GET -Uri $uri

                    if ($isDebugEnabled) {
                        Write-LogFile -Message "[DEBUG]     Value count: $($response.value.Count)" -Level Debug
                        Write-LogFile -Message "[DEBUG]     Has @odata.nextLink: $($null -ne $response.'@odata.nextLink')" -Level Debug
                    }

                    if ($response.value) {
                        if ($isDebugEnabled) {
                            Write-LogFile -Message "[DEBUG]   Processing $($response.value.Count) detections from page $pageCount" -Level Debug
                        }
                        foreach ($detection in $response.value) {
                            if ($isDebugEnabled) {
                                $userIdentifier = if ([string]::IsNullOrEmpty($detection.UserPrincipalName)) {
                                    if (![string]::IsNullOrEmpty($detection.UserDisplayName)) {
                                        "DisplayName: $($detection.UserDisplayName)"
                                    } elseif (![string]::IsNullOrEmpty($detection.UserId)) {
                                        "ID: $($detection.UserId)"
                                    } else {
                                        "[Unknown User]"
                                    }
                                } else {
                                    $detection.UserPrincipalName
                                }
                                Write-LogFile -Message "[DEBUG]     Processing detection:" -Level Debug
                                Write-LogFile -Message "[DEBUG]       Detection ID: $($detection.Id)" -Level Debug
                                Write-LogFile -Message "[DEBUG]       Risk Event Type: $($detection.RiskEventType)" -Level Debug
                                Write-LogFile -Message "[DEBUG]       Risk Level: $($detection.RiskLevel)" -Level Debug
                                Write-LogFile -Message "[DEBUG]       Risk State: $($detection.RiskState)" -Level Debug
                                Write-LogFile -Message "[DEBUG]       User: $userIdentifier" -Level Debug
                                Write-LogFile -Message "[DEBUG]       IP Address: $($detection.IPAddress)" -Level Debug
                                Write-LogFile -Message "[DEBUG]       Location: $($detection.Location.City), $($detection.Location.CountryOrRegion)" -Level Debug
                            }
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
                if ($isDebugEnabled) {
                    Write-LogFile -Message "[DEBUG] Processing scenario: All risky detections" -Level Debug
                    Write-LogFile -Message "[DEBUG] Base URI: $baseUri" -Level Debug
                    Write-LogFile -Message "[DEBUG]     Value count: $($response.value.Count)" -Level Debug
                    Write-LogFile -Message "[DEBUG]     Has @odata.nextLink: $($null -ne $response.'@odata.nextLink')" -Level Debug
                }

                if ($response.value) {
                    if ($isDebugEnabled) {
                        Write-LogFile -Message "[DEBUG]   Processing $($response.value.Count) detections from page $pageCount" -Level Debug
                    }
                    foreach ($detection in $response.value) {
                        if ($isDebugEnabled) {
                            $userIdentifier = if ([string]::IsNullOrEmpty($detection.UserPrincipalName)) {
                                if (![string]::IsNullOrEmpty($detection.UserDisplayName)) {
                                    "DisplayName: $($detection.UserDisplayName)"
                                } elseif (![string]::IsNullOrEmpty($detection.UserId)) {
                                    "ID: $($detection.UserId)"
                                } else {
                                    "[Unknown User]"
                                }
                            } else {
                                $detection.UserPrincipalName
                            }
                            Write-LogFile -Message "[DEBUG]     Processing detection: $($detection.Id)" -Level Debug
                            Write-LogFile -Message "[DEBUG]       Risk Event Type: $($detection.RiskEventType)" -Level Debug
                            Write-LogFile -Message "[DEBUG]       Risk Level: $($detection.RiskLevel)" -Level Debug
                            Write-LogFile -Message "[DEBUG]       User: $userIdentifier" -Level Debug
                        }
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