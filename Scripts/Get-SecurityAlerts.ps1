Function Get-SecurityAlerts {
<#
    .SYNOPSIS
    Retrieves security alerts.

    .DESCRIPTION
    Retrieves security alerts from Microsoft Graph, choosing between Get-MgSecurityAlert and 
    Get-MgSecurityAlertV2 based on the authentication type used.

    .PARAMETER OutputDir
    OutputDir is the parameter specifying the output directory.
    Default: Output\SecurityAlerts

    .PARAMETER Encoding
    Encoding is the parameter specifying the encoding of the CSV output file.
    Default: UTF8

    .PARAMETER LogLevel
    Specifies the level of logging:
    None: No logging
    Minimal: Critical errors only
    Standard: Normal operational logging
    Default: Standard

    .PARAMETER AlertId
    AlertId is the parameter specifying a specific alert ID to retrieve.
    Default: All alerts will be retrieved if not specified.

    .PARAMETER DaysBack
    Number of days to look back for alerts.
    Default: 90

    .PARAMETER Filter
    Custom filter string to apply to the alert retrieval.
    Default: None

    .EXAMPLE
    Get-SecurityAlerts
    Retrieves all security alerts from the past 30 days.

    .EXAMPLE
    Get-SecurityAlerts -AlertId "123456-abcdef-7890"
    Retrieves a specific security alert by ID.

    .EXAMPLE
    Get-SecurityAlerts -DaysBack 7
    Retrieves security alerts from the past 7 days.

    .EXAMPLE
    Get-SecurityAlerts -Filter "severity eq 'high'"
    Retrieves high severity security alerts.
#>
    [CmdletBinding()]
    param(
        [string]$OutputDir,
        [string]$Encoding = "UTF8",
        [string]$AlertId,
        [int]$DaysBack = 90,
        [string]$Filter,
        [ValidateSet('None', 'Minimal', 'Standard')]
        [string]$LogLevel = 'Standard'
    )

    Init-Logging
    Init-OutputDir -Component "SecurityAlerts" -FilePostfix "SecurityAlerts" -CustomOutputDir $OutputDir

    Write-LogFile -Message "=== Starting Security Alerts Collection ===" -Color "Cyan" -Level Standard

    $requiredScopes = @("SecurityEvents.Read.All")
    $graphAuth = Get-GraphAuthType -RequiredScopes $RequiredScopes       
    Write-LogFile -Message "[INFO] Analyzing security alerts..." -Level Standard

    try {
        # Choose the appropriate cmdlet based on auth type
        if ($graphAuth.Type -eq "Application") {
            #Write-LogFile -Message "[INFO] Using application authentication - selecting Get-MgSecurityAlertV2" -Level Standard
            $cmdlet = "Get-MgSecurityAlertV2"
        } else {
            #Write-LogFile -Message "[INFO] Using delegated authentication - selecting Get-MgSecurityAlert" -Level Standard
            $cmdlet = "Get-MgSecurityAlert"
        }

        $params = @{}
        if ($AlertId) {
            Write-LogFile -Message "[INFO] Retrieving specific alert: $AlertId" -Level Standard
            $params.Add("AlertId", $AlertId)
        } 
        else {
            if ($DaysBack -gt 0) {
                $startDate = (Get-Date).AddDays(-$DaysBack).ToString("yyyy-MM-ddT00:00:00Z")
                
                if ($Filter) {
                    $timeFilter = "createdDateTime ge $startDate"
                    $params.Add("Filter", "($Filter) and ($timeFilter)")
                    Write-LogFile -Message "[INFO] Using combined filter: $($params.Filter)" -Level Standard
                } 
                else {
                    $params.Add("Filter", "createdDateTime ge $startDate")
                    Write-LogFile -Message "[INFO] Filtering alerts from $startDate" -Level Standard
                }
            } 
            elseif ($Filter) {
                $params.Add("Filter", $Filter)
                Write-LogFile -Message "[INFO] Using custom filter: $Filter" -Level Standard
            }
            
            $params.Add("All", $true)
        }

        if ($cmdlet -eq "Get-MgSecurityAlert") {
            if ($AlertId) {
                $alerts = Get-MgSecurityAlert -AlertId $AlertId
            } else {
                $alerts = Get-MgSecurityAlert @params
            }
        } else {
            if ($AlertId) {
                $alerts = Get-MgSecurityAlertV2 -AlertId $AlertId
            } else {
                $alerts = Get-MgSecurityAlertV2 @params
            }
        }

        $alertSummary = @{
            TotalAlerts = 0
            SeverityHigh = 0
            SeverityMedium = 0
            SeverityLow = 0
            SeverityInformational = 0
            StatusNew = 0
            StatusInProgress = 0
            StatusResolved = 0
            StatusDismissed = 0
            StatusUnknown = 0
        }

        $formattedAlerts = $alerts | ForEach-Object {
            $alertSummary.TotalAlerts++
            
            switch ($_.Severity) {
                "high" { $alertSummary.SeverityHigh++ }
                "medium" { $alertSummary.SeverityMedium++ }
                "low" { $alertSummary.SeverityLow++ }
                "informational" { $alertSummary.SeverityInformational++ }
            }
            
            switch ($_.Status) {
                "newAlert" { $alertSummary.StatusNew++ }
                "new" { $alertSummary.StatusNew++ }
                "inProgress" { $alertSummary.StatusInProgress++ }
                "resolved" { $alertSummary.StatusResolved++ }
                "dismissed" { $alertSummary.StatusDismissed++ }
                default { $alertSummary.StatusUnknown++ }
            }

            # Extract affected users, handling both null and populated UserStates
            $affectedUsers = ""
            if ($_.UserStates -and $_.UserStates.Count -gt 0) {
                $userDetails = @()
                foreach ($userState in $_.UserStates) {
                    if ($userState.UserPrincipalName) {
                        $userInfo = $userState.UserPrincipalName
                        if ($userState.LogonIP) {
                            $userInfo += "/$($userState.LogonIP)"
                        } else {
                            $userInfo += "/null"
                        }
                        $userDetails += $userInfo
                    } elseif ($userState.Name) {
                        $userDetails += "$($userState.Name)/null"
                    }
                }
                $affectedUsers = $userDetails -join "; "
            }

            $affectedHosts = ""
            if ($_.HostStates -and $_.HostStates.Count -gt 0) {
                $hostDetails = @()
                foreach ($hostState in $_.HostStates) {
                    $hostInfo = ""
                    if ($hostState.NetBiosName) {
                        $hostInfo = $hostState.NetBiosName
                    } elseif ($hostState.PrivateHostName) {
                        $hostInfo = $hostState.PrivateHostName
                    } else {
                        $hostInfo = "Unknown"
                    }

                    if ($hostState.PrivateIpAddress) {
                        $hostInfo += "/$($hostState.PrivateIpAddress)"
                    } else {
                        $hostInfo += "/null"
                    }
                    
                    $hostDetails += $hostInfo
                }
                $affectedHosts = $hostDetails -join "; "
            }

            $sourceURLs = ($_.SourceMaterials) -join "; "
            
            $cloudApps = ($_.CloudAppStates | ForEach-Object { "$($_.Name): $($_.InstanceName)" }) -join "; "
            $comments = ($_.Comments | ForEach-Object { 
                if ($_.CreatedBy.User.DisplayName) {
                    "$($_.Comment) - $($_.CreatedBy.User.DisplayName)" 
                } else {
                    $_.Comment
                }
            }) -join "; "
            
            [PSCustomObject]@{
                Id = $_.Id
                Title = $_.Title
                Category = $_.Category
                Severity = $_.Severity
                Status = $_.Status
                CreatedDateTime = $_.CreatedDateTime
                EventDateTime = $_.EventDateTime
                LastModifiedDateTime = $_.LastModifiedDateTime
                AssignedTo = $_.AssignedTo
                Description = $_.Description
                DetectionSource = $_.DetectionSource
                AffectedUser = $affectedUsers
                AffectedHost = $affectedHosts
                AzureTenantId = $_.AzureTenantId
                AzureSubscriptionId = $_.AzureSubscriptionId
                Confidence = $_.Confidence
                ActivityGroupName = $_.ActivityGroupName
                ClosedDateTime = $_.ClosedDateTime
                Feedback = $_.Feedback
                LastEventDateTime = $_.LastEventDateTime
                SourceURL = $sourceURLs
                CloudAppStates = $cloudApps
                Comments = $comments
                Tags = ($_.Tags -join ", ")
                Vendor = $_.VendorInformation.Vendor
                Provider = $_.VendorInformation.Provider
                SubProvider = $_.VendorInformation.SubProvider
                ProviderVersion = $_.VendorInformation.ProviderVersion
                IncidentIds = ($_.IncidentIds -join ", ")
            }
        }

        $formattedAlerts | Export-Csv -Path $script:outputFile -NoTypeInformation -Encoding $Encoding

        $summary = [ordered]@{
            "Alert Summary" = [ordered]@{
                "Total Alerts" = $alertSummary.TotalAlerts
            }
            "Severity Distribution" = [ordered]@{
                "High" = $alertSummary.SeverityHigh
                "Medium" = $alertSummary.SeverityMedium
                "Low" = $alertSummary.SeverityLow
                "Informational" = $alertSummary.SeverityInformational
            }
            "Status Distribution" = [ordered]@{
                "New" = $alertSummary.StatusNew
                "In Progress" = $alertSummary.StatusInProgress
                "Resolved" = $alertSummary.StatusResolved
                "Dismissed" = $alertSummary.StatusDismissed
                "Unknown" = $alertSummary.StatusUnknown
            }
        }

        Write-Summary -Summary $summary -Title "Security Alerts Analysis"
    }
    catch {
        Write-LogFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Color "Red" -Level Minimal
        throw
    }
}