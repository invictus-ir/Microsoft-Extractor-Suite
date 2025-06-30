function Get-EntraApplicationsForSpecificUsers {
    <#
    .SYNOPSIS
    Retrieves Entra ID applications owned by or assigned to specific users.

    .DESCRIPTION
    This function efficiently collects information about applications that are owned by 
    or assigned to the specified users, avoiding the need to process all applications 
    in the tenant.

    .PARAMETER OutputDir
    OutputDir is the parameter specifying the output directory.
    Default: Output\Applications

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

    .PARAMETER UserIds
    Required parameter to filter applications by owner or assignments.
    Only shows applications owned by or assigned to these users.

    .EXAMPLE
    Get-EntraApplications -UserIds @("admin@domain.com")
    Retrieves applications owned by or assigned to specific users.

    .EXAMPLE
    Get-EntraApplications -UserIds @("user1@domain.com","user2@domain.com") -OutputDir "C:\Security\Apps"
    Retrieves applications for multiple users with custom output directory.
    #>

    [CmdletBinding()]
    param(
        [string]$OutputDir = "Output\Applications", 
        [string]$Encoding = "UTF8",
        [ValidateSet('None', 'Minimal', 'Standard', 'Debug')]
        [string]$LogLevel = 'Standard',
        [Parameter(Mandatory=$true)]
        [string[]]$UserIds
    )

    Set-LogLevel -Level ([LogLevel]::$LogLevel)
    $isDebugEnabled = $script:LogLevel -eq [LogLevel]::Debug

    if ($isDebugEnabled) {
        Write-LogFile -Message "[DEBUG] PowerShell Version: $($PSVersionTable.PSVersion)" -Level Debug
        Write-LogFile -Message "[DEBUG] Input parameters:" -Level Debug
        Write-LogFile -Message "[DEBUG]   OutputDir: '$OutputDir'" -Level Debug
        Write-LogFile -Message "[DEBUG]   Encoding: '$Encoding'" -Level Debug
        Write-LogFile -Message "[DEBUG]   UserIds: '$($UserIds -join ', ')'" -Level Debug
        Write-LogFile -Message "[DEBUG]   LogLevel: '$LogLevel'" -Level Debug
    }

    Write-LogFile -Message "=== Starting Entra Applications Collection ===" -Color "Cyan" -Level Standard

    $requiredScopes = @("Application.Read.All", "Directory.Read.All")
    $graphAuth = Get-GraphAuthType -RequiredScopes $RequiredScopes

    if ($isDebugEnabled) {
        Write-LogFile -Message "[DEBUG] Graph authentication details:" -Level Debug
        Write-LogFile -Message "[DEBUG]   Required scopes: $($requiredScopes -join ', ')" -Level Debug
        Write-LogFile -Message "[DEBUG]   Authentication type: $($graphAuth.AuthType)" -Level Debug
        Write-LogFile -Message "[DEBUG]   Current scopes: $($graphAuth.Scopes -join ', ')" -Level Debug
    }

    if (!(Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Force -Path $OutputDir > $null
        Write-LogFile -Message "[INFO] Created output directory: $OutputDir" -Level Standard
    }

    $validUsers = @()
    Write-LogFile -Message "[INFO] Resolving $($UserIds.Count) users..." -Level Standard
    foreach ($userId in $UserIds) {
        try {
            $user = Get-MgUser -UserId $userId -ErrorAction Stop
            $validUsers += $user
            Write-LogFile -Message "[INFO] Resolved user: $($user.UserPrincipalName)" -Level Standard
        }
        catch {
            Write-LogFile -Message "[WARNING] Could not resolve user: $userId" -Color "Yellow" -Level Minimal
        }
    }

    if ($validUsers.Count -eq 0) {
        Write-LogFile -Message "[ERROR] No valid users found. Cannot proceed." -Color "Red" -Level Minimal
        return
    }

    $results = @()
    $processedAppIds = @{}
    $summary = @{
        OwnedApps = 0
        AssignedApps = 0
        TotalApps = 0
        StartTime = Get-Date
        ProcessingTime = $null
    }

    foreach ($user in $validUsers) {
        Write-LogFile -Message "[INFO] Processing user: $($user.UserPrincipalName)" -Level Standard

        # Get owned applications
        try {
            $ownedApps = Get-MgUserOwnedObject -UserId $user.Id -All | Where-Object { $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.application' }
            
            foreach ($ownedAppRef in $ownedApps) {
                if (-not $processedAppIds.ContainsKey($ownedAppRef.Id)) {
                    try {
                        $app = Get-MgApplication -ApplicationId $ownedAppRef.Id
                        $processedAppIds[$ownedAppRef.Id] = $true
                        $summary.OwnedApps++
                        
                        # Get service principal if it exists
                        $servicePrincipal = $null
                        try {
                            $servicePrincipals = Get-MgServicePrincipal -Filter "appId eq '$($app.AppId)'"
                            $servicePrincipal = $servicePrincipals | Select-Object -First 1
                        }
                        catch { }

                        $appObject = [PSCustomObject]@{
                            AssociationType = "Owner"
                            AssociatedUser = $user.UserPrincipalName
                            ApplicationName = $app.DisplayName
                            ApplicationId = $app.AppId
                            ObjectId = $app.Id
                            PublisherName = if ($servicePrincipal) { $servicePrincipal.PublisherName } else { "" }
                            ApplicationType = if ($servicePrincipal) { 
                                $types = @()
                                if ($servicePrincipal.AppOwnerOrganizationId -eq "f8cdef31-a31e-4b4a-93e4-5f571e91255a" -or $servicePrincipal.AppOwnerOrganizationId -eq "72f988bf-86f1-41af-91ab-2d7cd011db47") { 
                                    $types += "Microsoft Application" 
                                }
                                if ($servicePrincipal.ServicePrincipalType -eq "ManagedIdentity") { 
                                    $types += "Managed Identity" 
                                }
                                if ($servicePrincipal.Tags -contains "WindowsAzureActiveDirectoryIntegratedApp") { 
                                    $types += "Enterprise Application" 
                                }
                                if ($types.Count -eq 0) { "Internal Application" } else { $types -join " & " }
                            } else { "Internal Application" }
                            CreatedDateTime = $app.CreatedDateTime
                            ServicePrincipalEnabled = if ($servicePrincipal) { $servicePrincipal.AccountEnabled } else { "N/A" }
                            HasClientSecrets = ($app.PasswordCredentials -and $app.PasswordCredentials.Count -gt 0)
                            HasCertificates = ($app.KeyCredentials -and $app.KeyCredentials.Count -gt 0)
                            RequiredApiPermissionCount = if ($app.RequiredResourceAccess) { 
                                ($app.RequiredResourceAccess | ForEach-Object { $_.ResourceAccess.Count } | Measure-Object -Sum).Sum 
                            } else { 0 }
                            SignInAudience = $app.SignInAudience
                            Homepage = if ($servicePrincipal) { $servicePrincipal.Homepage } else { $app.Web.HomePageUrl }
                            WebRedirectUris = ($app.Web.RedirectUris -join "; ")
                            PublicClientRedirectUris = ($app.PublicClient.RedirectUris -join "; ")
                        }
                        
                        $results += $appObject
                    }
                    catch {
                        Write-LogFile -Message "[WARNING] Could not process owned app: $($_.Exception.Message)" -Color "Yellow" -Level Minimal
                    }
                }
            }
        }
        catch {
            Write-LogFile -Message "[WARNING] Error getting owned apps for $($user.UserPrincipalName): $($_.Exception.Message)" -Color "Yellow" -Level Minimal
        }

        # Get application assignments
        try {
            $userAssignments = Get-MgUserAppRoleAssignment -UserId $user.Id -All
            
            foreach ($assignment in $userAssignments) {
                try {
                    $servicePrincipal = Get-MgServicePrincipal -ServicePrincipalId $assignment.ResourceId
                    
                    $appKey = "SP_$($servicePrincipal.Id)"
                    
                    if (-not $processedAppIds.ContainsKey($appKey)) {
                        $processedAppIds[$appKey] = $true
                        $summary.AssignedApps++
                        
                        # Try to get the corresponding application registration
                        $app = $null
                        if ($servicePrincipal.AppId) {
                            try {
                                $apps = Get-MgApplication -Filter "appId eq '$($servicePrincipal.AppId)'"
                                $app = $apps | Select-Object -First 1
                            }
                            catch { }
                        }

                        $appObject = [PSCustomObject]@{
                            AssociationType = "Assignment"
                            AssociatedUser = $user.UserPrincipalName
                            ApplicationName = $servicePrincipal.DisplayName
                            ApplicationId = $servicePrincipal.AppId
                            ObjectId = if ($app) { $app.Id } else { $servicePrincipal.Id }
                            PublisherName = $servicePrincipal.PublisherName
                            ApplicationType = if ($servicePrincipal.AppOwnerOrganizationId -eq "f8cdef31-a31e-4b4a-93e4-5f571e91255a" -or $servicePrincipal.AppOwnerOrganizationId -eq "72f988bf-86f1-41af-91ab-2d7cd011db47") { 
                                "Microsoft Application" 
                            } elseif ($servicePrincipal.ServicePrincipalType -eq "ManagedIdentity") { 
                                "Managed Identity" 
                            } elseif ($servicePrincipal.Tags -contains "WindowsAzureActiveDirectoryIntegratedApp") { 
                                "Enterprise Application" 
                            } else { 
                                "Internal Application" 
                            }
                            CreatedDateTime = if ($app) { $app.CreatedDateTime } else { $servicePrincipal.AdditionalProperties.createdDateTime }
                            ServicePrincipalEnabled = $servicePrincipal.AccountEnabled
                            HasClientSecrets = if ($app) { ($app.PasswordCredentials -and $app.PasswordCredentials.Count -gt 0) } else { "N/A" }
                            HasCertificates = if ($app) { ($app.KeyCredentials -and $app.KeyCredentials.Count -gt 0) } else { "N/A" }
                            RequiredApiPermissionCount = if ($app -and $app.RequiredResourceAccess) { 
                                ($app.RequiredResourceAccess | ForEach-Object { $_.ResourceAccess.Count } | Measure-Object -Sum).Sum 
                            } else { "N/A" }
                            SignInAudience = if ($app) { $app.SignInAudience } else { "" }
                            Homepage = $servicePrincipal.Homepage
                            WebRedirectUris = if ($app) { ($app.Web.RedirectUris -join "; ") } else { "" }
                            PublicClientRedirectUris = if ($app) { ($app.PublicClient.RedirectUris -join "; ") } else { "" }
                        }
                        
                        $results += $appObject
                    }
                }
                catch {
                    Write-LogFile -Message "[WARNING] Could not process assignment: $($_.Exception.Message)" -Color "Yellow" -Level Minimal
                }
            }
        }
        catch {
            Write-LogFile -Message "[WARNING] Error getting assignments for $($user.UserPrincipalName): $($_.Exception.Message)" -Color "Yellow" -Level Minimal
        }
    }

    $summary.TotalApps = $results.Count
    $summary.ProcessingTime = (Get-Date) - $summary.StartTime

    $date = Get-Date -Format "yyyyMMddHHmm"
    $outputPath = Join-Path $OutputDir "$($date)-UserApplications.csv"
    
    Write-LogFile -Message "[INFO] Exporting $($results.Count) applications to CSV..." -Level Standard
    $results | Export-Csv -Path $outputPath -NoTypeInformation -Encoding $Encoding

    Write-LogFile -Message "`n=== User Applications Summary ===" -Color "Cyan" -Level Standard
    Write-LogFile -Message "Users Processed: $($validUsers.Count)" -Level Standard
    Write-LogFile -Message "Owned Applications: $($summary.OwnedApps)" -Level Standard
    Write-LogFile -Message "Assigned Applications: $($summary.AssignedApps)" -Level Standard
    Write-LogFile -Message "Total Applications: $($summary.TotalApps)" -Level Standard
    Write-LogFile -Message "Output File: $outputPath" -Level Standard
    Write-LogFile -Message "Processing Time: $($summary.ProcessingTime.ToString('mm\:ss'))" -Color "Green" -Level Standard
    Write-LogFile -Message "===================================" -Color "Cyan" -Level Standard
}

function Get-QuickUALOperations {
<#
    .SYNOPSIS
    Quickly retrieves specific operations from Unified Audit Log for triage purposes.

    .DESCRIPTION
    A lightweight function designed for quick security triage that focuses on specific 
    operations in the UAL without the complexity of the full Get-UAL function.
    Optimized for speed and simplicity.

    .PARAMETER Operations
    Array of specific operations to search for (e.g., 'SearchQueryInitiated', 'MailItemsAccessed')
    
    .PARAMETER UserIds
    Comma-separated list of user IDs to filter on
    
    .PARAMETER StartDate
    Start date for the search (defaults to 7 days ago)
    
    .PARAMETER EndDate  
    End date for the search (defaults to now)
    
    .PARAMETER OutputDir
    Output directory for results
    
    .PARAMETER MaxResults
    Maximum number of results to retrieve per operation (default: 5000)
    
    .PARAMETER LogLevel
    Logging level
    
    .EXAMPLE
    Get-QuickUALOperations -Operations @('SearchQueryInitiated', 'MailItemsAccessed') -UserIds "user@domain.com"
    
    .EXAMPLE  
    Get-QuickUALOperations -Operations @('New-InboxRule', 'Set-InboxRule') -OutputDir "C:\Triage\Case123"
#>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string[]]$Operations,
        [string[]]$UserIds,
        [string]$StartDate,
        [string]$EndDate,
        [string]$OutputDir,
        [ValidateSet("CSV", "JSON", "SOF-ELK")]
        [string]$Output = "CSV",
        [int]$MaxResults = 5000,
        [ValidateSet('None', 'Minimal', 'Standard', 'Debug')]
        [string]$LogLevel = 'Standard'
    )

    Set-LogLevel -Level ([LogLevel]::$LogLevel)
    $WarningPreference = 'SilentlyContinue'

    StartDate -Quiet
    EndDate -Quiet
    
    if ([string]::IsNullOrEmpty($OutputDir)) {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $OutputDir = "Output\QuickUAL\$timestamp"
    }
    
    if (!(Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Force -Path $OutputDir > $null
        Write-LogFile -Message "[INFO] Created output directory: $OutputDir" -Level Standard
    }

    Write-LogFile -Message "=== Quick UAL Operations Collection ===" -Color "Cyan" -Level Standard
    Write-LogFile -Message "Operations: $($Operations -join ', ')" -Level Standard
    Write-LogFile -Message "Date Range: $($script:StartDate.ToString('yyyy-MM-dd HH:mm:ss')) to $($script:EndDate.ToString('yyyy-MM-dd HH:mm:ss'))" -Level Standard
    if ($UserIds) {
        Write-LogFile -Message "Target Users: $($UserIds -join ', ')" -Level Standard
    }
    Write-LogFile -Message "Output Format: $Output" -Level Standard
    Write-LogFile -Message "Max Results per Operation: $MaxResults" -Level Standard
    Write-LogFile -Message "Output Directory: $OutputDir" -Level Standard
    Write-LogFile -Message "----------------------------------------" -Level Standard

    $allResults = @()
    $totalRecords = 0

    foreach ($operation in $Operations) {
        Write-LogFile -Message "[INFO] Searching for operation: $operation" -Level Minimal
        
        try {
            $searchParams = @{
                StartDate = $script:StartDate
                EndDate = $script:EndDate
                Operations = $operation
            }
            
            if ($UserIds -and $UserIds.Count -gt 0) {
                $searchParams.UserIds = $UserIds
            }
            
            $countResult = Search-UnifiedAuditLog @searchParams -ResultSize 1 -WarningAction SilentlyContinue | Select-Object -First 1 -ExpandProperty ResultCount
            
            if ($null -eq $countResult -or $countResult -eq 0) {
                Write-LogFile -Message "[INFO] No records found for operation: $operation" -Level Standard -Color "Yellow"
                continue
            }
            
            Write-LogFile -Message "[INFO] Found $countResult records for operation: $operation" -Level Standard -Color "Green"
            
            if ($countResult -gt $MaxResults) {
                Write-LogFile -Message "[WARNING] Found $countResult records but the max is $MaxResults. Consider using Get-UAL to get all results available if needed." -Color "Yellow" -Level Minimal
            }
            
            $results = Search-UnifiedAuditLog @searchParams -ResultSize $MaxResults -WarningAction SilentlyContinue
 
            if ($results) {
                $processedResults = $results | ForEach-Object {
                    $record = $_ | Select-Object *
                    if ($record.AuditData) {
                        try {
                            $record.AuditData = $record.AuditData | ConvertFrom-Json
                        }
                        catch {
                            Write-LogFile -Message "[WARNING] Failed to parse AuditData for record: $($record.Identity)" -Color "Yellow" -Level Standard
                        }
                    }
                    $record.PSObject.Properties.Add((New-Object PSNoteProperty('OperationQueried', $operation)))
                    $record
                }
                
                $allResults += $processedResults
                $totalRecords += $processedResults.Count
                $operationFileName = $operation -replace '[\\/:*?"<>|]', '_' 
                
                # Save as JSON
                $jsonPath = Join-Path $OutputDir "$operationFileName.json"
                $processedResults | ConvertTo-Json -Depth 10 | Out-File $jsonPath -Encoding UTF8
                Write-LogFile -Message "[INFO] Saved $($processedResults.Count) records to: $jsonPath" -Level Standard
                
                # Save as CSV (flatten AuditData for CSV)
                $csvPath = Join-Path $OutputDir "$operationFileName.csv"
                $csvResults = $processedResults | ForEach-Object {
                    $flatRecord = $_ | Select-Object * -ExcludeProperty AuditData
                    
                    # Add key AuditData fields as separate columns
                    if ($_.AuditData) {
                        $flatRecord | Add-Member -NotePropertyName "AuditData_UserId" -NotePropertyValue $_.AuditData.UserId -Force
                        $flatRecord | Add-Member -NotePropertyName "AuditData_ClientIP" -NotePropertyValue $_.AuditData.ClientIP -Force
                        $flatRecord | Add-Member -NotePropertyName "AuditData_UserAgent" -NotePropertyValue $_.AuditData.UserAgent -Force
                        $flatRecord | Add-Member -NotePropertyName "AuditData_ObjectId" -NotePropertyValue $_.AuditData.ObjectId -Force
                        
                        $flatRecord | Add-Member -NotePropertyName "AuditData_Raw" -NotePropertyValue ($_.AuditData | ConvertTo-Json -Compress -Depth 5) -Force
                    }
                    $flatRecord
                }
                
                $csvResults | Export-Csv $csvPath -NoTypeInformation -Encoding UTF8
                Write-LogFile -Message "[INFO] Saved CSV format to: $csvPath" -Level Standard
            }
        }
        catch {
            Write-LogFile -Message "[ERROR] Failed to retrieve operation '$operation': $($_.Exception.Message)" -Color "Red" -Level Minimal
        }
    }

    if ( $allResults.Count -gt 0) {
        Write-LogFile -Message "[INFO] Creating combined file with all operations..." -Level Standard
        
        switch ($Output) {
            "CSV" {
                $combinedCsvPath = Join-Path $OutputDir "UAL-Operations-Combined.csv"
                $combinedCsvResults = $allResults | ForEach-Object {
                    $flatRecord = $_ | Select-Object * -ExcludeProperty AuditData
                    
                    if ($_.AuditData) {
                        $flatRecord | Add-Member -NotePropertyName "AuditData_UserId" -NotePropertyValue $_.AuditData.UserId -Force
                        $flatRecord | Add-Member -NotePropertyName "AuditData_ClientIP" -NotePropertyValue $_.AuditData.ClientIP -Force
                        $flatRecord | Add-Member -NotePropertyName "AuditData_UserAgent" -NotePropertyValue $_.AuditData.UserAgent -Force
                        $flatRecord | Add-Member -NotePropertyName "AuditData_ObjectId" -NotePropertyValue $_.AuditData.ObjectId -Force
                        $flatRecord | Add-Member -NotePropertyName "AuditData_Raw" -NotePropertyValue ($_.AuditData | ConvertTo-Json -Compress -Depth 5) -Force
                    }
                    $flatRecord
                }
                $combinedCsvResults | Export-Csv $combinedCsvPath -NoTypeInformation -Encoding $Encoding
                Write-LogFile -Message "[INFO] Saved combined CSV file: $combinedCsvPath" -Level Standard -Color "Green"
            }
            "JSON" {
                $combinedJsonPath = Join-Path $OutputDir "UAL-Operations-Combined.json"
                $allResults | ConvertTo-Json -Depth 10 | Out-File $combinedJsonPath -Encoding $Encoding
                Write-LogFile -Message "[INFO] Saved combined JSON file: $combinedJsonPath" -Level Standard -Color "Green"
            }
            "SOF-ELK" {
                $combinedSofElkPath = Join-Path $OutputDir "UAL-Operations-Combined.json"
                foreach ($item in $allResults) {
                    $item | ConvertTo-Json -Compress -Depth 10 | Out-File $combinedSofElkPath -Append -Encoding UTF8
                }
                Write-LogFile -Message "[INFO] Saved combined SOF-ELK file: $combinedSofElkPath" -Level Standard -Color "Green"
            }
        }
    }
           
    Write-LogFile -Message "`n=== Quick UAL Collection Summary ===" -Color "Cyan" -Level Standard
    Write-LogFile -Message "Operations Searched: $($Operations.Count)" -Level Standard
    Write-LogFile -Message "Total Records Retrieved: $totalRecords" -Level Standard
    Write-LogFile -Message "Output Directory: $OutputDir" -Level Standard
    Write-LogFile -Message "Files Created: JSON and CSV for each operation + combined files" -Level Standard
    Write-LogFile -Message "=============================================" -Color "Cyan" -Level Standard
}

function Test-TaskWillSkip {
    param(
        [string]$TaskName,
        [array]$UserIds
    )
    
    # List of tasks that are skipped when UserIds are provided
    $tenantWideTasks = @(
        "Get-DirectoryActivityLogs",
        "Get-TransportRules", 
        "Get-ConditionalAccessPolicies",
        "Get-Licenses",
        "Get-LicenseCompatibility", 
        "Get-EntraSecurityDefaults",
        "Get-LicensesByUser",
        "Get-Groups",
        "Get-GroupMembers", 
        "Get-DynamicGroups",
        "Get-SecurityAlerts",
        "Get-PIMAssignments",
        "Get-AllRoleActivity"
    )
    
    return ($UserIds.Count -gt 0 -and $TaskName -in $tenantWideTasks)
}