Function Get-Groups {
<#
    .SYNOPSIS
    Retrieves all groups in the organization.

    .DESCRIPTION
    Retrieves all groups, including details such as group ID and display name.

    .PARAMETER OutputDir
    OutputDir is the parameter specifying the output directory.
    Default: Output\Groups

    .PARAMETER Encoding
    Encoding is the parameter specifying the encoding of the CSV output file.
    Default: UTF8

    .PARAMETER LogLevel
    Specifies the level of logging:
    None: No logging
    Minimal: Critical errors only
    Standard: Normal operational logging
    Default: Standard
    
    .EXAMPLE
    Get-Groups
    Retrieves all groups and exports the output to a CSV file.
    
    .EXAMPLE
    Get-Groups -Encoding utf32
    Retrieves all groups and exports the output to a CSV file with UTF-32 encoding.
        
    .EXAMPLE
    Get-Groups -OutputDir C:\Windows\Temp
    Retrieves all groups and saves the output to the C:\Windows\Temp folder.	
#>    

    [CmdletBinding()]
    param(
        [string]$OutputDir = "Output\Groups",
        [string]$Encoding = "UTF8",
        [ValidateSet('None', 'Minimal', 'Standard', 'Debug')]
        [string]$LogLevel = 'Standard'
    )

    Set-LogLevel -Level ([LogLevel]::$LogLevel)
    $requiredScopes = @("Group.Read.All", "AuditLog.Read.All")
    $graphAuth = Get-GraphAuthType -RequiredScopes $requiredScopes
    Write-LogFile -Message "=== Starting Groups Collection ===" -Color "Cyan" -Level Minimal

    if (!(Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Force -Path $OutputDir > $null
    } 
    else {
        if (!(Test-Path -Path $OutputDir)) {
            Write-LogFile -Message "[Error] Custom directory invalid: $OutputDir exiting script" -Level Minimal
        }
    }

    try {
        Write-LogFile -Message "[INFO] Fetching all groups..." -Level Standard
        $allGroups = Get-MgGroup -All
        Write-LogFile -Message "[INFO] Found $($allGroups.Count) groups" -Level Standard -Color "Green"

        $results = $allGroups | ForEach-Object {
            [PSCustomObject]@{
                GroupId = $_.Id
                DisplayName = $_.DisplayName
                Description = $_.Description
                Mail = $_.Mail
                MailEnabled = $_.MailEnabled
                MailNickname = $_.MailNickname
                SecurityEnabled = $_.SecurityEnabled
                GroupTypes = $_.GroupTypes -join ','
                CreatedDateTime = $_.CreatedDateTime
                RenewedDateTime = $_.RenewedDateTime
                ExpirationDateTime = $_.ExpirationDateTime
                Visibility = $_.Visibility
                OnPremisesSyncEnabled = $_.OnPremisesSyncEnabled
                OnPremisesLastSyncDateTime = $_.OnPremisesLastSyncDateTime
                SecurityIdentifier = $_.SecurityIdentifier
                IsManagementRestricted = $_.IsManagementRestricted
                MembershipRule = $_.MembershipRule
                MembershipRuleProcessingState = $_.MembershipRuleProcessingState
                Classification = $_.Classification
                HideFromAddressLists = $_.HideFromAddressLists
                HideFromOutlookClients = $_.HideFromOutlookClients
                IsAssignableToRole = $_.IsAssignableToRole
                PreferredDataLocation = $_.PreferredDataLocation
                ProxyAddresses = $_.ProxyAddresses -join ';'
            }
        }

        $date = Get-Date -Format "yyyyMMddHHmm"
        $filePath = Join-Path $OutputDir "$($date)-Groups.csv"
        $results | Export-Csv -Path $filePath -NoTypeInformation -Encoding $Encoding

        Write-LogFile -Message "`nGroup Analysis Results:" -Color "Cyan" -Level Standard
        Write-LogFile -Message "Total Groups: $($results.Count)" -Level Standard
        Write-LogFile -Message "  - Security Enabled: $(($results | Where-Object { $_.SecurityEnabled -eq $true }).Count)" -Level Standard
        Write-LogFile -Message "  - Mail Enabled: $(($results | Where-Object { $_.MailEnabled -eq $true }).Count)" -Level Standard
        Write-LogFile -Message "  - On-Premises Synced: $(($results | Where-Object { $_.OnPremisesSyncEnabled -eq $true }).Count)" -Level Standard

        Write-LogFile -Message "`nExported File:" -Color "Cyan" -Level Standard
        Write-LogFile -Message "  - File: $filePath" -Level Standard

    }
    catch {
        Write-LogFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Color "Red" -Level Minimal
        throw
    }
}

Function Get-GroupMembers {
<#
    .SYNOPSIS
    Retrieves all members of each group and their relevant details.

    .DESCRIPTION
    Enumerates all members of every group in the organization, including when they were added, their permissions, and roles.

    .PARAMETER OutputDir
    The output directory for saving group member details.
    Default: Output\Groups

    .PARAMETER Encoding
    The encoding for CSV files.
    Default: UTF8

    .PARAMETER LogLevel
    Specifies the level of logging:
    None: No logging
    Minimal: Critical errors only
    Standard: Normal operational logging
    Default: Standard

    .EXAMPLE
    Get-GroupMembers
    Retrieves all group members and their details.

    .EXAMPLE
    Get-GroupMembers -OutputDir C:\Temp -Encoding utf32
    Retrieves all group members and saves details to C:\Temp with UTF-32 encoding.
#>

    [CmdletBinding()]
    param(
        [string]$OutputDir = "Output\Groups",
        [string]$Encoding = "UTF8",
        [ValidateSet('None', 'Minimal', 'Standard', 'Debug')]
        [string]$LogLevel = 'Standard'
    )

    Set-LogLevel -Level ([LogLevel]::$LogLevel)
    $requiredScopes = @("Group.Read.All", "Directory.Read.All")
    $graphAuth = Get-GraphAuthType -RequiredScopes $RequiredScopes

    Write-LogFile -Message "=== Starting Group Members Collection ===" -Color "Cyan" -Level Minimal

    if (!(Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
    }

    try {
        Write-LogFile -Message "[INFO] Fetching all groups..." -Level Standard
        $allGroups = Get-MgGroup -All
        Write-LogFile -Message "[INFO] Found $($allGroups.Count) groups" -Level Standard -Color "Green"

        $results = @()
        foreach ($group in $allGroups) {
            Write-LogFile -Message "[INFO] Processing group: $($group.DisplayName)" -Level Standard

            try {
                $members = Get-MgGroupMember -GroupId $group.Id -All | ForEach-Object {
                    [PSCustomObject]@{
                        GroupName = $group.DisplayName
                        GroupId = $group.Id
                        MemberId = $_.Id
                        DisplayName = $_.AdditionalProperties.displayName
                        Email = $_.AdditionalProperties.mail
                        UserPrincipalName = $_.AdditionalProperties.userPrincipalName
                        GroupCreated = $_.CreatedDateTime
                    }
                }

                $results += $members
            }
            catch {
                Write-LogFile -Message "[ERROR] Failed to retrieve members for group: $($group.DisplayName) Error: $($_.Exception.Message)" -Color "Red" -Level Minimal
            }
        }
        $date = Get-Date -Format "yyyyMMddHHmm"
        $filePath = Join-Path $OutputDir "$($date)-GroupMembers.csv"
        $results | Export-Csv -Path $filePath -NoTypeInformation -Encoding $Encoding

        Write-LogFile -Message "`nExported File:" -Color "Cyan" -Level Standard
        Write-LogFile -Message "  - File: $filePath" -Level Standard
    }
    catch {
        Write-LogFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Color "Red" -Level Minimal
        throw
    }
}
Function Get-DynamicGroups {
<#
    .SYNOPSIS
    Retrieves all dynamic groups and their membership rules.

    .DESCRIPTION
    Retrieves dynamic groups and includes details about their membership rules, which determine automatic user inclusion.

    .PARAMETER OutputDir
    The output directory for saving dynamic group details.
    Default: Output\Groups

    .PARAMETER Encoding
    The encoding for CSV files.
    Default: UTF8

    .PARAMETER LogLevel
    Specifies the level of logging:
    None: No logging
    Minimal: Critical errors only
    Standard: Normal operational logging
    Default: Standard

    .EXAMPLE
    Get-DynamicGroups
    Retrieves dynamic groups and their membership rules, outputting the details to a CSV file.

    .EXAMPLE
    Get-DynamicGroups -OutputDir C:\Temp -Encoding utf32
    Retrieves dynamic groups and saves details to C:\Temp with UTF-32 encoding.
#>

    [CmdletBinding()]
    param(
        [string]$OutputDir = "Output\Groups",
        [string]$Encoding = "UTF8",
        [ValidateSet('None', 'Minimal', 'Standard', 'Debug')]
        [string]$LogLevel = 'Standard'
    )

    Set-LogLevel -Level ([LogLevel]::$LogLevel)
    $requiredScopes = @("Group.Read.All", "Directory.Read.All")
    $graphAuth = Get-GraphAuthType -RequiredScopes $RequiredScopes
        
    Write-LogFile -Message "=== Starting Dynamic Groups Collection ===" -Color "Cyan" -Level Minimal

    if (!(Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Force -Path $OutputDir > $null
    } 
    else {
        if (!(Test-Path -Path $OutputDir)) {
            Write-LogFile -Message "[Error] Custom directory invalid: $OutputDir exiting script" -Level Minimal
        }
    }  

    try {
        Write-LogFile -Message "[INFO] Fetching all groups from Microsoft Graph..." -Level Standard
        $allGroups = Get-MgGroup -All
        Write-LogFile -Message "[INFO] Found $($allGroups.Count) total groups" -Level Standard

        $dynamicGroups = $allGroups | Where-Object { $_.MembershipRule -ne $null }
        Write-LogFile -Message "[INFO] Found $($dynamicGroups.Count) dynamic groups" -Level Standard

        $results = $dynamicGroups | ForEach-Object {
            [PSCustomObject]@{
                GroupId = $_.Id
                DisplayName = $_.DisplayName
                Description = $_.Description
                Mail = $_.Mail
                MailEnabled = $_.MailEnabled
                MailNickname = $_.MailNickname
                SecurityEnabled = $_.SecurityEnabled
                GroupTypes = $_.GroupTypes -join ','
                CreatedDateTime = $_.CreatedDateTime
                RenewedDateTime = $_.RenewedDateTime
                MembershipRule = $_.MembershipRule
                MembershipRuleProcessingState = $_.MembershipRuleProcessingState
                OnPremisesSyncEnabled = $_.OnPremisesSyncEnabled
                SecurityIdentifier = $_.SecurityIdentifier
                Classification = $_.Classification
                Visibility = $_.Visibility
            }
        }

        $date = Get-Date -Format "yyyyMMddHHmm"
        $filePath = Join-Path $OutputDir "$($date)-DynamicGroups.csv"
        $results | Export-Csv -Path $filePath -NoTypeInformation -Encoding $Encoding

        Write-LogFile -Message "`nDynamic Group Analysis Results:" -Color "Cyan" -Level Standard
        Write-LogFile -Message "Total Dynamic Groups: $($results.Count)" -Level Standard
        Write-LogFile -Message "  - Security Enabled: $(($results | Where-Object { $_.SecurityEnabled -eq $true }).Count)" -Level Standard
        Write-LogFile -Message "  - Mail Enabled: $(($results | Where-Object { $_.MailEnabled -eq $true }).Count)" -Level Standard
        
        $processingStates = $results | Group-Object -Property MembershipRuleProcessingState
        Write-LogFile -Message "`nMembership Rule Processing States:" -Color "Cyan" -Level Standard
        foreach ($state in $processingStates) {
            Write-LogFile -Message "  - $($state.Name): $($state.Count)" -Level Standard
        }

        Write-LogFile -Message "`nExported File:" -Color "Cyan" -Level Standard
        Write-LogFile -Message "  - File: $filePath" -Level Standard
    }
    catch {
        Write-LogFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Color "Red" -Level Minimal
        throw
    }
}