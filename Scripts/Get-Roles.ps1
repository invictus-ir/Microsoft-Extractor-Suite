# Inspired by: https://ourcloudnetwork.com/export-all-admin-role-memberships-in-azure-ad-with-powershell/
Function Get-AllRoleActivity {
<#
    .SYNOPSIS
    Exports all directory role memberships with last login information.

    .DESCRIPTION
    Retrieves all directory roles, and exports a report of all role memberships with their last login activity.

    .PARAMETER OutputDir
    OutputDir is the parameter specifying the output directory.
    Default: Output\Roles

    .PARAMETER Encoding
    Encoding is the parameter specifying the encoding of the CSV output file.
    Default: UTF8

    .PARAMETER IncludeEmptyRoles
    When specified, includes roles with no members in the summary output.
    Default: False

    .PARAMETER LogLevel
    Specifies the level of logging:
    None: No logging
    Minimal: Critical errors only
    Standard: Normal operational logging
    Default: Standard
    
    .EXAMPLE
    Get-AllRoleActivity
    Exports all directory role memberships with last login information to the default output directory.
    
    .EXAMPLE
    Get-AllRoleActivity -OutputDir "C:\Reports"
    Exports directory role memberships to the specified directory.
        
    .EXAMPLE
    Get-AllRoleActivity -IncludeEmptyRoles
    Exports directory role memberships and also logs information about roles with no members.
    
    .EXAMPLE
    Get-AllRoleActivity -Encoding utf32
    Exports directory role memberships with UTF-32 encoding.
#>    

    [CmdletBinding()]
    param(
        [string]$OutputDir,
        [string]$Encoding = "UTF8",
        [switch]$IncludeEmptyRoles = $false,
        [ValidateSet('None', 'Minimal', 'Standard')]
        [string]$LogLevel = 'Standard'
    )

    Init-Logging
    if ($OutputDir) {
        Init-OutputDir -Component "Roles" -FilePostfix "AllRoles" -CustomOutputDir $OutputDir
    } else {
        Init-OutputDir -Component "Roles" -FilePostfix "AllRoles"
    }
    Write-LogFile -Message "=== Starting Directory Role Membership Export ===" -Color "Cyan" -Level Standard

    $requiredScopes = @("User.Read.All", "Directory.Read.All", "AuditLog.Read.All")
    $graphAuth = Get-GraphAuthType -RequiredScopes $RequiredScopes
    Write-LogFile -Message "[INFO] Retrieving directory roles and memberships..." -Level Standard
    
    $processedRoles = 0
    $rolesWithMembers = 0
    $rolesWithoutMembers = 0
    $totalMembers = 0
    $emptyRoles = @()
    $rolesWithUsers = @()
    $allRoleMembers = @()

    try {
        $allRoles = Get-MgDirectoryRole -All
        Write-LogFile -Message "[INFO] Found $($allRoles.Count) directory roles" -Level Standard
        
        foreach ($role in $allRoles) {
            $processedRoles++
            $displayName = $role.DisplayName
            $roleMembers = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id
            
            if ($null -eq $roleMembers -or $roleMembers.Count -eq 0) {
                $rolesWithoutMembers++
                $emptyRoles += $displayName
                continue
            }
            
            $rolesWithMembers++
            $roleMemberCount = 0
            
            foreach ($member in $roleMembers) {
                #Skip service principals
                if ($member.AdditionalProperties.'@odata.type' -match "servicePrincipal") {
                    Write-LogFile -Message "[INFO] Skipping service principal in role $displayName" -Level Standard
                    continue
                }
                
                $totalMembers++
                $userId = $member.Id
                $roleMemberCount++
                
                try {
                    $selectProperties = @(
                        "UserPrincipalName", "DisplayName", "Id", "Department", "JobTitle", 
                        "AccountEnabled", "CreatedDateTime", "SignInActivity"
                    )
                    
                    try {
                        $user = Get-MgUser -UserId $userId -Select $selectProperties -ErrorAction Stop
                    } catch {
                        if ($_.Exception.Response.StatusCode -eq 429) {
                            Start-Sleep -Seconds 5
                            $user = Get-MgUser -UserId $userId -Select $selectProperties -ErrorAction Stop
                        } else {
                            throw
                        }
                    }
                    
                    $userObject = [PSCustomObject]@{
                        Role = $displayName
                        UserName = $user.UserPrincipalName
                        UserId = $userId
                        DisplayName = $user.DisplayName
                        Department = $user.Department
                        JobTitle = $user.JobTitle
                        AccountEnabled = $user.AccountEnabled
                        CreatedDateTime = $user.CreatedDateTime
                        LastInteractiveSignIn = $user.SignInActivity.LastSignInDateTime
                        LastNonInteractiveSignIn = $user.SignInActivity.LastNonInteractiveSignInDateTime
                    }
                    
                    if ($user.SignInActivity.LastSignInDateTime) {
                        $daysSinceSignIn = (New-TimeSpan -Start $user.SignInActivity.LastSignInDateTime -End (Get-Date)).Days
                        $userObject | Add-Member -MemberType NoteProperty -Name "DaysSinceLastSignIn" -Value $daysSinceSignIn
                    } else {
                        $userObject | Add-Member -MemberType NoteProperty -Name "DaysSinceLastSignIn" -Value "No sign-in data"
                    }
                    
                    $allRoleMembers += $userObject
                }
                catch {
                    Write-LogFile -Message "[WARNING] Error processing user $userId in role $displayName`: $($_.Exception.Message)" -Color "Yellow" -Level Standard
                    
                    try {
                        $basicInfo = Get-MgUser -UserId $userId -Select "DisplayName,UserPrincipalName" -ErrorAction SilentlyContinue
                        $userName = $basicInfo.UserPrincipalName
                        $displayName = $basicInfo.DisplayName
                    }
                    catch {
                        $userName = "Unknown"
                        $displayName = "Unknown"
                    }
                    
                    $userObject = [PSCustomObject]@{
                        Role = $displayName
                        UserName = $userName
                        UserId = $userId
                        DisplayName = $displayName
                        Department = "Error retrieving data"
                        JobTitle = "Error retrieving data"
                        AccountEnabled = "Error retrieving data"
                        CreatedDateTime = "Error retrieving data"
                        LastInteractiveSignIn = "Error retrieving data"
                        LastNonInteractiveSignIn = "Error retrieving data"
                        DaysSinceLastSignIn = "Error retrieving data"
                    }
                    $allRoleMembers += $userObject
                }
            }
            
            $rolesWithUsers += "$displayName ($roleMemberCount users)"
        }

        $outputFile = "$OutputDir\$($date)-All-Roles.csv"
        $allRoleMembers | Export-Csv -Path $script:outputFile -NoTypeInformation -Encoding $Encoding

        Write-LogFile -Message "`nRoles with users:" -Color "Green" -Level Standard
        foreach ($role in $rolesWithUsers) {
            Write-LogFile -Message "  + $role" -Level Standard
        }
        
        Write-LogFile -Message "`nEmpty roles:" -Color "Yellow" -Level Standard
        foreach ($emptyRole in $emptyRoles) {
            Write-LogFile -Message "  - $emptyRole" -Level Standard
        }
        
        Write-LogFile -Message "`nSummary:" -Level Standard -Color "Cyan"
        Write-LogFile -Message "  - Total roles processed: $processedRoles" -Level Standard
        Write-LogFile -Message "  - Roles with members: $rolesWithMembers" -Level Standard
        Write-LogFile -Message "  - Roles without members: $rolesWithoutMembers" -Level Standard
        Write-LogFile -Message "  - Total role user assignments: $totalMembers" -Level Standard
        
        Write-LogFile -Message "`nExported file:" -Level Standard -Color "Cyan"
        Write-LogFile -Message "  - File: $script:outputFile" -Level Standard
    }
    catch {
        Write-LogFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Color "Red" -Level Minimal
        throw
    }
}

function Get-PIMAssignments {
#Inspired by: https://github.com/nathanmcnulty/nathanmcnulty/blob/master/Entra/FindSyncedPrivilegedUsers-NoPIM.ps1 & https://github.com/nathanmcnulty/nathanmcnulty/blob/master/Entra/FindSyncedPrivilegedUsers-PIM.ps1    
<#
    .SYNOPSIS
    Generates an overview of all Entra ID PIM role assignments.

    .DESCRIPTION
    Retrieves all Privileged Identity Management (PIM) role assignments in Entra ID. It includes both active and eligible assignments and expands group memberships to show individual users.

    .PARAMETER OutputDir
    OutputDir is the parameter specifying the output directory.
    Default: Output\Roles

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
    Get-PIMAssignments
    Exports all PIM role assignments to the default output directory.
    
    .EXAMPLE
    Get-PIMAssignments -OutputDir "C:\Reports"
    Exports PIM role assignments to the specified directory.
    
    .EXAMPLE
    Get-PIMAssignments -LogLevel Minimal
    Exports PIM role assignments with minimal logging.
#>

    [CmdletBinding()]
    param(
        [string]$OutputDir,
        [string]$Encoding = "UTF8",
        [ValidateSet('None', 'Minimal', 'Standard')]
        [string]$LogLevel = 'Standard'
    )

    Init-Logging
    if ($OutputDir) {
        Init-OutputDir -Component "Roles" -FilePostfix "PIM-Assignments" -CustomOutputDir $OutputDir
    } else {
        Init-OutputDir -Component "Roles" -FilePostfix "PIM-Assignments"
    }
    Write-LogFile -Message "=== Starting PIM Role Assignment Export ===" -Color "Cyan" -Level Standard

    $requiredScopes = @("RoleAssignmentSchedule.Read.Directory", "RoleEligibilitySchedule.Read.Directory", "User.Read.All", "Group.Read.All")
    $graphAuth = Get-GraphAuthType -RequiredScopes $RequiredScopes
    
    Write-LogFile -Message "[INFO] Retrieving PIM role assignments..." -Level Standard
    $allAssignments = @()
    $processedActiveAssignments = 0
    $processedEligibleAssignments = 0
    $skippedAssignments = 0
    
    try {
        Write-LogFile -Message "[INFO] Retrieving active PIM assignments..." -Color "Green" -Level Standard
        $activeAssignmentsUri = "https://graph.microsoft.com/beta/roleManagement/directory/roleAssignmentSchedules?`$expand=principal,roleDefinition"
        $activeResponse = Invoke-MgGraphRequest -Method GET -Uri $activeAssignmentsUri
        $activePimAssignments = $activeResponse.value

        $nextLink = $activeResponse.'@odata.nextLink'
        while ($null -ne $nextLink) {
            $activeResponse = Invoke-MgGraphRequest -Method GET -Uri $nextLink
            $activePimAssignments += $activeResponse.value
            $nextLink = $activeResponse.'@odata.nextLink'
        }
        
        $activeAssignmentsCount = $activePimAssignments.Count
        Write-LogFile -Message "[INFO] Found $($activeAssignmentsCount) active PIM assignments" -Level Standard
        
        foreach ($assignment in $activePimAssignments) {
            $added = $false
            if ($assignment.principal.'@odata.type' -match '.user') {
                $user = $assignment.Principal
                $isOnPremSynced = $user.onPremisesSyncEnabled -eq $true
                                
                $allAssignments += [PSCustomObject]@{
                    RoleName = $assignment.roleDefinition.displayName
                    UserPrincipalName = $user.userPrincipalName
                    DisplayName = $user.displayName
                    AssignmentType = "PIM Active"
                    SourceType = "Direct"
                    SourceName = "N/A"
                    OnPremisesSynced = $isOnPremSynced
                    AssignmentStatus = "Active"
                    StartDateTime = $assignment.scheduleInfo.startDateTime
                    EndDateTime = if ($assignment.scheduleInfo.expiration) { $assignment.scheduleInfo.expiration.endDateTime } else { "Permanent" }
                    DirectoryScopeId = $assignment.directoryScopeId
                }
                $processedActiveAssignments++
                $added = $true
            }

            elseif ($assignment.principal.'@odata.type' -match '.group') {
                $roleName = $assignment.roleDefinition.displayName
                $groupId = $assignment.principalId
                $groupName = $assignment.principal.displayName
                
                Write-LogFile -Message "[INFO] Processing group $groupName with role $roleName" -Level Standard
                
                try {
                    $groupMembersUri = "https://graph.microsoft.com/v1.0/groups/$groupId/members"
                    $groupResponse = Invoke-MgGraphRequest -Method GET -Uri $groupMembersUri
                    $groupMembers = $groupResponse.value
                    
                    $nextLink = $groupResponse.'@odata.nextLink'
                    while ($null -ne $nextLink) {
                        $groupResponse = Invoke-MgGraphRequest -Method GET -Uri $nextLink
                        $groupMembers += $groupResponse.value
                        $nextLink = $groupResponse.'@odata.nextLink'
                    }

                    $groupMemberCount = 0
                    foreach ($member in $groupMembers) {
                        if ($member.'@odata.type' -notmatch '.user') {
                            continue
                        }
                        
                        try {
                            $userId = $member.id
                            $userUri = "https://graph.microsoft.com/v1.0/users/$userId"
                            $userDetails = Invoke-MgGraphRequest -Method GET -Uri $userUri
                            $isOnPremSynced = $userDetails.onPremisesSyncEnabled -eq $true
                            
                            $allAssignments += [PSCustomObject]@{
                                RoleName = $roleName
                                UserPrincipalName = $userDetails.userPrincipalName
                                DisplayName = $userDetails.displayName
                                AssignmentType = "PIM Active"
                                SourceType = "Group"
                                SourceName = $groupName
                                OnPremisesSynced = $isOnPremSynced
                                AssignmentStatus = "Active"
                                StartDateTime = $assignment.scheduleInfo.startDateTime
                                EndDateTime = if ($assignment.scheduleInfo.expiration) { $assignment.scheduleInfo.expiration.endDateTime } else { "Permanent" }
                                DirectoryScopeId = $assignment.directoryScopeId
                            }
                            $processedActiveAssignments++
                            $groupMemberCount++
                            $added = $true
                        }
                        catch {
                            Write-LogFile -Message "[WARNING] Could not process user $userId in group $groupName`: $_" -Color "Yellow" -Level Standard
                            $skippedAssignments++
                        }
                    }
                    if ($groupMemberCount -eq 0) {
                        $skippedAssignments++
                    }
                }
                catch {
                    Write-LogFile -Message "[WARNING] Error processing group members for $groupName`: $_" -Color "Yellow" -Level Standard
                    $skippedAssignments++
                }
            }
            if (-not $added) {
                $skippedAssignments++
            }
        }
        
        Write-LogFile -Message "[INFO] Retrieving eligible PIM assignments..." -Color "Green" -Level Standard
        $eligibleAssignmentsUri = "https://graph.microsoft.com/beta/roleManagement/directory/roleEligibilitySchedules?`$expand=principal,roleDefinition"
        $eligibleResponse = Invoke-MgGraphRequest -Method GET -Uri $eligibleAssignmentsUri
        $eligiblePimAssignments = $eligibleResponse.value
        
        $nextLink = $eligibleResponse.'@odata.nextLink'
        while ($null -ne $nextLink) {
            $eligibleResponse = Invoke-MgGraphRequest -Method GET -Uri $nextLink
            $eligiblePimAssignments += $eligibleResponse.value
            $nextLink = $eligibleResponse.'@odata.nextLink'
        }
        
        $eligibleAssignmentsCount = $eligiblePimAssignments.Count
        Write-LogFile -Message "[INFO] Found $($eligiblePimAssignments.Count) eligible PIM assignments" -Level Standard

        foreach ($assignment in $eligiblePimAssignments) {
            $added = $false
            if ($assignment.principal.'@odata.type' -match '.user') {
                $user = $assignment.principal
                $isOnPremSynced = $user.onPremisesSyncEnabled -eq $true
                
                $allAssignments += [PSCustomObject]@{
                    RoleName = $assignment.roleDefinition.displayName
                    UserPrincipalName = $user.userPrincipalName
                    DisplayName = $user.displayName
                    AssignmentType = "PIM Eligible"
                    SourceType = "Direct"
                    SourceName = "N/A"
                    OnPremisesSynced = $isOnPremSynced
                    AssignmentStatus = "Eligible"
                    StartDateTime = $assignment.scheduleInfo.startDateTime
                    EndDateTime = if ($assignment.scheduleInfo.expiration) { $assignment.scheduleInfo.expiration.endDateTime } else { "Permanent" }
                    DirectoryScopeId = $assignment.directoryScopeId
                }
                $processedEligibleAssignments++
                $added = $true
            }

            elseif ($assignment.principal.'@odata.type' -match '.group') {
                $roleName = $assignment.roleDefinition.displayName
                $groupId = $assignment.principalId
                $groupName = $assignment.principal.displayName
                
                Write-LogFile -Message "[INFO] Processing group $groupName with role $roleName" -Level Standard
                
                try {
                    $groupMembersUri = "https://graph.microsoft.com/v1.0/groups/$groupId/members"
                    $groupResponse = Invoke-MgGraphRequest -Method GET -Uri $groupMembersUri
                    $groupMembers = $groupResponse.value
                    
                    $nextLink = $groupResponse.'@odata.nextLink'
                    while ($null -ne $nextLink) {
                        $groupResponse = Invoke-MgGraphRequest -Method GET -Uri $nextLink
                        $groupMembers += $groupResponse.value
                        $nextLink = $groupResponse.'@odata.nextLink'
                    }
                    
                    $groupMemberCount = 0
                    foreach ($member in $groupMembers) {
                        if ($member.'@odata.type' -notmatch '.user') {
                            continue
                        }
                        
                        try {
                            $userId = $member.id
                            $userUri = "https://graph.microsoft.com/v1.0/users/$userId"
                            $userDetails = Invoke-MgGraphRequest -Method GET -Uri $userUri
                            $isOnPremSynced = $userDetails.onPremisesSyncEnabled -eq $true
                            
                            $allAssignments += [PSCustomObject]@{
                                RoleName = $roleName
                                UserPrincipalName = $userDetails.userPrincipalName
                                DisplayName = $userDetails.displayName
                                AssignmentType = "PIM Eligible"
                                SourceType = "Group"
                                SourceName = $groupName
                                OnPremisesSynced = $isOnPremSynced
                                AssignmentStatus = "Eligible"
                                StartDateTime = $assignment.scheduleInfo.startDateTime
                                EndDateTime = if ($assignment.scheduleInfo.expiration) { $assignment.scheduleInfo.expiration.endDateTime } else { "Permanent" }
                                DirectoryScopeId = $assignment.directoryScopeId
                            }
                            $processedEligibleAssignments++
                            $groupMemberCount++
                            $added = $true
                        }
                        catch {
                            Write-LogFile -Message "[WARNING] Could not process user $userId in group $groupName`: $_" -Color "Yellow" -Level Standard
                            $skippedAssignments++

                        }
                    }
                    if ($groupMemberCount -eq 0) {
                        $skippedAssignments++
                    }
                }
                catch {
                    Write-LogFile -Message "[WARNING] Error processing group members for $groupName`: $_" -Color "Yellow" -Level Standard
                    $skippedAssignments++
                }
            }
            if (-not $added) {
                $skippedAssignments++
            }
        }
        
        $allAssignments | Export-Csv -Path $script:outputFile -NoTypeInformation -Encoding $Encoding
        
        $totalAssignments = $allAssignments.Count
        $pimActiveCount = ($allAssignments | Where-Object { $_.AssignmentStatus -eq "Active" }).Count
        $pimEligibleCount = ($allAssignments | Where-Object { $_.AssignmentStatus -eq "Eligible" }).Count
        $directCount = ($allAssignments | Where-Object { $_.SourceType -eq "Direct" }).Count
        $groupCount = ($allAssignments | Where-Object { $_.SourceType -eq "Group" }).Count
        $onPremSyncedCount = ($allAssignments | Where-Object { $_.OnPremisesSynced -eq $true }).Count
        $cloudOnlyCount = ($allAssignments | Where-Object { $_.OnPremisesSynced -eq $false }).Count
        
        Write-LogFile -Message "`nSummary:" -Level Standard -Color "Cyan"
        Write-LogFile -Message " - Total role assignments: $totalAssignments" -Level Standard
        Write-LogFile -Message " - PIM Active assignments: $pimActiveCount" -Level Standard
        Write-LogFile -Message " - PIM Eligible assignments: $pimEligibleCount" -Level Standard
        Write-LogFile -Message " - Direct assignments: $directCount" -Level Standard
        Write-LogFile -Message " - Group-inherited assignments: $groupCount" -Level Standard
        Write-LogFile -Message " - On-premises synced users: $onPremSyncedCount" -Level Standard
        Write-LogFile -Message " - Cloud-only users: $cloudOnlyCount" -Level Standard

        # Only show this if there's a discrepancy between found and processed
        if (($activeAssignmentsCount + $eligibleAssignmentsCount) -ne $totalAssignments) {
            Write-LogFile -Message "`nNote: $($activeAssignmentsCount + $eligibleAssignmentsCount) total assignments were found, but only $totalAssignments were processed." -Level Standard -Color "Yellow"
            Write-LogFile -Message " - This is usually due to service principals or empty groups that were skipped during processing." -Level Standard
        }
        
        Write-LogFile -Message "`nExported file:" -Level Standard -Color "Cyan"
        Write-LogFile -Message " - File: $script:outputFile" -Level Standard
    }
    catch {
        Write-LogFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Color "Red" -Level Minimal
        throw
    }
}