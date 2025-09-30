function Get-Users {
<#
    .SYNOPSIS
    Retrieves the creation time and date of the last password change for all users.
    Script inspired by: https://github.com/tomwechsler/Microsoft_Graph/blob/main/Entra_ID/Create_time_last_password.ps1

    .DESCRIPTION
    Retrieves the creation time and date of the last password change for all users.

    .PARAMETER OutputDir
    OutputDir is the parameter specifying the output directory.
    Default: Output\Users

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
    UserId is the parameter specifying a single user ID or UPN to filter the results.
    Default: All users will be included if not specified.
    
    .EXAMPLE
    Get-Users
    Retrieves the creation time and date of the last password change for all users.

    .EXAMPLE
    Get-Users -Encoding utf32
    Retrieves the creation time and date of the last password change for all users and exports the output to a CSV file with UTF-32 encoding.
        
    .EXAMPLE
    Get-Users -OutputDir C:\Windows\Temp
    Retrieves the creation time and date of the last password change for all users and saves the output to the C:\Windows\Temp folder.	
#>
    [CmdletBinding()]
    param(
        [string]$OutputDir,
        [string]$Encoding = "UTF8",
        [string]$UserIds,
        [ValidateSet('None', 'Minimal', 'Standard', 'Debug')]
        [string]$LogLevel = 'Standard'
    )

    Init-Logging
    if ($OutputDir) {
        Init-OutputDir -Component "Users" -FilePostfix "Users" -CustomOutputDir $OutputDir
    } else {
        Init-OutputDir -Component "Users" -FilePostfix "Users"
    }
    
    $requiredScopes = @("User.Read.All")
    $graphAuth = Get-GraphAuthType -RequiredScopes $RequiredScopes
    Write-LogFile -Message "=== Starting Users Collection ===" -Color "Cyan" -Level Standard

    try {
        $selectobjects = "UserPrincipalName","DisplayName","Id","CompanyName","Department","JobTitle","City","Country","Identities","UserType","LastPasswordChangeDateTime","AccountEnabled","CreatedDateTime","CreationType","ExternalUserState","ExternalUserStateChangeDateTime","SignInActivity","OnPremisesSyncEnabled"
        $mgUsers = @()

        if ($UserIds) {
            Write-LogFile -Message "[INFO] Filtering results for user: $UserIds" -Level Standard
            
            try {
                $mgUsers = Get-Mguser -Filter "userPrincipalName eq '$UserIds'" -select $selectobjects
                                
                if (-not $mgUsers) {
                    Write-LogFile -Message "[WARNING] User not found: $UserIds" -Color "Yellow" -Level Standard
                    $mgUsers = @()
                }
            } catch {
                Write-LogFile -Message "[WARNING] Error retrieving user $UserIds`: $($_.Exception.Message)" -Color "Yellow" -Level Standard
                $mgUsers = @()
            }
        } else {
            $mgUsers = Get-MgUser -All -Select $selectobjects
        }

        $formattedUsers = $mgUsers | ForEach-Object {
            [PSCustomObject]@{
                UserPrincipalName = $_.UserPrincipalName
                DisplayName = $_.DisplayName
                Id = $_.Id
                Department = $_.Department
                JobTitle = $_.JobTitle
                AccountEnabled = $_.AccountEnabled
                CreatedDateTime = $_.CreatedDateTime
                LastPasswordChangeDateTime = $_.LastPasswordChangeDateTime
                UserType = $_.UserType
                OnPremisesSyncEnabled = $_.OnPremisesSyncEnabled
                Mail = $_.Mail
                LastSignInDateTime = $_.SignInActivity.LastSignInDateTime
                LastNonInteractiveSignInDateTime = $_.SignInActivity.LastNonInteractiveSignInDateTime
                IdentityProvider = ($_.Identities | Where-Object { $_.SignInType -eq "federated" }).Issuer
                City = $_.City
                Country = $_.Country
                UsageLocation = $_.UsageLocation
            }
        }

        if ($isDebugEnabled) {
            Write-LogFile -Message "[DEBUG] User formatting completed:" -Level Debug
            Write-LogFile -Message "[DEBUG]   Original users: $($mgUsers.Count)" -Level Debug
            Write-LogFile -Message "[DEBUG]   Formatted users: $($formattedUsers.Count)" -Level Debug
            Write-LogFile -Message "[DEBUG] Starting user analysis by creation date..." -Level Debug
        }

        $date = (Get-Date).AddDays(-7)
        $oneweekold = $mgUsers | Where-Object {
            $_.CreatedDateTime -gt $date
        }

        $date = (Get-Date).AddDays(-30)
        $onemonthold = $mgUsers | Where-Object {
            $_.CreatedDateTime -gt $date
        }

        $date = (Get-Date).AddDays(-90)
        $threemonthold = $mgUsers | Where-Object {
            $_.CreatedDateTime -gt $date
        }

        $date = (Get-Date).AddDays(-180)
        $sixmonthold = $mgUsers | Where-Object {
            $_.CreatedDateTime -gt $date
        }

        $date = (Get-Date).AddDays(-360)
        $OneYear = $mgUsers | Where-Object {
            $_.CreatedDateTime -gt $date
        }

        Get-MgUser | Get-Member > $null
        $formattedUsers  | Export-Csv -Path $script:outputFile -NoTypeInformation -Encoding $Encoding

        $userSummary = [PSCustomObject]@{
            TotalUsers = $mgUsers.Count
            EnabledUsers = ($mgUsers | Where-Object { $_.AccountEnabled }).Count
            DisabledUsers = ($mgUsers | Where-Object { -not $_.AccountEnabled }).Count
            SyncedUsers = ($mgUsers | Where-Object { $_.OnPremisesSyncEnabled }).Count
            GuestUsers = ($mgUsers | Where-Object { $_.UserType -eq "Guest" }).Count
            LastSevenDays = $oneweekold.Count
            LastThirtyDays = $onemonthold.Count
            LastNinetyDays = $threemonthold.Count
            Onehundredeighty = $sixmonthold.Count
            OneYear = $OneYear.Count
        }

        Write-LogFile -Message "User Analysis Results:" -Color "Cyan" -Level Standard
        Write-LogFile -Message "Total Users: $($userSummary.TotalUsers)" -Level Standard
        Write-LogFile -Message "  - Enabled: $($userSummary.EnabledUsers)" -Level Standard
        Write-LogFile -Message "  - Disabled: $($userSummary.DisabledUsers)" -Level Standard
        Write-LogFile -Message "  - Synced from On-Premises: $($userSummary.SyncedUsers)" -Level Standard
        Write-LogFile -Message "  - Guest Users: $($userSummary.GuestUsers)" -Level Standard

        Write-LogFile -Message "`nRecent Account Creation:" -Color "Cyan" -Level Standard
        Write-LogFile -Message "  - Last 7 days: $($userSummary.LastSevenDays)" -Level Standard
        Write-LogFile -Message "  - Last 30 days: $($userSummary.LastThirtyDays)" -Level Standard
        Write-LogFile -Message "  - Last 90 days: $($userSummary.LastNinetyDays)" -Level Standard
        Write-LogFile -Message "  - Last 6 months: $($userSummary.Onehundredeighty)" -Level Standard
        Write-LogFile -Message "  - Last 1 year $($userSummary.OneYear)" -Level Standard

        Write-LogFile -Message "`nExported File:" -Color "Cyan" -Level Standard
        Write-LogFile -Message "  - File: $script:outputFile" -Level Standard
    }
    catch {
        Write-logFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Color "Red" -Level Minimal
        if ($isDebugEnabled) {
            Write-LogFile -Message "[DEBUG] Error details:" -Level Debug
            Write-LogFile -Message "[DEBUG]   Exception type: $($_.Exception.GetType().Name)" -Level Debug
            Write-LogFile -Message "[DEBUG]   Error message: $($_.Exception.Message)" -Level Debug
            Write-LogFile -Message "[DEBUG]   Stack trace: $($_.ScriptStackTrace)" -Level Debug
        }
        throw
    }   
}

Function Get-AdminUsers {
<#
    .SYNOPSIS
    Retrieves all Administrator directory roles.

    .DESCRIPTION
    Retrieves Administrator directory roles, including the identification of users associated with each specific role.

    .PARAMETER OutputDir
    OutputDir is the parameter specifying the output directory.
    Default: Output\Admins

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
    
    .EXAMPLE
    Get-AdminUsers
    Retrieves Administrator directory roles, including the identification of users associated with each specific role.
    
    .EXAMPLE
    Get-AdminUsers -Encoding utf32
    Retrieves Administrator directory roles, including the identification of users associated with each specific role and exports the output to a CSV file with UTF-32 encoding.
        
    .EXAMPLE
    Get-AdminUsers -OutputDir C:\Windows\Temp
    Retrieves Administrator directory roles, including the identification of users associated with each specific role and saves the output to the C:\Windows\Temp folder.	
#>    

    [CmdletBinding()]
    param(
        [string]$OutputDir,
        [string]$Encoding = "UTF8",
        [ValidateSet('None', 'Minimal', 'Standard', 'Debug')]
        [string]$LogLevel = 'Standard'
    )

    Init-Logging
    if ($OutputDir) {
        Init-OutputDir -Component "Admins" -FilePostfix "AdminUsers" -CustomOutputDir $OutputDir
    } else {
        Init-OutputDir -Component "Admins" -FilePostfix "AdminUsers"
    }

    Write-LogFile -Message "=== Starting Admin Users Collection ===" -Color "Cyan" -Level Standard

    $requiredScopes = @("User.Read.All", "Directory.Read.All")
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

    Write-LogFile -Message "[INFO] Analyzing administrator roles..." -Level Standard
    $rolesWithUsers = @()
    $rolesWithoutUsers = @()
    $exportedFiles = @()
    $totalAdminCount = 0
    $inactiveAdminCount = 0

    # Track users with no recent sign-in
    $inactiveThreshold = (Get-Date).AddDays(-30)
    $inactiveAdmins = @()

    try {
        if ($isDebugEnabled) {
            Write-LogFile -Message "[DEBUG] Retrieving all directory roles..." -Level Debug
            $performance = Measure-Command {
                $getRoles = Get-MgDirectoryRole -all
            }
            Write-LogFile -Message "[DEBUG] Directory roles retrieval took $([math]::round($performance.TotalSeconds, 2)) seconds" -Level Debug
            Write-LogFile -Message "[DEBUG] Found $($getRoles.Count) total directory roles" -Level Debug
        } else {
            $getRoles = Get-MgDirectoryRole -all
        }
        
        foreach ($role in $getRoles) {
            $roleId = $role.Id
            $roleName = $role.DisplayName
        
            if ($roleName -like "*Admin*") {
                if ($isDebugEnabled) {
                    Write-LogFile -Message "[DEBUG] Processing admin role: $roleName" -Level Debug
                    Write-LogFile -Message "[DEBUG]   Role ID: $roleId" -Level Debug
                }
                
                if ($isDebugEnabled) {
                    $memberPerformance = Measure-Command {
                        $areThereUsers = Get-MgDirectoryRoleMember -DirectoryRoleId $roleId
                    }
                    Write-LogFile -Message "[DEBUG]   Role member query took $([math]::round($memberPerformance.TotalSeconds, 2)) seconds" -Level Debug
                } else {
                    $areThereUsers = Get-MgDirectoryRoleMember -DirectoryRoleId $roleId
                }

                if ($null -eq $areThereUsers) {
                    $rolesWithoutUsers += $roleName
                    continue
                }

                $results = @()
                $count = 0
                foreach ($user in $areThereUsers) {
                    $userid = $user.Id
                    if ($userid -eq ".") {
                        if ($isDebugEnabled) {
                            Write-LogFile -Message "[DEBUG]     Skipping invalid user ID: $userid" -Level Debug
                        }
                        continue
                    }

                    $count++
                    if ($isDebugEnabled) {
                        Write-LogFile -Message "[DEBUG]     Processing user $count/$($areThereUsers.Count): $userid" -Level Debug
                    }
                    try {
                        $selectProperties = @(
                        "UserPrincipalName", "DisplayName", "Id", "Department", "JobTitle", 
                        "AccountEnabled", "CreatedDateTime","SignInActivity"
                        )


                        try {
                            $getUserName = Get-MgUser -UserId $userid -Select $selectProperties -ErrorAction Stop
                        } catch {
                            if ($_.Exception.Response.StatusCode -eq 429) {
                                Start-Sleep -Seconds 5
                                $getUserName = Get-MgUser -UserId $userid -Select $selectProperties -ErrorAction Stop
                            } else {
                                throw
                            }
                        }
                    
                        $userName = $getUserName.UserPrincipalName
                        $userObject = [PSCustomObject]@{
                            UserName = $userName
                            UserId = $userid
                            Role = $roleName
                            DisplayName = $getUserName.DisplayName
                            Department = $getUserName.Department
                            JobTitle = $getUserName.JobTitle
                            AccountEnabled = $getUserName.AccountEnabled
                            CreatedDateTime = $getUserName.CreatedDateTime
                            LastInteractiveSignIn = $getUserName.SignInActivity.LastSignInDateTime
                            LastNonInteractiveSignIn = $getUserName.SignInActivity.LastNonInteractiveSignInDateTime
                        }

                        if ($getUserName.SignInActivity.LastSignInDateTime) {
                            $daysSinceSignIn = (New-TimeSpan -Start $getUserName.SignInActivity.LastSignInDateTime -End (Get-Date)).Days
                            $userObject | Add-Member -MemberType NoteProperty -Name "DaysSinceLastSignIn" -Value $daysSinceSignIn
                            
                            if ($getUserName.SignInActivity.LastSignInDateTime -lt $inactiveThreshold) {
                                $inactiveAdminCount++
                                $inactiveAdmins += "$($getUserName.DisplayName) ($userName) - $daysSinceSignIn days"
                            }
                        } else {
                            $userObject | Add-Member -MemberType NoteProperty -Name "DaysSinceLastSignIn" -Value "No sign-in data"
                            $inactiveAdminCount++
                            $inactiveAdmins += "$($getUserName.DisplayName) ($userName) - No sign-in data"                 
                        }
                        $results += $userObject
                    }
                    catch {
                        Write-LogFile -Message "[WARNING] Error processing user $userid in role $roleName`: $($_.Exception.Message)" -Color "Yellow" -Level Standard
                    }
                }

                if ($results.Count -gt 0) {
                    $totalAdminCount += $results.Count
                    $rolesWithUsers += "$roleName ($($results.Count) users)"
                    
                    $date = [datetime]::Now.ToString('yyyyMMdd')
                    $safeRoleName = $roleName -replace '[^\w\-_\.]', '_'
                    $rolePath = Split-Path $script:outputFile -Parent
                    $roleFilePath = Join-Path $rolePath "$date-$safeRoleName.csv"

                    $results | Export-Csv -Path $roleFilePath -NoTypeInformation -Encoding $Encoding
                    $exportedFiles += $roleFilePath
                }
                else {
                    $rolesWithoutUsers += $roleName
                }
            }
        }

        # Create merged file
        $outputDirPath = Split-Path $script:outputFile -Parent
        $outputDirMerged = Join-Path $outputDirPath "Merged"
        if (!(Test-Path $outputDirMerged)) {
            New-Item -ItemType Directory -Force -Path $outputDirMerged > $null
        }

        $date = [datetime]::Now.ToString('yyyyMMdd')
        $mergedFile = Join-Path $outputDirMerged "$date-All-Administrators.csv"

        # Get all individual admin role files and merge them
        $adminFiles = Get-ChildItem $outputDirPath -Filter "*Admin*.csv" -ErrorAction SilentlyContinue
        if ($adminFiles.Count -gt 0) {
            $adminFiles | 
                ForEach-Object { Import-Csv $_.FullName } | 
                Export-Csv $mergedFile -NoTypeInformation -Encoding $Encoding
        }

        Write-LogFile -Message "`nRoles with users:" -Color "Green" -Level Standard
        foreach ($role in $rolesWithUsers) {
            Write-LogFile -Message "  + $role" -Level Standard
        }

        Write-LogFile -Message "`nEmpty roles:" -Color "Yellow" -Level Standard
        foreach ($role in $rolesWithoutUsers) {
            Write-LogFile -Message "  - $role" -Level Standard
        }

        if ($inactiveAdmins.Count -gt 0) {
            Write-LogFile -Message "`nInactive administrators (30+ days):" -Color "Yellow" -Level Standard
            foreach ($admin in $inactiveAdmins) {
                Write-LogFile -Message "  ! $admin" -Level Standard
            }
        }

        Write-LogFile -Message "`nSummary:" -Level Standard -Color "Cyan"
        Write-LogFile -Message "  Total admin roles: $($rolesWithUsers.Count + $rolesWithoutUsers.Count)" -Level Standard
        Write-LogFile -Message "  Roles with users: $($rolesWithUsers.Count)" -Level Standard
        Write-LogFile -Message "  Empty roles: $($rolesWithoutUsers.Count)" -Level Standard
        Write-LogFile -Message "  Total administrators: $totalAdminCount" -Level Standard
        if ($IncludeSignInActivity) {
            Write-LogFile -Message "  Inactive administrators: $inactiveAdminCount" -Level Standard
        }

        Write-LogFile -Message "`nExported files:" -Level Standard -Color "Cyan"
        Write-LogFile -Message "  Individual role files: $outputDirPath" -Level Standard
        Write-LogFile -Message "  Merged file: $mergedFile" -Level Standard
    }
    catch {
        Write-logFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Color "Red" -Level Minimal
        if ($isDebugEnabled) {
            Write-LogFile -Message "[DEBUG] Error details:" -Level Debug
            Write-LogFile -Message "[DEBUG]   Exception type: $($_.Exception.GetType().Name)" -Level Debug
            Write-LogFile -Message "[DEBUG]   Error message: $($_.Exception.Message)" -Level Debug
            Write-LogFile -Message "[DEBUG]   Stack trace: $($_.ScriptStackTrace)" -Level Debug
        }
        throw
    }
}