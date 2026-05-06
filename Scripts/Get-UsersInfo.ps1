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
    Init-OutputDir -Component "Users" -FilePostfix "Users" -CustomOutputDir $OutputDir

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
            Write-LogFile -Message "[INFO] Found $($mgUsers.Count) users" -Level Standard
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

        $now  = Get-Date
        $d7   = $now.AddDays(-7)
        $d30  = $now.AddDays(-30)
        $d90  = $now.AddDays(-90)
        $d180 = $now.AddDays(-180)
        $d360 = $now.AddDays(-360)

        $counts = @{ Week=0; Month=0; ThreeMonth=0; SixMonth=0; Year=0; Enabled=0; Disabled=0; OnPrem=0; Guest=0 }
        foreach ($u in $mgUsers) {
            if ($u.CreatedDateTime -gt $d7)   { $counts.Week++ }
            if ($u.CreatedDateTime -gt $d30)  { $counts.Month++ }
            if ($u.CreatedDateTime -gt $d90)  { $counts.ThreeMonth++ }
            if ($u.CreatedDateTime -gt $d180) { $counts.SixMonth++ }
            if ($u.CreatedDateTime -gt $d360) { $counts.Year++ }
            if ($u.AccountEnabled)            { $counts.Enabled++ }
            else                              { $counts.Disabled++ }
            if ($u.OnPremisesSyncEnabled)     { $counts.OnPrem++ }
            if ($u.UserType -eq "Guest")      { $counts.Guest++ }
        }

        $formattedUsers | Export-Csv -Path $script:outputFile -NoTypeInformation -Encoding $Encoding

        $summary = [ordered]@{
            "User Counts" = [ordered]@{
                "Total Users"            = $mgUsers.Count
                "Enabled Users"          = $counts.Enabled
                "Disabled Users"         = $counts.Disabled
                "Synced from On-Premises" = $counts.OnPrem
                "Guest Users"            = $counts.Guest
            }
            "Recent Account Creation" = [ordered]@{
                "Last 7 days"   = $counts.Week
                "Last 30 days"  = $counts.Month
                "Last 90 days"  = $counts.ThreeMonth
                "Last 6 months" = $counts.SixMonth
                "Last 1 year"   = $counts.Year
            }
        }

        Write-Summary -Summary $summary -Title "User Analysis Summary"
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
    Init-OutputDir -Component "Admins" -FilePostfix "AdminUsers" -CustomOutputDir $OutputDir

    Write-LogFile -Message "=== Starting Admin Users Collection ===" -Color "Cyan" -Level Standard

    $requiredScopes = @("User.Read.All", "Directory.Read.All")
    $graphAuth = Get-GraphAuthType -RequiredScopes $RequiredScopes

    if ($isDebugEnabled) {
        Write-LogFile -Message "[DEBUG] Graph authentication details:" -Level Debug
        Write-LogFile -Message "[DEBUG]   Required scopes: $($requiredScopes -join ', ')" -Level Debug
        Write-LogFile -Message "[DEBUG]   Authentication type: $($graphAuth.AuthType)" -Level Debug
        Write-LogFile -Message "[DEBUG]   Current scopes: $($graphAuth.Scopes -join ', ')" -Level Debug
    }

    Write-LogFile -Message "[INFO] Analyzing administrator roles..." -Level Standard
    $rolesWithUsers = [System.Collections.Generic.List[object]]::new()
    $rolesWithoutUsers = [System.Collections.Generic.List[object]]::new()
    $exportedFiles = [System.Collections.Generic.List[object]]::new()
    $totalAdminCount = 0
    $inactiveAdminCount = 0
    $inactiveThreshold = (Get-Date).AddDays(-30)
    $inactiveAdmins = [System.Collections.Generic.List[object]]::new()

    try {
        if ($isDebugEnabled) {
            Write-LogFile -Message "[DEBUG] Retrieving all directory roles..." -Level Debug
            $performance = Measure-Command { $getRoles = Get-MgDirectoryRole -all }
            Write-LogFile -Message "[DEBUG] Directory roles retrieval took $([math]::round($performance.TotalSeconds, 2)) seconds" -Level Debug
        } else {
            $getRoles = Get-MgDirectoryRole -all
        }
        
        foreach ($role in $getRoles) {
            $roleId = $role.Id
            $roleName = $role.DisplayName
        
            if ($roleName -like "*Admin*") {
                $areThereUsers = Get-MgDirectoryRoleMember -DirectoryRoleId $roleId

                if ($null -eq $areThereUsers) {
                    $rolesWithoutUsers.Add($roleName)
                    continue
                }

                $results = New-Object System.Collections.Generic.List[PSObject]
                
                # 1. Verzamel en filter ID's
                $validUserIds = [System.Collections.Generic.List[string]]::new()
                foreach ($member in $areThereUsers) {
                    if (-not [string]::IsNullOrWhiteSpace($member.Id) -and $member.Id -ne ".") {
                        $cleanId = $member.Id -replace '[^a-zA-Z0-9\-]', ''
                        if ($cleanId) { $validUserIds.Add($cleanId) }
                    }
                }
                
                if ($validUserIds.Count -eq 0) { continue }

                # 2. Bulk OData Filtering (15 gebruikers per keer)
                for ($i = 0; $i -lt $validUserIds.Count; $i += 15) {
                    
                    $chunkSize = [math]::Min(15, $validUserIds.Count - $i)
                    $currentChunk = $validUserIds.GetRange($i, $chunkSize)
                    
                    $filterValues = $currentChunk | ForEach-Object { "'$_'" }
                    $filterString = "id in ($($filterValues -join ','))"

                    try {
                        $getUsers = Get-MgUser -Filter $filterString -Property "UserPrincipalName","DisplayName","Id","Department","JobTitle","AccountEnabled","CreatedDateTime","SignInActivity" -ErrorAction Stop

                        [array]$retrievedUsers = $getUsers

                        foreach ($u in $retrievedUsers) {
                            $userName = $u.UserPrincipalName

                            $userObject = [PSCustomObject]@{
                                UserName = $userName
                                UserId = $u.Id
                                Role = $roleName
                                DisplayName = $u.DisplayName
                                Department = $u.Department
                                JobTitle = $u.JobTitle
                                AccountEnabled = $u.AccountEnabled
                                CreatedDateTime = $u.CreatedDateTime
                                LastInteractiveSignIn = $u.SignInActivity.LastSignInDateTime
                                LastNonInteractiveSignIn = $u.SignInActivity.LastNonInteractiveSignInDateTime
                            }

                            if ($u.SignInActivity.LastSignInDateTime) {
                                $lastSignInDate = [datetime]$u.SignInActivity.LastSignInDateTime
                                $daysSinceSignIn = (New-TimeSpan -Start $lastSignInDate -End (Get-Date)).Days
                                $userObject | Add-Member -MemberType NoteProperty -Name "DaysSinceLastSignIn" -Value $daysSinceSignIn
                                
                                if ($lastSignInDate -lt $inactiveThreshold) {
                                    $inactiveAdminCount++
                                    $inactiveAdmins.Add("$($u.DisplayName) ($userName) - $daysSinceSignIn days")
                                }
                            } else {
                                $userObject | Add-Member -MemberType NoteProperty -Name "DaysSinceLastSignIn" -Value "No sign-in data"
                                $inactiveAdminCount++
                                $inactiveAdmins.Add("$($u.DisplayName) ($userName) - No sign-in data")                 
                            }
                            
                            $results.Add($userObject)
                        }
                    } catch {
                        $errMsg = $_.Exception.Message
                        Write-LogFile -Message "[WARNING] Bulk fetch failed for role $roleName`: $errMsg" -Color "Yellow" -Level Standard
                    }
                }

                # Export per rol
                if ($results.Count -gt 0) {
                    $totalAdminCount += $results.Count
                    $rolesWithUsers.Add("$roleName ($($results.Count) users)")
                    
                    $date = [datetime]::Now.ToString('yyyyMMdd')
                    $safeRoleName = $roleName -replace '[^\w\-_\.]', '_'
                    $rolePath = Split-Path $script:outputFile -Parent
                    $roleFilePath = Join-Path $rolePath "$date-$safeRoleName.csv"

                    $results.ToArray() | Export-Csv -Path $roleFilePath -NoTypeInformation -Encoding $Encoding
                    $exportedFiles.Add($roleFilePath)
                }
                else {
                    $rolesWithoutUsers.Add($roleName)
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

        $adminFiles = Get-ChildItem $outputDirPath -Filter "*Admin*.csv" -ErrorAction SilentlyContinue
        if ($adminFiles.Count -gt 0) {
            $adminFiles | ForEach-Object { Import-Csv $_.FullName } | Export-Csv $mergedFile -NoTypeInformation -Encoding $Encoding
        }

        $summary = [ordered]@{
            "Role Summary" = [ordered]@{
                "Total admin roles" = ($rolesWithUsers.Count + $rolesWithoutUsers.Count)
                "Roles with users" = $rolesWithUsers.Count
                "Empty roles" = $rolesWithoutUsers.Count
                "Total administrators" = $totalAdminCount
                "Inactive administrators (30+ days)" = $inactiveAdminCount
            }
        }

        Write-LogFile -Message "`nRoles with users:" -Color "Green" -Level Standard
        foreach ($role in $rolesWithUsers) { Write-LogFile -Message "  + $role" -Level Standard }

        Write-LogFile -Message "`nEmpty roles:" -Color "Yellow" -Level Standard
        foreach ($role in $rolesWithoutUsers) { Write-LogFile -Message "  - $role" -Level Standard }

        if ($inactiveAdmins.Count -gt 0) {
            Write-LogFile -Message "`nInactive administrators (30+ days):" -Color "Yellow" -Level Standard
            foreach ($admin in $inactiveAdmins) { Write-LogFile -Message "  ! $admin" -Level Standard }
        }

        Write-Summary -Summary $summary -Title "Admin Users Summary"
    }
    catch {
        Write-logFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Color "Red" -Level Minimal
        throw
    }
}