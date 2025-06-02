Function Get-Licenses {
<#
    .SYNOPSIS
    Retrieves all licenses in the tenant with retention times and premium license indicators.

    .DESCRIPTION
    Returns all available licenses in the tenant along with their retention times and premium license indicators, and exports the details to a CSV file.

    .PARAMETER OutputDir
    OutputDir is the parameter specifying the output directory.
    Default: Output\Licenses

    .PARAMETER LogLevel
    Specifies the level of logging:
    None: No logging
    Minimal: Critical errors only
    Standard: Normal operational logging
    Debug: Verbose logging for debugging purposes
    Default: Standard

    .EXAMPLE
    Get-Licenses
    Retrieves all licenses and saves them to a CSV file in Output\Licenses.
#>
    [CmdletBinding()]
    param(
        [string]$OutputDir = "Output\Licenses",
        [ValidateSet('None', 'Minimal', 'Standard', 'Debug')]
        [string]$LogLevel = 'Standard'
    )

    Set-LogLevel -Level ([LogLevel]::$LogLevel)
    $isDebugEnabled = $script:LogLevel -eq [LogLevel]::Debug

    if ($isDebugEnabled) {
        Write-LogFile -Message "[DEBUG] PowerShell Version: $($PSVersionTable.PSVersion)" -Level Debug
        Write-LogFile -Message "[DEBUG] Input parameters:" -Level Debug
        Write-LogFile -Message "[DEBUG]   OutputDir: '$OutputDir'" -Level Debug
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

    if (!(Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
    }

    Write-LogFile -Message "=== Starting License Collection ===" -Color "Cyan" -Level Minimal

    try {
        $licenses = Get-MgSubscribedSku | Select-Object SkuPartNumber, CapabilityStatus, AppliesTo, ConsumedUnits, ServicePlans

        if ($isDebugEnabled) {
            Write-LogFile -Message "[DEBUG] Retrieved licenses:" -Level Debug
            foreach ($license in $licenses) {
                Write-LogFile -Message "[DEBUG]   - $($license.SkuPartNumber): $($license.ConsumedUnits) units, Status: $($license.CapabilityStatus)" -Level Debug
            }
        }

        if (-not $licenses) {
            Write-LogFile -Message "[ERROR] No licenses found in the tenant." -Color "Red" -Level Minimal
            return
        }

        $results = $licenses | ForEach-Object {
             $servicePlanNames = $_.ServicePlans.ServicePlanName -join '; '
             $servicePlansForChecks = $_.ServicePlans.ServicePlanName

             if ($isDebugEnabled) {
                Write-LogFile -Message "[DEBUG]   Service Plans Count: $($_.ServicePlans.Count)" -Level Debug
                Write-LogFile -Message "[DEBUG]   Service Plans: $($servicePlansForChecks -join ', ')" -Level Debug
            }


            [PSCustomObject]@{
                Sku              = $_.SkuPartNumber
                Status           = $_.CapabilityStatus
                Scope            = $_.AppliesTo
                Units            = $_.ConsumedUnits
                Retention        = if ($_.SkuPartNumber -match "E5") { "365 days" }
                                  elseif ($_.SkuPartNumber -match "E3") { "180 days" }
                                  else { "90 days" }
                E3               = if ($_.SkuPartNumber -in @("M365ENTERPRISE", "ENTERPRISEPACK", "STANDARD_EDU")) { "Yes" } else { "No" }
                E5               = if ($_.SkuPartNumber -in @("SPE_E5", "ENTERPRISEPREMIUM")) { "Yes" } else { "No" }
                P1               = if ($servicePlansForChecks -contains "AAD_PREMIUM") { "Yes" } else { "No" }
                P2               = if ($servicePlansForChecks -contains "AAD_PREMIUM_P2") { "Yes" } else { "No" }
                DefenderID       = if ($servicePlansForChecks -contains "MDE_ATP") { "Yes" } else { "No" }
                Defender365P1    = if ($servicePlansForChecks -contains "ATP_ENTERPRISE") { "Yes" } else { "No" }
                Defender365P2    = if ($servicePlansForChecks -contains "ATP_ENTERPRISE_PLUS") { "Yes" } else { "No" }
                ServicePlans     = $servicePlanNames
            }
        }

        $date = [datetime]::Now.ToString('yyyyMMddHHmmss')
        $outputFile = Join-Path $OutputDir "$($date)-TenantLicenses.csv"
        $results | Sort-Object -Property Units -Descending | Export-Csv -Path $outputFile -NoTypeInformation -Encoding UTF8
        Write-LogFile -Message "[INFO] License information saved to: $outputFile" -Color "Green" -Level Standard
        Write-LogFile -Message "`nLicense Information:" -Color "Cyan" -Level Standard

        return $results | 
            Sort-Object -Property Units -Descending | 
            Format-Table -Property @(
                @{Label = "License Name"; Expression = {$_.Sku}; Width = 30},
                @{Label = "Status"; Expression = {$_.Status}; Width = 10},
                @{Label = "Units"; Expression = {$_.Units}; Width = 8; Alignment = "Right"},
                @{Label = "Retention"; Expression = {$_.Retention}; Width = 12},
                @{Label = "E3"; Expression = {$_.E3}; Width = 5},
                @{Label = "E5"; Expression = {$_.E5}; Width = 5},
                @{Label = "P1"; Expression = {$_.P1}; Width = 5},
                @{Label = "P2"; Expression = {$_.P2}; Width = 5},
                @{Label = "DefenderID"; Expression = {$_.DefenderID}; Width = 12},
                @{Label = "Def365P1"; Expression = {$_.Defender365P1}; Width = 10},
                @{Label = "Def365P2"; Expression = {$_.Defender365P2}; Width = 10}
            ) -AutoSize


    } catch {
        Write-LogFile -Message "[ERROR] Failed to retrieve licenses: $($_.Exception.Message)" -Color "Red" -Level Minimal
        if ($isDebugEnabled) {
            Write-LogFile -Message "[DEBUG] Error details:" -Level Debug
            Write-LogFile -Message "[DEBUG]   Exception type: $($_.Exception.GetType().Name)" -Level Debug
            Write-LogFile -Message "[DEBUG]   Stack trace: $($_.ScriptStackTrace)" -Level Debug
        }
        throw
    }
}

Function Get-LicenseCompatibility {
<#
    .SYNOPSIS
    Checks the presence of E5, P2, P1, and E3 licenses and informs about functionality limitations.

    .DESCRIPTION
    Determines if E5, P2, P1, and E3 licenses are present and outputs messages regarding the capabilities and limitations.

    .PARAMETER LogLevel
    Specifies the level of logging:
    None: No logging
    Minimal: Critical errors only
    Standard: Normal operational logging
    Debug: Verbose logging for debugging purposes
    Default: Standard

    .EXAMPLE
    Get-LicenseCompatibility
    Checks for E5, P2, P1, and E3 licenses and outputs corresponding limitations.
#>
    [CmdletBinding()]
    param(
        [ValidateSet('None', 'Minimal', 'Standard', 'Debug')]
        [string]$LogLevel = 'Standard'
    )

    Set-LogLevel -Level ([LogLevel]::$LogLevel)
    $isDebugEnabled = $script:LogLevel -eq [LogLevel]::Debug

    if ($isDebugEnabled) {
        Write-LogFile -Message "[DEBUG] PowerShell Version: $($PSVersionTable.PSVersion)" -Level Debug
        Write-LogFile -Message "[DEBUG] Input parameters:" -Level Debug
        Write-LogFile -Message "[DEBUG]   OutputDir: '$OutputDir'" -Level Debug
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

    Write-LogFile -Message "=== Starting License Compatibility Check ===" -Color "Cyan" -Level Minimal

    try {
        $licenses = Get-MgSubscribedSku
        $allServicePlans = $licenses | ForEach-Object { $_.ServicePlans.ServicePlanName }

        if ($isDebugEnabled) {
            Write-LogFile -Message "[DEBUG] Found $($licenses.Count) total SKUs in tenant" -Level Debug
            Write-LogFile -Message "[DEBUG] Total service plans found: $($allServicePlans.Count)" -Level Debug
        }

        $global:e5Present = $licenses | Where-Object { $_.SkuPartNumber -match "E5" }
        $global:e3Present = $licenses | Where-Object { $_.SkuPartNumber -match "E3" }
        $global:p1Present = $allServicePlans -contains "AAD_PREMIUM"
        $global:p2Present = $allServicePlans -contains "AAD_PREMIUM_P2"

        if ($isDebugEnabled) {
            Write-LogFile -Message "[DEBUG] License analysis results:" -Level Debug
            Write-LogFile -Message "[DEBUG]   E5 licenses found: $($global:e5Present.Count)" -Level Debug
            if ($global:e5Present) {
                $global:e5Present | ForEach-Object { Write-LogFile -Message "[DEBUG]     - $($_.SkuPartNumber): $($_.ConsumedUnits) units" -Level Debug }
            }
            Write-LogFile -Message "[DEBUG]   E3 licenses found: $($global:e3Present.Count)" -Level Debug
            if ($global:e3Present) {
                $global:e3Present | ForEach-Object { Write-LogFile -Message "[DEBUG]     - $($_.SkuPartNumber): $($_.ConsumedUnits) units" -Level Debug }
            }
            Write-LogFile -Message "[DEBUG]   P1 capability present: $global:p1Present" -Level Debug
            Write-LogFile -Message "[DEBUG]   P2 capability present: $global:p2Present" -Level Debug
        }

        Write-LogFile -Message "`nLicense Status:" -Color "Cyan" -Level Standard
        Write-LogFile -Message "E5: $(if($global:e5Present){"Present"}else{"Not Present"})" -Color $(if($global:e5Present){"Green"}else{"Yellow"}) -Level Standard
        if (-not $global:e5Present) {
            Write-LogFile -Message "E3: $(if($global:e3Present){"Present"}else{"Not Present"})" -Color $(if($global:e3Present){"Green"}else{"Yellow"}) -Level Standard
        }
        Write-LogFile -Message "P2: $(if($global:p2Present){"Present"}else{"Not Present"})" -Color $(if($global:p2Present){"Green"}else{"Yellow"}) -Level Standard
        if (-not ($global:p2Present -or $global:e5Present)) {
            Write-LogFile -Message "P1: $(if($global:p1Present){"Present"}else{"Not Present"})" -Color $(if($global:p1Present){"Green"}else{"Yellow"}) -Level Standard
        }

        Write-LogFile -Message "`nFeature Compatibility:" -Color "Cyan" -Level Standard

        $features = @(
            @{Feature = "Get-Sessions"; Required = "E5"; Status = $global:e5Present}
            @{Feature = "Get-MessageIDs"; Required = "E5"; Status = $global:e5Present}
            @{Feature = "Get-GraphEntraAuditLogs"; Required = "E5"; Status = $global:e5Present}
            @{Feature = "Get-RiskyUsers"; Required = "E5 or P2"; Status = ($global:e5Present -or $global:p2Present)}
        )

        foreach ($feature in $features) {
            $status = if ($feature.Status) { "Available" } else { "Not Available" }
            $color = if ($feature.Status) { "Green" } else { "Yellow" }
            Write-LogFile -Message "$($feature.Feature) ($($feature.Required)): $status" -Color $color -Level Standard
        }

        Write-LogFile -Message "`nRetention Information:" -Color "Cyan" -Level Standard
        if ($global:e3Present -or $global:e5Present -or $global:p1Present -or $global:p2Present) {
            Write-LogFile -Message "Audit Log retention: 30 days" -Color "Green" -Level Standard
            Write-LogFile -Message "Sign-in Log retention: 30 days" -Color "Green" -Level Standard
        } else {
            Write-LogFile -Message "Audit Log retention: 7 days" -Color "Yellow" -Level Standard
            Write-LogFile -Message "Sign-in Log retention: 7 days" -Color "Yellow" -Level Standard
        }

        $recommendations = @()
        
        if (-not $global:e5Present) {
            $recommendations += "- Consider E5 license for full feature access and extended retention"
        }
        if (-not $global:p2Present -and -not $global:e5Present) {
            $recommendations += "- P2 license would enable risky users monitoring"
        }
        if (-not ($global:e3Present -or $global:e5Present -or $global:p1Present -or $global:p2Present)) {
            $recommendations += "- Current retention period is limited. Consider upgrading for extended retention"
        }

        if ($recommendations.Count -gt 0) {
            Write-LogFile -Message "`nRecommendations:" -Color "Cyan" -Level Standard
            foreach ($recommendation in $recommendations) {
                Write-LogFile -Message $recommendation -Color "Yellow" -Level Standard
            }
        }
    } catch {
        Write-LogFile -Message "[ERROR] Failed to check license capabilities: $($_.Exception.Message)" -Color "Red" -Level Minimal
        if ($isDebugEnabled) {
            Write-LogFile -Message "[DEBUG] Error details:" -Level Debug
            Write-LogFile -Message "[DEBUG]   Exception type: $($_.Exception.GetType().Name)" -Level Debug
            Write-LogFile -Message "[DEBUG]   Stack trace: $($_.ScriptStackTrace)" -Level Debug
        }
        throw
    }
}     

Function Get-EntraSecurityDefaults {
<#
    .SYNOPSIS
    Checks the status of Entra ID security defaults.

    .DESCRIPTION
    Retrieves and logs the status of security defaults and exports the result to a CSV file.

    .PARAMETER OutputDir
    OutputDir is the parameter specifying the output directory.
    Default: Output\Licenses
    
    .PARAMETER LogLevel
    Specifies the level of logging:
    None: No logging
    Minimal: Critical errors only
    Standard: Normal operational logging
    Debug: Verbose logging for debugging purposes
    Default: Standard

    .EXAMPLE
    Get-EntraSecurityDefaults
    Checks the status of security defaults and saves the results to a CSV file in Output\Licenses.
#>
    [CmdletBinding()]
    param(
        [string]$OutputDir = "Output\Licenses",
        [ValidateSet('None', 'Minimal', 'Standard', 'Debug')]
        [string]$LogLevel = 'Standard'
    )

    Set-LogLevel -Level ([LogLevel]::$LogLevel)
    $isDebugEnabled = $script:LogLevel -eq [LogLevel]::Debug

    if ($isDebugEnabled) {
        Write-LogFile -Message "[DEBUG] PowerShell Version: $($PSVersionTable.PSVersion)" -Level Debug
        Write-LogFile -Message "[DEBUG] Input parameters:" -Level Debug
        Write-LogFile -Message "[DEBUG]   OutputDir: '$OutputDir'" -Level Debug
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

    if (!(Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
    }

    Write-LogFile -Message "=== Starting Security Defaults Check ===" -Color "Cyan" -Level Minimal

    try {
        if ($null -eq $global:e5Present) {
            $licenses = Get-MgSubscribedSku
            $allServicePlans = $licenses | ForEach-Object { $_.ServicePlans.ServicePlanName }
            $global:e5Present = $licenses | Where-Object { $_.SkuPartNumber -match "E5" }
            $global:e3Present = $licenses | Where-Object { $_.SkuPartNumber -match "E3" }
            $global:p2Present = $allServicePlans -contains "AAD_PREMIUM_P2"
            $global:p1Present = $allServicePlans -contains "AAD_PREMIUM"
        }

        $securityDefaults = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy
        $isEnabled = $securityDefaults.IsEnabled
        $hasPremiumLicense = $global:e5Present -or $global:e3Present -or $global:p2Present -or $global:p1Present


        if ($isDebugEnabled) {
            Write-LogFile -Message "[DEBUG] Security defaults analysis:" -Level Debug
            Write-LogFile -Message "[DEBUG]   Security Defaults Enabled: $isEnabled" -Level Debug
            Write-LogFile -Message "[DEBUG]   Has Premium License: $hasPremiumLicense" -Level Debug
            Write-LogFile -Message "[DEBUG]   Policy ID: $($securityDefaults.Id)" -Level Debug
            Write-LogFile -Message "[DEBUG]   Policy Display Name: $($securityDefaults.DisplayName)" -Level Debug
        }

        Write-LogFile -Message "`nSecurity Defaults Status:" -Color "Cyan" -Level Standard
        if ($isEnabled) {
            Write-LogFile -Message "Security Defaults: Enabled" -Color "Green" -Level Standard
        } else {
            Write-LogFile -Message "Security Defaults: Disabled" -Color "Yellow" -Level Standard
        }

        $securityDefaults = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy
        $isEnabled = $securityDefaults.IsEnabled

        $result = [PSCustomObject]@{
            SecurityDefaultsEnabled = if ($isEnabled) { "Yes" } else { "No" }
        }

        Write-LogFile -Message "`nLicense Context:" -Color "Cyan" -Level Standard
        if ($hasPremiumLicense) {
            Write-LogFile -Message "Premium License(s) Detected:" -Level Standard
            if ($global:e5Present) { Write-LogFile -Message "  - E5" -Level Standard }
            if ($global:e3Present -and -not $global:e5Present) { Write-LogFile -Message "  - E3" -Level Standard }
            if ($global:p2Present -and -not $global:e5Present) { Write-LogFile -Message "  - P2" -Level Standard }
            if ($global:p1Present -and -not ($global:p2Present -or $global:e5Present)) { Write-LogFile -Message "  - P1" -Level Standard }
        } else {
            Write-LogFile -Message "No Premium Licenses Detected" -Level Standard
        }

        Write-LogFile -Message "`nRecommendations:" -Color "Cyan" -Level Standard
        if ($hasPremiumLicense) {
            if ($isEnabled) {
                Write-LogFile -Message "[!] With your current license level (Premium), Microsoft recommends:" -Color "Yellow" -Level Standard
                Write-LogFile -Message "  - Disable Security Defaults" -Level Standard
                Write-LogFile -Message "  - Configure Conditional Access policies for greater control" -Level Standard
                Write-LogFile -Message "  - Implement MFA through Conditional Access" -Level Standard
            } else {
                Write-LogFile -Message "Current configuration aligns with Microsoft recommendations" -Color "Green" -Level Standard
                Write-LogFile -Message "  - Ensure Conditional Access policies are properly configured" -Level Standard
                Write-LogFile -Message "  - Regular review of security policies is recommended" -Level Standard
            }
        } else {
            if ($isEnabled) {
                Write-LogFile -Message "Current configuration aligns with Microsoft recommendations" -Color "Green" -Level Standard
                Write-LogFile -Message "  - Security Defaults provide basic security for free/basic licenses" -Level Standard
            } else {
                Write-LogFile -Message "[!] With your current license level (Basic), Microsoft recommends:" -Color "Red" -Level Minimal
                Write-LogFile -Message "  - Enable Security Defaults for baseline protection" -Level Standard
                Write-LogFile -Message "  - Consider upgrading to premium license for advanced security features" -Level Standard
            }
        }

        $result = [PSCustomObject]@{
            SecurityDefaultsEnabled = if ($isEnabled) { "Yes" } else { "No" }
            HasPremiumLicense = if ($hasPremiumLicense) { "Yes" } else { "No" }
            RecommendedState = if ($hasPremiumLicense) { "Disabled" } else { "Enabled" }
            AlignedWithRecommendations = if (($hasPremiumLicense -and -not $isEnabled) -or (-not $hasPremiumLicense -and $isEnabled)) { "Yes" } else { "No" }
            CheckDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }

        $date = [datetime]::Now.ToString('yyyyMMddHHmmss')
        $outputFile = Join-Path $OutputDir "$($date)-EntraSecurityDefaults.csv"
        $result | Export-Csv -Path $outputFile -NoTypeInformation -Encoding UTF8

        Write-LogFile -Message "`nCheck Summary:" -Color "Cyan" -Level Standard
        Write-LogFile -Message ($result | Format-List | Out-String).Trim() -Level Standard
        
        Write-LogFile -Message "`nOutput Files:" -Color "Cyan" -Level Standard
        Write-LogFile -Message "- Results exported to: $outputFile" -Color "Green" -Level Standard
    } catch {
        Write-LogFile -Message "[ERROR] Failed to check security defaults: $($_.Exception.Message)" -Color "Red" -Level Minimalif ($isDebugEnabled) {
            Write-LogFile -Message "[DEBUG] Error details:" -Level Debug
            Write-LogFile -Message "[DEBUG]   Exception type: $($_.Exception.GetType().Name)" -Level Debug
            Write-LogFile -Message "[DEBUG]   Stack trace: $($_.ScriptStackTrace)" -Level Debug
        }
        throw
    }
}

Function Get-LicensesByUser {
<#
    .SYNOPSIS
    Retrieves license assignments for all users in the tenant.

    .DESCRIPTION
    Retrieves all licenses assigned to users in the tenant and saves the results to a CSV file.

    .PARAMETER OutputDir
    OutputDir is the parameter specifying the output directory.
    Default: Output\Licenses

    .PARAMETER LogLevel
    Specifies the level of logging:
    None: No logging
    Minimal: Critical errors only
    Standard: Normal operational logging
    Debug: Verbose logging for debugging purposes
    Default: Standard

    .EXAMPLE
    Get-LicensesByUser -OutputDir "Output\Licenses"
    Retrieves license assignments and saves the details to a CSV file in the specified directory.
#>
    [CmdletBinding()]
    param(
        [string]$OutputDir = "Output\Licenses",
        [ValidateSet('None', 'Minimal', 'Standard', 'Debug')]
        [string]$LogLevel = 'Standard'
    )

    Set-LogLevel -Level ([LogLevel]::$LogLevel)
    $isDebugEnabled = $script:LogLevel -eq [LogLevel]::Debug

    if ($isDebugEnabled) {
        Write-LogFile -Message "[DEBUG] PowerShell Version: $($PSVersionTable.PSVersion)" -Level Debug
        Write-LogFile -Message "[DEBUG] Input parameters:" -Level Debug
        Write-LogFile -Message "[DEBUG]   OutputDir: '$OutputDir'" -Level Debug
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

    if (!(Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
    }

    Write-LogFile -Message "=== Starting User License Collection ===" -Color "Cyan" -Level Minimal

    try {
        if (!(Get-MgContext)) {
            Connect-MgGraph -Scopes "User.Read.All", "Directory.Read.All"
        }

        $skus = Get-MgSubscribedSku | Select-Object SkuId, SkuPartNumber
        if ($isDebugEnabled) {
            Write-LogFile -Message "[DEBUG] Retrieved $($skus.Count) SKUs from tenant" -Level Debug
            foreach ($sku in $skus) {
                Write-LogFile -Message "[DEBUG]   SKU: $($sku.SkuPartNumber) (ID: $($sku.SkuId))" -Level Debug
            }
        }

        $results = @()
        $users = Get-MgUser -All -Property DisplayName, UserPrincipalName, Id

        if (-not $users) {
            Write-LogFile -Message "[ERROR] No users retrieved. Ensure you have sufficient permissions and users exist in the tenant." -Color "Red" -Level Minimal
            return
        }

        foreach ($user in $users) {
            if (-not $user.Id) {
                Write-LogFile -Message "[ALERT] Skipping user: $($user.DisplayName) - Missing 'Id' property" -Color "Yellow" -Level Standard
                continue
            }

            try {
                $licenseDetails = Get-MgUserLicenseDetail -UserId $user.Id

                if ($licenseDetails) {
                    foreach ($license in $licenseDetails) {
                        $skuPartNumber = ($skus | Where-Object { $_.SkuId -eq $license.SkuId }).SkuPartNumber

                        if ($isDebugEnabled) {
                            Write-LogFile -Message "[DEBUG]   Found license: $skuPartNumber for user $($user.UserPrincipalName)" -Level Debug
                        }

                        $results += [PSCustomObject]@{
                            DisplayName       = $user.DisplayName
                            UserPrincipalName = $user.UserPrincipalName
                            SkuPartNumber     = $skuPartNumber
                        }
                    }
                } else {
                    $results += [PSCustomObject]@{
                        DisplayName       = $user.DisplayName
                        UserPrincipalName = $user.UserPrincipalName
                        SkuPartNumber     = "None"
                    }
                }
            } catch {
                Write-LogFile -Message "[ERROR] Failed to retrieve license details for user $($user.UserPrincipalName): $($_.Exception.Message)" -Color "Red" -Level Minimal
                if ($isDebugEnabled) {
                    Write-LogFile -Message "[DEBUG] Error details for user $($user.UserPrincipalName):" -Level Debug
                    Write-LogFile -Message "[DEBUG]   Exception type: $($_.Exception.GetType().Name)" -Level Debug
                    Write-LogFile -Message "[DEBUG]   Stack trace: $($_.ScriptStackTrace)" -Level Debug
                }
            }
        }

        $date = [datetime]::Now.ToString('yyyyMMddHHmmss')
        $outputFile = Join-Path $OutputDir "$($date)-UserLicenses.csv"
        $results | Sort-Object DisplayName | Export-Csv -Path $outputFile -NoTypeInformation -Encoding UTF8

        $userLicenseSummary = [PSCustomObject]@{
            TotalUsers = ($users | Measure-Object).Count
            LicensedUsers = ($results | Select-Object -Unique UserPrincipalName | Measure-Object).Count
            UnlicensedUsers = (($results | Where-Object { $_.SkuPartNumber -eq "None" }) | Measure-Object).Count
            TotalAssignments = ($results | Where-Object { $_.SkuPartNumber -ne "None" } | Measure-Object).Count
        }

        $licenseDistribution = $results | 
            Where-Object { $_.SkuPartNumber -ne "None" } | 
            Group-Object SkuPartNumber | 
            Sort-Object Count -Descending

        Write-LogFile -Message "`nUser License Summary:" -Color "Cyan" -Level Standard
        Write-LogFile -Message "Total Users: $($userLicenseSummary.TotalUsers)" -Level Standard
        Write-LogFile -Message "  - Total License Assignments: $($userLicenseSummary.TotalAssignments)" -Level Standard
        Write-LogFile -Message "  - Licensed Users: $($userLicenseSummary.LicensedUsers)" -Level Standard
        Write-LogFile -Message "  - Unlicensed Users: $($userLicenseSummary.UnlicensedUsers)" -Level Standard

        Write-LogFile -Message "`nLicense Type Distribution:" -Color "Cyan" -Level Standard
        foreach ($license in $licenseDistribution) {
            Write-LogFile -Message "  - $($license.Name): $($license.Count) assignments" -Level Standard
        }

        Write-LogFile -Message "`nExported File:" -Color "Cyan" -Level Standard
        Write-LogFile -Message "  - File: $outputFile" -Level Standard
    } catch {
        Write-LogFile -Message "[ERROR] Failed to retrieve user license assignments: $($_.Exception.Message)" -Color "Red" -Level Minimal
        if ($isDebugEnabled) {
            Write-LogFile -Message "[DEBUG] Error details:" -Level Debug
            Write-LogFile -Message "[DEBUG]   Exception type: $($_.Exception.GetType().Name)" -Level Debug
            Write-LogFile -Message "[DEBUG]   Stack trace: $($_.ScriptStackTrace)" -Level Debug
        }
        throw
    }
}
    