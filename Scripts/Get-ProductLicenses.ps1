Function Get-Licenses {
    <#
        .SYNOPSIS
        Retrieves all licenses in the tenant with retention times and premium license indicators.
    
        .DESCRIPTION
        Returns all available licenses in the tenant along with their retention times and premium license indicators, and exports the details to a CSV file.
    
        .EXAMPLE
        Get-Licenses
        Retrieves all licenses and saves them to a CSV file in Output\Licenses.
    #>
    [CmdletBinding()]
    param(
        [string]$OutputDir = "Output\Licenses"
    )

    if (!(Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
    }

    Write-LogFile -Message "[INFO] Retrieving tenant licenses."

    try {
        $licenses = Get-MgSubscribedSku | Select-Object SkuPartNumber, CapabilityStatus, AppliesTo, ConsumedUnits, ServicePlans

        if (-not $licenses) {
            Write-LogFile -Message "[ERROR] No licenses found in the tenant." -Color "Red"
            return
        }

        $results = $licenses | ForEach-Object {
            $servicePlans = $_.ServicePlans.ServicePlanName

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
                P1               = if ($servicePlans -contains "AAD_PREMIUM") { "Yes" } else { "No" }
                P2               = if ($servicePlans -contains "AAD_PREMIUM_P2") { "Yes" } else { "No" }
                DefenderID       = if ($servicePlans -contains "MDE_ATP") { "Yes" } else { "No" }
                Defender365P1    = if ($servicePlans -contains "ATP_ENTERPRISE") { "Yes" } else { "No" }
                Defender365P2    = if ($servicePlans -contains "ATP_ENTERPRISE_PLUS") { "Yes" } else { "No" }
                ServicePlans     = $_.ServicePlans
            }
        }

        $date = [datetime]::Now.ToString('yyyyMMddHHmmss')
        $outputFile = Join-Path $OutputDir "$($date)-TenantLicenses.csv"
        $results | Sort-Object -Property Units -Descending | Export-Csv -Path $outputFile -NoTypeInformation -Encoding UTF8
        Write-LogFile -Message "[INFO] License information saved to: $outputFile" -Color "Green"

        return $results | Sort-Object -Property ConsumedUnits -Descending | select-object *
    } catch {
        Write-LogFile -Message "[ERROR] Failed to retrieve licenses: $($_.Exception.Message)" -Color "Red"
        throw
    }
}

Function Get-LicenseCompatibility {
    <#
        .SYNOPSIS
        Checks the presence of E5, P2, P1, and E3 licenses and informs about the functionality of specific commands available to use in Extractor Suite as well as AAD audit log retention.
    
        .DESCRIPTION
        Determines if E5, P2, P1, and E3 licenses are present and outputs messages regarding the capabilities of Extractor Suite functions and the retention period of Azure Active Directory audit logs.
    
        .EXAMPLE
        Get-LicenseCompatibility
        Checks for E5, P2, P1, and E3 licenses and outputs corresponding limitations of using Extractor Suite for the current license level.
    #>

    try {
        $licenses = Get-MgSubscribedSku | Select-Object SkuPartNumber

        $global:e5Present = $licenses | Where-Object { $_.SkuPartNumber -match "E5" }
        $global:p2Present = $licenses | Where-Object { $_.SkuPartNumber -match "P2" }
        $global:p1Present = $licenses | Where-Object { $_.SkuPartNumber -match "P1" }
        $global:e3Present = $licenses | Where-Object { $_.SkuPartNumber -match "E3" }

        if ($global:e5Present) {
            Write-LogFile -Message "[INFO] E5 license detected. All parts of Extractor Suite will work with this license level." -Color "Green"
        } else {
            Write-LogFile -Message "[INFO] E5 is missing. Get-Sessions, Get-MessageIDs, and Get-ADAuditLogsGraph will not work." -Color "Yellow"
        }

        if (-not $global:e5Present -and -not $p2Present) {
            Write-LogFile -Message "[INFO] Neither E5 or P2 are present. Get-RiskyUsers will not work." -Color "Yellow"
        }

        if ($global:e3Present -or $global:e5Present -or $global:p1Present -or $global:p2Present) {
            Write-LogFile -Message "[INFO] Azure Active Directory Audit Log retention is 30 days."
        } else {
            Write-LogFile -Message "[INFO] Azure Active Directory Audit Log retention is 7 days."
        }

    } catch {
        Write-LogFile -Message "[ERROR] Failed to check license capabilities: $($_.Exception.Message)" -Color "Red"
        throw
    }
}     

Function Get-EntraSecurityDefaults {
    <#
        .SYNOPSIS
        Checks the status of Entra ID security defaults.
    
        .DESCRIPTION
        Retrieves and logs the status of security defaults and exports the result to a CSV file.
    
        .EXAMPLE
        Get-EntraSecurityDefaults
        Checks the status of security defaults and saves the results to a CSV file in Output\Licenses.
    #>
        [CmdletBinding()]
        param(
            [string]$OutputDir = "Output\Licenses"
        )
    
        if (!(Test-Path $OutputDir)) {
            New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
        }
    
        Write-LogFile -Message "[INFO] Checking for Entra ID security defaults."
    
        try {
            $securityDefaults = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy
            $isEnabled = $securityDefaults.IsEnabled
    
            $result = [PSCustomObject]@{
                SecurityDefaultsEnabled = if ($isEnabled) { "Yes" } else { "No" }
            }
    
            if ($isEnabled) {
                Write-LogFile -Message "[INFO] Azure security defaults have been enabled" -Color "Green"
    
                if ($global:e3present -or $global:e5present -or $global:p1present -or $global:p2present) {
                    Write-LogFile -Message "[ALERT] Azure security defaults detected on a P1/P2/E3/E5 license. Microsoft recommends using conditional access policies with greater granularity instead of Azure security defaults with these licenses." -Color "Yellow"
                }
            } else {
                Write-LogFile -Message "[INFO] Azure security defaults have not been enabled" -Color "Yellow"
    
                if (-not ($global:e3present -or $global:e5present -or $global:p1present -or $global:p2present)) {
                    Write-LogFile -Message "[ALERT] Azure security defaults are NOT enabled. Microsoft recommends security defaults enabled at this license level." -Color "Red"
                }
            }

            $date = [datetime]::Now.ToString('yyyyMMddHHmmss')
            $outputFile = Join-Path $OutputDir "$($date)-EntraSecurityDefaults.csv"
            $result | Export-Csv -Path $outputFile -NoTypeInformation -Encoding UTF8
            Write-LogFile -Message "[INFO] Security defaults status saved to: $outputFile" -Color "Green"
    
            return $result
        } catch {
            Write-LogFile -Message "[ERROR] Failed to check security defaults: $($_.Exception.Message)" -Color "Red"
            throw
        }
}

Function Get-LicensesByUser {
    <#
        .SYNOPSIS
        Retrieves license assignments for all users in the tenant.
    
        .DESCRIPTION
        Retrieves all licenses assigned to users in the tenant and saves the results to a CSV file.
    
        .EXAMPLE
        Get-LicensesByUser -OutputDir "Output\Licenses"
        Retrieves license assignments and saves the details to a CSV file in the specified directory.
    #>
    [CmdletBinding()]
    param(
        [string]$OutputDir = "Output\Licenses"
    )

    if (!(Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
    }

    Write-LogFile -Message "[INFO] Retrieving license assignments for all users."

    try {
        if (!(Get-MgContext)) {
            Connect-MgGraph -Scopes "User.Read.All", "Directory.Read.All"
        }

        $skus = Get-MgSubscribedSku | Select-Object SkuId, SkuPartNumber
        $results = @()
        $users = Get-MgUser -All -Property DisplayName, UserPrincipalName, Id

        if (-not $users) {
            Write-LogFile -Message "[ERROR] No users retrieved. Ensure you have sufficient permissions and users exist in the tenant." -Color "Red"
            return
        }

        foreach ($user in $users) {
            if (-not $user.Id) {
                Write-LogFile -Message "[ALERT] Skipping user: $($user.DisplayName) - Missing 'Id' property" -Color "Yellow"
                continue
            }

            try {
                $licenseDetails = Get-MgUserLicenseDetail -UserId $user.Id

                if ($licenseDetails) {
                    foreach ($license in $licenseDetails) {
                        $skuPartNumber = ($skus | Where-Object { $_.SkuId -eq $license.SkuId }).SkuPartNumber

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
                Write-LogFile -Message "[ERROR] Failed to retrieve license details for user $($user.UserPrincipalName): $($_.Exception.Message)" -Color "Red"
            }
        }

        $date = [datetime]::Now.ToString('yyyyMMddHHmmss')
        $outputFile = Join-Path $OutputDir "$($date)-UserLicenses.csv"
        $results | Sort-Object DisplayName | Export-Csv -Path $outputFile -NoTypeInformation -Encoding UTF8
        Write-LogFile -Message "[INFO] User license assignments saved to: $outputFile" -Color "Green"

        return $results | Sort-Object DisplayName | Format-Table -AutoSize
    } catch {
        Write-LogFile -Message "[ERROR] Failed to retrieve user license assignments: $($_.Exception.Message)" -Color "Red"
        throw
    }
}
