
Function Get-ConditionalAccessPolicies {
<#
    .SYNOPSIS
    Retrieves all the conditional access policies. 

    .DESCRIPTION
    Retrieves all the conditional access policies.

    .PARAMETER OutputDir
    OutputDir is the parameter specifying the output directory.
    Default: Output\ConditionalAccessPolicies

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
    Get-ConditionalAccessPolicies
    Retrieves all the conditional access policies.

    .EXAMPLE
    Get-ConditionalAccessPolicies -Application
    Retrieves all the conditional access policies via application authentication.
    
    .EXAMPLE
    Get-ConditionalAccessPolicies -Encoding utf32
    Retrieves all the conditional access policies and exports the output to a CSV file with UTF-32 encoding.
        
    .EXAMPLE
    Get-ConditionalAccessPolicies -OutputDir C:\Windows\Temp
    Retrieves all the conditional access policies and saves the output to the C:\Windows\Temp folder.	
#>
    [CmdletBinding()]
    param(
        [string]$OutputDir = "Output\ConditionalAccessPolicies",
        [string]$Encoding = "UTF8",
        [ValidateSet('None', 'Minimal', 'Standard', 'Debug')]
        [string]$LogLevel = 'Standard'
    )

    Set-LogLevel -Level ([LogLevel]::$LogLevel)
    $isDebugEnabled = $script:LogLevel -eq [LogLevel]::Debug
    $results=@();

    if ($isDebugEnabled) {
        Write-LogFile -Message "[DEBUG] PowerShell Version: $($PSVersionTable.PSVersion)" -Level Debug
        Write-LogFile -Message "[DEBUG] Input parameters:" -Level Debug
        Write-LogFile -Message "[DEBUG]   OutputDir: $OutputDir" -Level Debug
        Write-LogFile -Message "[DEBUG]   Encoding: $Encoding" -Level Debug
        Write-LogFile -Message "[DEBUG]   LogLevel: $LogLevel" -Level Debug
        
        $graphModule = Get-Module -Name Microsoft.Graph* -ErrorAction SilentlyContinue
        if ($graphModule) {
            Write-LogFile -Message "[DEBUG] Microsoft Graph Modules loaded:" -Level Debug
            foreach ($module in $graphModule) {
                Write-LogFile -Message "[DEBUG]   - $($module.Name) v$($module.Version)" -Level Debug
            }
        } else {
            Write-LogFile -Message "[DEBUG] No Microsoft Graph modules loaded" -Level Debug
        }
    }

    $requiredScopes = @("Policy.Read.All")
    $graphAuth = Get-GraphAuthType -RequiredScopes $RequiredScopes

    if ($isDebugEnabled) {
        Write-LogFile -Message "[DEBUG] Graph authentication completed" -Level Debug
        try {
            $context = Get-MgContext
            if ($context) {
                Write-LogFile -Message "[DEBUG] Graph context information:" -Level Debug
                Write-LogFile -Message "[DEBUG]   Account: $($context.Account)" -Level Debug
                Write-LogFile -Message "[DEBUG]   Environment: $($context.Environment)" -Level Debug
                Write-LogFile -Message "[DEBUG]   TenantId: $($context.TenantId)" -Level Debug
                Write-LogFile -Message "[DEBUG]   Scopes: $($context.Scopes -join ', ')" -Level Debug
            }
        } catch {
            Write-LogFile -Message "[DEBUG] Could not retrieve Graph context details" -Level Debug
        }
    }

    Write-LogFile -Message "=== Starting Conditional Access Policy Collection ===" -Color "Cyan" -Level Standard

    if (!(test-path $OutputDir)) {
        New-Item -ItemType Directory -Force -Path $OutputDir > $null
    }    
    else {
        if (!(Test-Path -Path $OutputDir)) {
            Write-LogFile -Message "[Error] Custom directory invalid: $OutputDir exiting script" -Level Minimal -Color "Red"
        }
    }  

    try {
        $policies = Get-MgIdentityConditionalAccessPolicy -All
        foreach ($policy in $policies) {
            Write-LogFile -Message "[INFO] Processing policy: $($policy.DisplayName)" -Level Standard

            if ($isDebugEnabled) {
                Write-LogFile -Message "[DEBUG] Policy details:" -Level Debug
                Write-LogFile -Message "[DEBUG]   ID: $($policy.Id)" -Level Debug
                Write-LogFile -Message "[DEBUG]   State: $($policy.State)" -Level Debug
                Write-LogFile -Message "[DEBUG]   Created: $($policy.CreatedDateTime)" -Level Debug
                Write-LogFile -Message "[DEBUG]   Modified: $($policy.ModifiedDateTime)" -Level Debug
            }

            $includeUsers = $policy.Conditions.Users.IncludeUsers -join '; '
            $excludeUsers = $policy.Conditions.Users.ExcludeUsers -join '; '
            $includeGroups = $policy.Conditions.Users.IncludeGroups -join '; '
            $excludeGroups = $policy.Conditions.Users.ExcludeGroups -join '; '
            $includeRoles = $policy.Conditions.Users.IncludeRoles -join '; '
            $excludeRoles = $policy.Conditions.Users.ExcludeRoles -join '; '
            
            $includeApplications = $policy.Conditions.Applications.IncludeApplications -join '; '
            $excludeApplications = $policy.Conditions.Applications.ExcludeApplications -join '; '
            
            $includePlatforms = $policy.Conditions.Platforms.IncludePlatforms -join '; '
            $excludePlatforms = $policy.Conditions.Platforms.ExcludePlatforms -join '; '
            
            $includeLocations = $policy.Conditions.Locations.IncludeLocations -join '; '
            $excludeLocations = $policy.Conditions.Locations.ExcludeLocations -join '; '

            $myObject = [PSCustomObject]@{
                # Basic Information
                DisplayName = $policy.DisplayName
                Id = $policy.Id
                State = $policy.State
                CreatedDateTime = $policy.CreatedDateTime
                ModifiedDateTime = $policy.ModifiedDateTime
                Description = $policy.Description

                # Users and Groups
                IncludeUsers = $includeUsers
                ExcludeUsers = $excludeUsers
                IncludeGroups = $includeGroups
                ExcludeGroups = $excludeGroups
                IncludeRoles = $includeRoles
                ExcludeRoles = $excludeRoles

                # Applications
                IncludeApplications = $includeApplications
                ExcludeApplications = $excludeApplications
                ClientAppTypes = ($policy.Conditions.ClientAppTypes -join '; ')

                # Platforms
                IncludePlatforms = $includePlatforms
                ExcludePlatforms = $excludePlatforms

                # Locations
                IncludeLocations = $includeLocations
                ExcludeLocations = $excludeLocations

                # Risk Levels
                UserRiskLevels = ($policy.Conditions.UserRiskLevels -join '; ')
                SignInRiskLevels = ($policy.Conditions.SignInRiskLevels -join '; ')
                ServicePrincipalRiskLevels = ($policy.Conditions.ServicePrincipalRiskLevels -join '; ')

                # Device States
                IncludeDeviceStates = ($policy.Conditions.Devices.IncludeDeviceStates -join '; ')
                ExcludeDeviceStates = ($policy.Conditions.Devices.ExcludeDeviceStates -join '; ')
                DeviceFilter = if ($policy.Conditions.Devices.DeviceFilter.Rule) {
                    "$($policy.Conditions.Devices.DeviceFilter.Mode): $($policy.Conditions.Devices.DeviceFilter.Rule)"
                } else { "Not Configured" }
                
                # Grant Controls
                BuiltInControls = ($policy.GrantControls.BuiltInControls -join '; ')
                CustomAuthenticationFactors = ($policy.GrantControls.CustomAuthenticationFactors -join '; ')
                GrantOperator = $policy.GrantControls.Operator
                TermsOfUse = ($policy.GrantControls.TermsOfUse -join '; ')

                # Session Controls
                ApplicationEnforcedRestrictions = $policy.SessionControls.ApplicationEnforcedRestrictions.IsEnabled
                CloudAppSecurity = $policy.SessionControls.CloudAppSecurity.IsEnabled
                DisableResilienceDefaults = $policy.SessionControls.DisableResilienceDefaults
                PersistentBrowser = $policy.SessionControls.PersistentBrowser.Mode
                SignInFrequency = "$($policy.SessionControls.SignInFrequency.Value) $($policy.SessionControls.SignInFrequency.Type)"

                # Device Controls
                DeviceFilterMode = $policy.Conditions.Devices.DeviceFilter.Mode
                DeviceFilterRule = $policy.Conditions.Devices.DeviceFilter.Rule

                # Additional Conditions
                UserActions = ($policy.Conditions.UserRiskLevels -join '; ')
                ClientAppsV2 = ($policy.Conditions.ClientAppTypes -join '; ')
                DeviceStates = ($policy.Conditions.Devices.DeviceStates -join '; ')
            }

            $results+= $myObject;
        }
    }

    catch {
        Write-logFile -Message "[ERROR] An error occurred: $($_.Exception.Message)"  -Color "Red" -Level Minimal
        if ($isDebugEnabled) {
            Write-LogFile -Message "[DEBUG] Fatal error details:" -Level Debug
            Write-LogFile -Message "[DEBUG]   Exception type: $($_.Exception.GetType().Name)" -Level Debug
            Write-LogFile -Message "[DEBUG]   Full error: $($_.Exception.ToString())" -Level Debug
            Write-LogFile -Message "[DEBUG]   Stack trace: $($_.ScriptStackTrace)" -Level Debug
            Write-LogFile -Message "[DEBUG]   Policies collected before error: $($results.Count)" -Level Debug
        }
        throw
    }

    $date = [datetime]::Now.ToString('yyyyMMddHHmmss') 
    $filePath = "$OutputDir\$($date)-ConditionalAccessPolicy.csv"
    $results | Export-Csv -Path $filePath -NoTypeInformation -Encoding $Encoding

    Write-LogFile -Message "`n=== Conditional Access Policy Summary ===" -Color "Cyan" -Level Standard
    Write-LogFile -Message "Total Policies: $($results.Count)" -Level Standard
    Write-LogFile -Message "Enabled Policies: $(($results | Where-Object { $_.State -eq 'enabled' }).Count)" -Level Standard
    Write-LogFile -Message "Disabled Policies: $(($results | Where-Object { $_.State -eq 'disabled' }).Count)" -Level Standard
    Write-LogFile -Message "Output: $filePath" -Level Standard
    Write-LogFile -Message "===================================" -Color "Cyan" -Level Standard
}
        