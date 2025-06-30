function Get-Devices {
<#
    .SYNOPSIS
    Retrieves information about all devices registered in Entra ID.

    .DESCRIPTION
    Retrieves detailed information about all devices registered in Entra ID, including device status, 
    operating system details, trust type, and management information.

    .PARAMETER OutputDir
    OutputDir is the parameter specifying the output directory.
    Default: Output\Device Information

    .PARAMETER Encoding
    Encoding is the parameter specifying the encoding of the output file.
    Default: UTF8

    .PARAMETER OutputType
    Output is the parameter specifying the type of output file (CSV or JSON).
    Default: CSV

    .PARAMETER UserIds
    UserIds is the UserIds parameter filtering the log entries by the account of the user who performed the actions.

    .PARAMETER LogLevel
    Specifies the level of logging:
    None: No logging
    Minimal: Critical errors only
    Standard: Normal operational logging
    Debug: Verbose logging for debugging purposes
    Default: Standard
    
    .EXAMPLE
    Get-Devices
    Retrieves information about all devices and exports to a CSV file in the default directory.

    .EXAMPLE
    Get-Devices -Output JSON
    Retrieves information about all devices and exports to a JSON file.
        
    .EXAMPLE
    Get-Devices -OutputDir C:\Windows\Temp -Encoding UTF32
    Retrieves device information and saves the output to the C:\Windows\Temp folder with UTF-32 encoding.

    .EXAMPLE
    Get-Devices -OutputDir "Reports" -Output JSON -Encoding UTF8
    Retrieves device information and saves as a JSON file in the Reports folder with UTF-8 encoding.

    .EXAMPLE
    Get-Devices -UserIds "user@domain.com"
    Retrieves information about devices registered to the specified user.
#>
    [CmdletBinding()]
    param (
        [string]$outputDir = "Output\Device Information",
        [string]$Encoding = "UTF8",
        [ValidateSet("CSV", "JSON")]
        [string]$Output = "CSV",
        [ValidateSet('None', 'Minimal', 'Standard', 'Debug')]
        [string]$LogLevel = 'Standard',
        [string]$UserIds
    )

    Set-LogLevel -Level ([LogLevel]::$LogLevel)
    $isDebugEnabled = $script:LogLevel -eq [LogLevel]::Debug
    $date = Get-Date -Format "yyyyMMddHHmm"
    $summary = @{
        TotalDevices = 0
        AzureADJoined = 0
        WorkplaceJoined = 0
        HybridJoined = 0
        ActiveDevices30Days = 0
        InactiveDevices90Days = 0
        CompliantDevices = 0
        ManagedDevices = 0
        Windows = 0
        MacOS = 0
        iOS = 0
        Android = 0
        Other = 0
        StartTime = Get-Date
        ProcessingTime = $null
    }

    if ($isDebugEnabled) {
        Write-LogFile -Message "[DEBUG] PowerShell Version: $($PSVersionTable.PSVersion)" -Level Debug
        Write-LogFile -Message "[DEBUG] Input parameters:" -Level Debug
        Write-LogFile -Message "[DEBUG]   OutputDir: $OutputDir" -Level Debug
        Write-LogFile -Message "[DEBUG]   Encoding: $Encoding" -Level Debug
        Write-LogFile -Message "[DEBUG]   Output: $Output" -Level Debug
        Write-LogFile -Message "[DEBUG]   LogLevel: $LogLevel" -Level Debug
        Write-LogFile -Message "[DEBUG]   UserIds: $UserIds" -Level Debug
        
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

    Write-LogFile -Message "=== Starting Device Collection ===" -Color "Cyan" -Level Standard

    if (!(test-path $OutputDir)) {
        New-Item -ItemType Directory -Force -Path $OutputDir > $null
    }
    else {
        if (!(Test-Path -Path $OutputDir)) {
            Write-LogFile -Message "[Error] Custom directory invalid: $OutputDir exiting script" -Level Minimal -Color "Red"
        }
    }

    $outputFile = "$($date)-Devices.$($Output.ToLower())"
    $outputDirectory = Join-Path $outputDir $outputFile

    $requiredScopes = @("Device.Read.All", "Directory.Read.All")
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

    try {
        write-logFile -Message "[INFO] Collecting device information..." -Level Standard
        $devices = Get-MgDevice -All

        if ($UserIds) {
            $userIdList = $UserIds -split ','
            Write-LogFile -Message "[INFO] Filtering devices for user(s): $UserIds" -Level Standard
            $filteredDevices = @()
            
            foreach ($device in $devices) {
                try {
                    $owners = Get-MgDeviceRegisteredOwner -DeviceId $device.Id -ErrorAction SilentlyContinue
                    $users = Get-MgDeviceRegisteresdUser -DeviceId $device.Id -ErrorAction SilentlyContinue
                } catch {
                    Write-LogFile -Message "[WARNING] Failed to retrieve owners/users for device $($device.DisplayName) (ID: $($device.Id)). Error: $($_.Exception.Message)" -Level Standard -Color "Yellow"
                    if ($isDebugEnabled) {
                        Write-LogFile -Message "[DEBUG] Owner/User retrieval error:" -Level Debug
                        Write-LogFile -Message "[DEBUG]   Device ID: $($device.Id)" -Level Debug
                        Write-LogFile -Message "[DEBUG]   Exception type: $($_.Exception.GetType().Name)" -Level Debug
                        Write-LogFile -Message "[DEBUG]   Full error: $($_.Exception.ToString())" -Level Debug
                    }
                }    

                $matchFound = $false
                foreach ($userId in $userIdList) {
                    if (($owners.AdditionalProperties.userPrincipalName -contains $userId) -or 
                        ($users.AdditionalProperties.userPrincipalName -contains $userId)) {
                        $matchFound = $true
                        break
                    }
                }
                
                if ($matchFound) {
                    $filteredDevices += $device
                }
            }
            
            $devices = $filteredDevices
            Write-LogFile -Message "[INFO] Found $($devices.Count) devices for specified users" -Level Standard
        }

        $results = @()
        $totalDevices = $devices.Count
        $summary.TotalDevices = $totalDevices
        $current = 0

        Write-LogFile -Message "[INFO] Processing $totalDevices devices..." -Level Standard

        foreach ($device in $devices) {
            $current++
            if ($isDebugEnabled) {
                Write-LogFile -Message "[DEBUG] Processing device: $($device.DisplayName) (ID: $($device.Id))" -Level Debug
                Write-LogFile -Message "[DEBUG]   TrustType: $($device.TrustType)" -Level Debug
                Write-LogFile -Message "[DEBUG]   OperatingSystem: $($device.OperatingSystem)" -Level Debug
            }
            if ($LogLevel -eq 'Standard') {
                Write-Progress -Activity "Processing devices" -Status "Processing device $($current) of $($totalDevices)" -PercentComplete (($current / $totalDevices) * 100)
            }

            $createdDateTime = if ($device.AdditionalProperties.createdDateTime) {
                [DateTime]$device.AdditionalProperties.createdDateTime
            } else { "N/A" }

            $lastSignInDate = if ($device.ApproximateLastSignInDateTime) {
                [DateTime]$device.ApproximateLastSignInDateTime
            } else { $null }

            switch ($device.TrustType) {
                "AzureAd" { $summary.AzureADJoined++ }
                "Workplace" { $summary.WorkplaceJoined++ }
                "ServerAd" { $summary.HybridJoined++ }
            }

            if ($device.IsCompliant) { $summary.CompliantDevices++ }
            if ($device.IsManaged) { $summary.ManagedDevices++ }

            if ($lastSignInDate -gt (Get-Date).AddDays(-30)) {
                $summary.ActiveDevices30Days++
            }
            if ($lastSignInDate -lt (Get-Date).AddDays(-90)) {
                $summary.InactiveDevices90Days++
            }

            switch -Wildcard ($device.OperatingSystem) {
                "Windows*" { $summary.Windows++ }
                "Mac*" { $summary.MacOS++ }
                "iOS*" { $summary.iOS++ }
                "Android*" { $summary.Android++ }
                default { $summary.Other++ }
            }

            $deviceEntry = [PSCustomObject]@{
                CreatedDateTime = if ($createdDateTime -ne "N/A") { $createdDateTime.ToString("yyyy-MM-dd HH:mm:ss") } else { "" }
                DeviceId = $device.DeviceId
                ObjectId = $device.Id
                AccountEnabled = $device.AccountEnabled
                DeviceOwnership = if ($device.DeviceOwnership) { $device.DeviceOwnership } else { "" }
                DisplayName = $device.DisplayName
                EnrollmentType = if ($device.EnrollmentType) { $device.EnrollmentType } else { "" }
                IsCompliant = $device.IsCompliant
                IsManaged = $device.IsManaged
                IsRooted = if ($null -ne $device.IsRooted) { $device.IsRooted } else { "" }
                ManagementType = if ($device.ManagementType) { $device.ManagementType } else { "" }
                DeviceCategory = if ($device.DeviceCategory) { $device.DeviceCategory } else { "" }
                OperatingSystem = $device.OperatingSystem
                OperatingSystemVersion = $device.OperatingSystemVersion
                Manufacturer = if ($device.Manufacturer) { $device.Manufacturer } else { "" }
                Model = if ($device.Model) { $device.Model } else { "" }
                LastSignInDateTime = if ($device.ApproximateLastSignInDateTime) { 
                    (Get-Date $device.ApproximateLastSignInDateTime).ToString("yyyy-MM-dd HH:mm:ss") 
                } else { "" }
                TrustType = $device.TrustType
                RegisteredOwners = $ownersList
                RegisteredUsers = $usersList
                MDMAppId = if ($device.MDMAppId) { $device.MDMAppId } else { "" }
                OnPremisesSyncEnabled = $device.OnPremisesSyncEnabled
                ProfileType = $device.ProfileType
                SecurityIdentifier = if ($device.SecurityIdentifier) { $device.SecurityIdentifier } else { "" }
            }

            $results += $deviceEntry
        }

        if ($Output -eq "CSV") {
            $results | Export-Csv -Path $outputDirectory -NoTypeInformation -Encoding $Encoding
        } else {
            $results | ConvertTo-Json -Depth 100 | Out-File $outputDirectory -Encoding $Encoding
        }

        $summary.ProcessingTime = (Get-Date) - $summary.StartTime

        Write-LogFile -Message "`n=== Device Analysis Summary ===" -Color "Cyan" -Level Standard
        Write-LogFile -Message "Device Counts:" -Level Standard
        Write-LogFile -Message "  Total Devices: $($summary.TotalDevices)" -Level Standard
        Write-LogFile -Message "  Entra ID Joined: $($summary.AzureADJoined)" -Level Standard
        Write-LogFile -Message "  Workplace Joined: $($summary.WorkplaceJoined)" -Level Standard
        Write-LogFile -Message "  Hybrid Joined: $($summary.HybridJoined)" -Level Standard

        Write-LogFile -Message "`nDevice Status:" -Level Standard
        Write-LogFile -Message "  Compliant Devices: $($summary.CompliantDevices)" -Level Standard
        Write-LogFile -Message "  Managed Devices: $($summary.ManagedDevices)" -Level Standard
        Write-LogFile -Message "  Active (Last 30 Days): $($summary.ActiveDevices30Days)" -Level Standard
        Write-LogFile -Message "  Inactive (>90 Days): $($summary.InactiveDevices90Days)" -Level Standard

        Write-LogFile -Message "`nOperating Systems:" -Level Standard
        Write-LogFile -Message "  Windows: $($summary.Windows)" -Level Standard
        Write-LogFile -Message "  macOS: $($summary.MacOS)" -Level Standard
        Write-LogFile -Message "  iOS: $($summary.iOS)" -Level Standard
        Write-LogFile -Message "  Android: $($summary.Android)" -Level Standard
        Write-LogFile -Message "  Other: $($summary.Other)" -Level Standard

        Write-LogFile -Message "`nExport Details:" -Level Standard
        Write-LogFile -Message "  Output File: $outputDirectory" -Level Standard
        Write-LogFile -Message "  Processing Time: $($summary.ProcessingTime.ToString('mm\:ss'))" -Color "Green" -Level Standard
        Write-LogFile -Message "===================================" -Color "Cyan" -Level Standard
    }
    catch {
        write-logFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Color "Red"
        if ($isDebugEnabled) {
            Write-LogFile -Message "[DEBUG] Fatal error details:" -Level Debug
            Write-LogFile -Message "[DEBUG]   Exception type: $($_.Exception.GetType().Name)" -Level Debug
            Write-LogFile -Message "[DEBUG]   Full error: $($_.Exception.ToString())" -Level Debug
            Write-LogFile -Message "[DEBUG]   Stack trace: $($_.ScriptStackTrace)" -Level Debug
            Write-LogFile -Message "[DEBUG]   Devices collected before error: $($results.Count)" -Level Debug
        }
        throw
    }
}