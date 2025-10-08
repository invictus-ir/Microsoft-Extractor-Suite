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
        [string]$OutputDir,
        [string]$Encoding = "UTF8",
        [ValidateSet("CSV", "JSON")]
        [string]$Output = "CSV",
        [ValidateSet('None', 'Minimal', 'Standard', 'Debug')]
        [string]$LogLevel = 'Standard',
        [string]$UserIds
    )

    Init-Logging
    if ($OutputDir) {
        Init-OutputDir -Component "Device Information" -FilePostfix "Devices" -CustomOutputDir $OutputDir
    } else {
        Init-OutputDir -Component "Device Information" -FilePostfix "Devices"
    }
    Write-LogFile -Message "=== Starting Device Collection ===" -Color "Cyan" -Level Standard
    
	$requiredScopes = @("Application.Read.All")
    Check-GraphContext -RequiredScopes $requiredScopes

    $date = Get-Date -Format "yyyyMMddHHmm"
    $summary = [ordered]@{
        "Device Counts" = [ordered]@{
            "Total Devices" = 0
            "Entra ID Joined" = 0
            "Workplace Joined" = 0
            "Hybrid Joined" = 0
        }
        "Device Status" = [ordered]@{
            "Compliant Devices" = 0
            "Managed Devices" = 0
            "Active (Last 30 Days)" = 0
            "Inactive (>90 Days)" = 0
        }
        "Operating Systems" = [ordered]@{
            "Windows" = 0
            "macOS" = 0
            "iOS" = 0
            "Android" = 0
            "Other" = 0
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
                    $users = Get-MgDeviceRegisteredUser -DeviceId $device.Id -ErrorAction SilentlyContinue
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
        $summary["Device Counts"]["Total Devices"] = $totalDevices
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
                "AzureAd" { $summary["Device Counts"]["Entra ID Joined"]++ }
                "Workplace" { $summary["Device Counts"]["Workplace Joined"]++ }
                "ServerAd" { $summary["Device Counts"]["Hybrid Joined"]++ }
            }

            if ($device.IsCompliant) { $summary["Device Status"]["Compliant Devices"]++ }
            if ($device.IsManaged) { $summary["Device Status"]["Managed Devices"]++ }

            if ($lastSignInDate -gt (Get-Date).AddDays(-30)) {
                $summary["Device Status"]["Active (Last 30 Days)"]++
            }
            if ($lastSignInDate -lt (Get-Date).AddDays(-90)) {
                $summary["Device Status"]["Inactive (>90 Days)"]++
            }

            switch -Wildcard ($device.OperatingSystem) {
                "Windows*" { $summary["Operating Systems"]["Windows"]++ }
                "Mac*" { $summary["Operating Systems"]["macOS"]++ }
                "iOS*" { $summary["Operating Systems"]["iOS"]++ }
                "Android*" { $summary["Operating Systems"]["Android"]++ }
                default { $summary["Operating Systems"]["Other"]++ }
            }

            $ownersList = ($owners.AdditionalProperties.userPrincipalName -join "; ")
            $usersList = ($users.AdditionalProperties.userPrincipalName -join "; ")

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
            $results | Export-Csv -Path $script:outputFile -NoTypeInformation -Encoding $Encoding
        } else {
            $results | ConvertTo-Json -Depth 100 | Out-File $script:outputFile -Encoding $Encoding
        }

        Write-Progress -Activity "Processing devices" -Completed
        Write-Summary -Summary $summary -Title "Device Analysis Summary"
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