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
        [string]$OutputDir = "Output\Users",
        [string]$Encoding = "UTF8"
    )

    $requiredScopes = @("User.Read.All")
    $graphAuth = Get-GraphAuthType -RequiredScopes $RequiredScopes

    if (!(test-path $OutputDir)) {
        New-Item -ItemType Directory -Force -Name $OutputDir > $null
        write-logFile -Message "[INFO] Creating the following directory: $OutputDir"
    }
    else {
		if (Test-Path -Path $OutputDir) {
			write-LogFile -Message "[INFO] Custom directory set to: $OutputDir"
		}
		else {
			write-Error "[Error] Custom directory invalid: $OutputDir exiting script" -ErrorAction Stop
			write-LogFile -Message "[Error] Custom directory invalid: $OutputDir exiting script"
		}
	}

    Write-logFile -Message "[INFO] Running Get-Users" -Color "Green"

    try {
        $selectobjects = "Id","AccountEnabled","DisplayName","UserPrincipalName","Mail","CreatedDateTime","LastPasswordChangeDateTime","DeletedDateTime","JobTitle","Department","OfficeLocation","City","State","Country"
        $mgUsers = Get-MgUser -All -Select $selectobjects 
        write-host "A total of $($mgUsers.count) users found:" 

        $date = (Get-Date).AddDays(-7)
        $oneweekold = $mgUsers | Where-Object {
            $_.CreatedDateTime -gt $date
        }
        write-host "  - $($oneweekold.count) users created within the last 7 days."

        $date = (Get-Date).AddDays(-30)
        $onemonthold = $mgUsers | Where-Object {
            $_.CreatedDateTime -gt $date
        }
        write-host "  - $($onemonthold.count) users created within the last 30 days."

        $date = (Get-Date).AddDays(-90)
        $threemonthold = $mgUsers | Where-Object {
            $_.CreatedDateTime -gt $date
        }
        write-host "  - $($threemonthold.count) users created within the last 90 days."

        $date = (Get-Date).AddDays(-180)
        $sixmonthold = $mgUsers | Where-Object {
            $_.CreatedDateTime -gt $date
        }
        write-host "  - $($sixmonthold.count) users created within the last 6 months."

        $date = (Get-Date).AddDays(-360)
        $sixmonthold = $mgUsers | Where-Object {
            $_.CreatedDateTime -gt $date
        }
        write-host "  - $($sixmonthold.count) users created within the last 1 year."

        Get-MgUser | Get-Member > $null

        $date = Get-Date -Format "yyyyMMddHHmm"
        $filePath = "$OutputDir\$($date)-Users.csv"
        
        $mgUsers | select-object $selectobjects | Export-Csv -Path $filePath -NoTypeInformation -Encoding $Encoding
    }
    catch {
        Write-logFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Color "Red"
        throw
    }
    
    Write-logFile -Message "[INFO] Output written to $filePath" -Color "Green"
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
        [string]$outputDir = "Output\Admins",
        [string]$Encoding = "UTF8"
    )

    $requiredScopes = @("User.Read.All", "Directory.Read.All")
    $graphAuth = Get-GraphAuthType -RequiredScopes $RequiredScopes
    
    if (!(test-path $OutputDir)) {
        New-Item -ItemType Directory -Force -Name $OutputDir > $null
        write-logFile -Message "[INFO] Creating the following directory: $OutputDir"
    }
    else {
		if (Test-Path -Path $OutputDir) {
			write-LogFile -Message "[INFO] Custom directory set to: $OutputDir"
		}
		else {
			write-Error "[Error] Custom directory invalid: $OutputDir exiting script" -ErrorAction Stop
			write-LogFile -Message "[Error] Custom directory invalid: $OutputDir exiting script"
		}
	}
    
    Write-logFile -Message "[INFO] Running Get-AdminUsers" -Color "Green"
    try {
        $getRoles = Get-MgDirectoryRole -all
        foreach ($role in $getRoles) {
            $roleId = $role.Id
            $roleName = $role.DisplayName

            if ($roleName -like "*Admin*") {
                $areThereUsers = Get-MgDirectoryRoleMember -DirectoryRoleId $roleId

                if ($null -eq $areThereUsers) {
                    write-host "[INFO] $roleName - No users found"
                }

                else {
                    $results=@();

                    $count = 0
                    foreach ($user in $areThereUsers) {
                        $userid = $user.Id

                        if ($userid -eq ".") {
                            write-host "."
                        }
                        
                        else {
                            $count = $count +1
                            try{
                                $getUserName = Get-MgUser -Filter ("Id eq '$userid'") -ErrorAction Stop
                                $userName = $getUserName.UserPrincipalName
                                $userid = $getUserName.Id

                                $myObject = [PSCustomObject]@{
                                    UserName = $userName
                                    UserId = $userid
                                    Role = $roleName
                                }

                                $results+= $myObject;
                            }
                            catch{
                                Write-logFile -Message "[INFO] Resource $userid does not exist or one of its queried reference-property objects are not present." -Color "Yellow"
                            }
                        }
                    }

                    Write-logFile -Message "[info] $roleName - $count users found" -Color "Yellow"
                    $filePath = "$OutputDir\$($date)-$roleName.csv"
                    $results | Export-Csv -Path $filePath -NoTypeInformation -Encoding $Encoding
                    Write-logFile -Message "[INFO] Output written to $filePath" -Color "Green"
                }
            }
        }
    }
    catch {
        Write-logFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Color "Red"
        throw
    }

    $outputDirMerged = "$OutputDir\Merged\"
    If (!(test-path $outputDirMerged)) {
        Write-LogFile -Message "[INFO] Creating the following directory: $outputDirMerged"
        New-Item -ItemType Directory -Force -Path $outputDirMerged > $null
    }
    
    Write-LogFile -Message "[INFO] Merging Administrator CSV Ouput Files" -Color "Green"
    $date = Get-Date -Format "yyyyMMddHHmm"
    Get-ChildItem $OutputDir -Filter "*Administrator.csv" | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv "$outputDirMerged/$($date)-All-Administrators.csv" -NoTypeInformation -Append  
}

Function Get-UserDevices {
    <#
        .SYNOPSIS
        Retrieves devices registered for each user in Azure AD with detailed device information.
    
        .DESCRIPTION
        Retrieves devices registered to users in Azure AD, including key properties like `accountEnabled`, `approximateLastSignInDateTime`, `createdDateTime`, `displayName`, `operatingSystem`, and `operatingSystemVersion`. Outputs the results to a CSV file.
    
        .PARAMETER OutputDir
        Specifies the directory where output files will be saved.
        Default: Output\Devices
    
        .PARAMETER Encoding
        Specifies the encoding for the CSV output file.
        Default: UTF8
    
        .EXAMPLE
        Get-UserDevices
        Retrieves detailed device information for all users in Azure AD.
    
        .EXAMPLE
        Get-UserDevices -Encoding utf32
        Retrieves device details and exports the output in UTF-32 encoding.
    
        .EXAMPLE
        Get-UserDevices -OutputDir C:\Temp
        Retrieves device details and saves the output in the C:\Temp directory.
    #>
    
        [CmdletBinding()]
        param(
            [string]$OutputDir = "Output\Users",
            [string]$Encoding = "UTF8"
        )
    
        $requiredScopes = @("User.Read.All", "Directory.Read.All", "Device.Read.All")
        $graphAuth = Get-GraphAuthType -RequiredScopes $requiredScopes
    
        if (!(Test-Path -Path $OutputDir)) {
            New-Item -ItemType Directory -Force -Path $OutputDir > $null
            Write-Logfile -Message "[INFO] Creating the following directory: $OutputDir"
        }
        else {
            Write-Logfile -Message "[INFO] Using existing directory: $OutputDir"
        }
    
        Write-Logfile -Message "[INFO] Running Get-UserDevices" -Color "Green"
    
        try {
            $users = Get-MgUser -All -Property Id, DisplayName
            $results = @()
    
            foreach ($user in $users) {
                Write-Logfile -Message "[INFO] Fetching devices for user: $($user.DisplayName)"
                try {
                    $devices = Get-MgUserRegisteredDevice -UserId $user.Id -All
    
                    foreach ($device in $devices) {
                        $results += [PSCustomObject]@{
                            UserName                    = $user.DisplayName
                            UserId                      = $user.Id
                            DeviceName                  = $device.AdditionalProperties.displayName
                            OperatingSystem             = $device.AdditionalProperties.operatingSystem
                            OperatingSystemVersion      = $device.AdditionalProperties.operatingSystemVersion
                            AccountEnabled              = $device.AdditionalProperties.accountEnabled
                            ApproximateLastSignInDate   = $device.AdditionalProperties.approximateLastSignInDateTime
                            CreatedDateTime             = $device.AdditionalProperties.createdDateTime
                        }
                    }
                }
                catch {
                    Write-Logfile -Message "[WARNING] Failed to retrieve devices for user: $($user.DisplayName)" -Color "Yellow"
                }
            }
    
            $date = Get-Date -Format "yyyyMMddHHmm"
            $filePath = "$OutputDir\$($date)-UserDevices.csv"
            $results | Export-Csv -Path $filePath -NoTypeInformation -Encoding $Encoding
            Write-Logfile -Message "[INFO] Output written to $filePath" -Color "Green"
        }
        catch {
            Write-Logfile -Message "[ERROR] An error occurred: $($_.Exception.Message)"
            throw
        }
    
        $outputDirMerged = "$OutputDir\Merged\"
        if (!(Test-Path -Path $outputDirMerged)) {
            Write-Logfile -Message "[INFO] Creating the following directory: $outputDirMerged"
            New-Item -ItemType Directory -Force -Path $outputDirMerged > $null
        }
    
        Write-Logfile -Message "[INFO] Merging User Device CSV Output Files" -Color 'Green'
        $date = Get-Date -Format "yyyyMMddHHmm"
        Get-ChildItem $OutputDir -Filter "*UserDevices.csv" | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv "$outputDirMerged/$($date)-All-UserDevices.csv" -NoTypeInformation -Append
}    
