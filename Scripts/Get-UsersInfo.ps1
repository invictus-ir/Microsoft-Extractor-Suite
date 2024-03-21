function Get-Users {
<#
    .SYNOPSIS
    Retrieves the creation time and date of the last password change for all users.
    Script inspired by: https://github.com/tomwechsler/Microsoft_Graph/blob/main/Entra_ID/Create_time_last_password.ps1

    .DESCRIPTION
    Retrieves the creation time and date of the last password change for all users.
    The output will be written to: Output\UserInfo\

    .PARAMETER OutputDir
    OutputDir is the parameter specifying the output directory.
    Default: Output\UserInfo

    .PARAMETER Encoding
    Encoding is the parameter specifying the encoding of the CSV output file.
    Default: UTF8

    .PARAMETER Application
    Application is the parameter specifying App-only access (access without a user) for authentication and authorization.
    Default: Delegated access (access on behalf a user)
    
    .EXAMPLE
    Get-Users
    Retrieves the creation time and date of the last password change for all users.

    .EXAMPLE
    Get-Users -Application
    Retrieves the creation time and date of the last password change for all users via application authentication.
	
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
        [string]$Encoding,
        [switch]$Application
    )

    if (!($Application.IsPresent)) {
        Connect-MgGraph -Scopes User.Read.All, Directory.AccessAsUser.All, User.ReadBasic.All, Directory.Read.All -NoWelcome
    }

    try {
        $areYouConnected = Get-MgUser -ErrorAction stop
    }
    catch {
        Write-logFile -Message "[WARNING] You must call Connect-MgGraph -Scopes 'User.Read.All, Directory.AccessAsUser.All, User.ReadBasic.All, Directory.Read.All' before running this script" -Color "Red"
        break
    }

    if ($Encoding -eq "" ){
		$Encoding = "UTF8"
	}

    if ($OutputDir -eq "" ){
        $OutputDir = "Output\UserInfo"
        if (!(test-path $OutputDir)) {
            New-Item -ItemType Directory -Force -Name $OutputDir | Out-Null
            write-logFile -Message "[INFO] Creating the following directory: $OutputDir"
        }
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

    Get-MgUser | Get-Member | out-null

    $date = Get-Date -Format "yyyyMMddHHmm"
    $filePath = "$OutputDir\$($date)-Users.csv"
    
    $mgUsers | select-object $selectobjects | Export-Csv -Path $filePath -NoTypeInformation -Encoding $Encoding
    
    Write-logFile -Message "[INFO] Output written to $filePath" -Color "Green"
}

Function Get-AdminUsers {
<#
    .SYNOPSIS
    Retrieves all Administrator directory roles.

    .DESCRIPTION
    Retrieves Administrator directory roles, including the identification of users associated with each specific role.
	The output will be written to: Output\UserInfo\

	.PARAMETER OutputDir
	OutputDir is the parameter specifying the output directory.
	Default: Output\UserInfo

	.PARAMETER Encoding
    Encoding is the parameter specifying the encoding of the CSV output file.
	Default: UTF8

    .PARAMETER Application
    Application is the parameter specifying App-only access (access without a user) for authentication and authorization.
    Default: Delegated access (access on behalf a user)
    
    .EXAMPLE
    Get-AdminUsers
	Retrieves Administrator directory roles, including the identification of users associated with each specific role.
	
    .EXAMPLE
    Get-AdminUsers -Application
    Retrieves Administrator directory roles, including the identification of users associated with each specific role via application authentication.

	.EXAMPLE
	Get-AdminUsers -Encoding utf32
	Retrieves Administrator directory roles, including the identification of users associated with each specific role and exports the output to a CSV file with UTF-32 encoding.
		
	.EXAMPLE
	Get-AdminUsers -OutputDir C:\Windows\Temp
	Retrieves Administrator directory roles, including the identification of users associated with each specific role and saves the output to the C:\Windows\Temp folder.	
#>    

    [CmdletBinding()]
    param(
        [string]$outputDir,
        [string]$Encoding,
        [switch]$Application
    )

    if (!($Application.IsPresent)) {
        Connect-MgGraph -Scopes User.Read.All, Directory.AccessAsUser.All, Directory.Read.All -NoWelcome
    }

    try {
        $areYouConnected = Get-MgDirectoryRole -ErrorAction stop
    }
    catch {
        Write-logFile -Message "[WARNING] You must call Connect-MgGraph -Scopes 'User.Read.All, Directory.AccessAsUser.All, Directory.Read.All' before running this script" -Color "Red"
        break
    }
    
    if ($Encoding -eq "" ){
        $Encoding = "UTF8"
    }

    if ($OutputDir -eq "" ){
        $OutputDir = "Output\UserInfo"
        if (!(test-path $OutputDir)) {
            New-Item -ItemType Directory -Force -Name $OutputDir | Out-Null
            write-logFile -Message "[INFO] Creating the following directory: $OutputDir"
        }
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

                $myObject = [PSCustomObject]@{
                    UserName          = "-"
                    UserId            = "_"
                    Role              = "-"
                }

                $count = 0
                $areThereUsers | ForEach-Object {

                    $userid = $_.Id

                    if ($userid -eq ".") {
                        write-host "."
                    }
                    
                    else {
                        $count = $count +1
                        try{
                            $getUserName = Get-MgUser -Filter ("Id eq '$userid'")
                            $userName = $getUserName.UserPrincipalName

                            $myObject.UserName = $userName
                            $myObject.UserId = $userid
                            $myObject.Role = $roleName

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

    $outputDirMerged = "$OutputDir\Merged\"
    If (!(test-path $outputDirMerged)) {
        Write-LogFile -Message "[INFO] Creating the following directory: $outputDirMerged"
        New-Item -ItemType Directory -Force -Path $outputDirMerged | Out-Null
    }
    
    Write-LogFile -Message "[INFO] Merging Administrator CSV Ouput Files" -Color "Green"
    Get-ChildItem $OutputDir -Filter "*Administrator.csv" | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv "$outputDirMerged/All-Administrators.csv" -NoTypeInformation -Append  
}