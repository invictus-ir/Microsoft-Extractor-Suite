function Get-MFA {
<#
    .SYNOPSIS
    Retrieves the MFA status for all users.
    Script inspired by: https://activedirectorypro.com/mfa-status-powershell/

    .DESCRIPTION
    Retrieves the MFA status for all users.
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
    Get-MFA
    Retrieves the MFA status for all users.

    .EXAMPLE
    Get-MFA
    Retrieves the MFA status for all users via application authentication.
	
    .EXAMPLE
    Get-MFA -Encoding utf32
    Retrieves the MFA status for all users and exports the output to a CSV file with UTF-32 encoding.
		
    .EXAMPLE
    Get-MFA -OutputDir C:\Windows\Temp
    Retrieves the MFA status for all users and saves the output to the C:\Windows\Temp folder.	
#>
    [CmdletBinding()]
    param(
        [string]$OutputDir,
        [string]$Encoding,
        [switch]$Application
    )

    if (!($Application.IsPresent)) {
        Connect-MgGraph -Scopes UserAuthenticationMethod.Read.All,User.Read.All -NoWelcome
    }

    try {
        $areYouConnected = Get-MgUser -ErrorAction stop 
    }
    catch {
        Write-logFile -Message "[WARNING] You must call Connect-MgGraph -Scopes 'UserAuthenticationMethod.Read.All,User.Read.All' before running this script" -Color "Red"
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
  
    Write-logFile -Message "[INFO] Running Get-MFA" -Color "Green"
    
    $users = Get-MgUser -All

    $MFAEmail = 0
    $MFAfido2 = 0
    $MFAapp = 0
    $MFAphone = 0
    $MFAsoftwareoath = 0
    $MFAtempaccess = 0
    $MFAhellobusiness = 0
    $MFAstatusAmount = 0

    $results=@();

    foreach ($user in $users) {

        $myObject = [PSCustomObject]@{
            user               = "-"
            MFAstatus          = "Disabled"  # Default to 'Disabled'
            email              = "-"
            fido2              = "-"
            app                = "-"
            password           = "-"
            phone              = "-"
            softwareoath       = "-"
            tempaccess         = "-"
            hellobusiness      = "-"
        }

        $MFAData= Get-MgUserAuthenticationMethod -UserId $user.UserPrincipalName

        $myobject.user = $user.UserPrincipalName;
        ForEach ($method in $MFAData) {
      
            Switch ($method.AdditionalProperties["@odata.type"]) {
                "#microsoft.graph.emailAuthenticationMethod" { 
                $myObject.email = $true 
                $myObject.MFAstatus = "Enabled"
                }

                "#microsoft.graph.fido2AuthenticationMethod" { 
                $myObject.fido2 = $true 
                $myObject.MFAstatus = "Enabled"
              }

                "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod" { 
                $myObject.app = $true 
                $myObject.MFAstatus = "Enabled"
              }

                "#microsoft.graph.passwordAuthenticationMethod" {              
                $myObject.password = $true 
                if($myObject.MFAstatus -ne "Enabled"){
                    $myObject.MFAstatus = "Disabled"
                }                
              }

                "#microsoft.graph.phoneAuthenticationMethod" { 
                $myObject.phone = $true 
                $myObject.MFAstatus = "Enabled"
              }

                "#microsoft.graph.softwareOathAuthenticationMethod" { 
                $myObject.softwareoath = $true 
                $myObject.MFAstatus = "Enabled"
              }

                "#microsoft.graph.temporaryAccessPassAuthenticationMethod" { 
                $myObject.tempaccess = $true 
                $myObject.MFAstatus = "Enabled"
              }

                "#microsoft.graph.windowsHelloForBusinessAuthenticationMethod" { 
                $myObject.hellobusiness = $true 
                $myObject.MFAstatus = "Enabled"
              }  
            
            }
        }
		
		if($myObject.MFAstatus -eq "Enabled") {
            $MFAstatusAmount++
        }

        $results+= $myObject;
    }
	
	$filePath = "$OutputDir\MFAStatus.csv"
    $results | Export-Csv -Path $filePath -NoTypeInformation -Encoding $Encoding
    Write-logFile -Message "[INFO] Output written to $filePath" -Color "Green"
	
	$MFAEmail = (Import-Csv -Path "$filePath" -Delimiter "," | Where-Object { $_.email -eq "True" } | Measure-Object).Count
	$MFAfido2 = (Import-Csv -Path "$filePath" -Delimiter "," | Where-Object { $_.fido2 -eq "True" } | Measure-Object).Count
	$MFAapp = (Import-Csv -Path "$filePath" -Delimiter "," | Where-Object { $_.app -eq "True" } | Measure-Object).Count
	$MFAphone = (Import-Csv -Path "$filePath" -Delimiter "," | Where-Object { $_.phone -eq "True" } | Measure-Object).Count
	$MFAsoftwareoath = (Import-Csv -Path "$filePath" -Delimiter "," | Where-Object { $_.softwareoath -eq "True" } | Measure-Object).Count
	$MFAtempaccess = (Import-Csv -Path "$filePath" -Delimiter "," | Where-Object { $_.tempaccess -eq "True" } | Measure-Object).Count
	$MFApassword = (Import-Csv -Path "$filePath" -Delimiter "," | Where-Object { $_.password -eq "True" } | Measure-Object).Count
	$MFAhellobusiness = (Import-Csv -Path "$filePath" -Delimiter "," | Where-Object { $_.hellobusiness -eq "True" } | Measure-Object).Count
	$MFAstatusAmount = (Import-Csv -Path "$filePath" -Delimiter "," | Where-Object { $_.MFAstatus -eq "Enabled" } | Measure-Object).Count

    write-host "$MFAstatusAmount out of $($users.count) users have MFA enabled:"
    write-host "  - $MFAEmail x Email"
    write-host "  - $MFAfido2 x Fido2"
    write-host "  - $MFAapp x App"
    write-host "  - $MFAphone x Phone"
    write-host "  - $MFAsoftwareoath x SoftwareOAuth"
    write-host "  - $MFAtempaccess x TempAccess"
    write-host "  - $MFAhellobusiness x HelloBusiness"  
}