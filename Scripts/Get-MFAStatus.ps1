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
    
  .EXAMPLE
  Get-MFA
	Retrieves the MFA status for all users.
	
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
        [string]$Encoding
    )

    try {
        $areYouConnected = Get-MgUser -ErrorAction stop
    }
    catch {
        Write-logFile -Message "[WARNING] You must call Connect-GraphAPI before running this script" -Color "Red"
        break
    }

    if ($Encoding -eq "" ){
        $Encoding = "UTF8"
    }

    if ($OutputDir -eq "" ){
        $OutputDir = "Output\UserInfo\"
        if (!(test-path $OutputDir)) {
            write-logFile -Message "[INFO] Creating the following directory: $OutputDir"
            New-Item -ItemType Directory -Force -Name $OutputDir | Out-Null
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
            MFAstatus          = "_"
            email              = "-"
            fido2              = "-"
            app                = "-"
            password           = "-"
            phone              = "-"
            softwareoath       = "-"
            tempaccess         = "-"
            hellobusiness      = "-"
        }

        $MFAData=Get-MgUserAuthenticationMethod -UserId $user.UserPrincipalName

        $myobject.user = $user.UserPrincipalName;
        ForEach ($method in $MFAData) {
      
            Switch ($method.AdditionalProperties["@odata.type"]) {
                "#microsoft.graph.emailAuthenticationMethod"  { 
                $myObject.email = $true 
                $myObject.MFAstatus = "Enabled"
                $MFAEmail = $MFAEmail + 1
              }

                "#microsoft.graph.fido2AuthenticationMethod"                   { 
                $myObject.fido2 = $true 
                $myObject.MFAstatus = "Enabled"
                $MFAfido2 = $MFAfido2 + 1
              }

                "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod"  { 
                $myObject.app = $true 
                $myObject.MFAstatus = "Enabled"
                $MFAapp = $MFAapp + 1
              }

                "#microsoft.graph.passwordAuthenticationMethod"                {              
                $myObject.password = $true 
                if($myObject.MFAstatus -ne "Enabled"){
                    $myObject.MFAstatus = "Disabled"
                }                
              }

                "#microsoft.graph.phoneAuthenticationMethod"  { 
                $myObject.phone = $true 
                $myObject.MFAstatus = "Enabled"
                $MFAphone = $MFAphone + 1
              }

                "#microsoft.graph.softwareOathAuthenticationMethod"  { 
                $myObject.softwareoath = $true 
                $myObject.MFAstatus = "Enabled"
                $MFAsoftwareoath = $MFAsoftwareoath + 1
              }

                "#microsoft.graph.temporaryAccessPassAuthenticationMethod"  { 
                $myObject.tempaccess = $true 
                $myObject.MFAstatus = "Enabled"
                $MFAtempaccess = $MFAtempaccess + 1
              }

                "#microsoft.graph.windowsHelloForBusinessAuthenticationMethod"  { 
                $myObject.hellobusiness = $true 
                $myObject.MFAstatus = "Enabled"
                $MFAhellobusiness = $MFAhellobusiness + 1
              }  
            
            }
            if($myObject.MFAstatus -eq "Enabled") {
                $MFAstatusAmount = $MFAstatusAmount + 1
            }
        }

        $results+= $myObject;
    }

    write-host "$MFAstatusAmount out of $($users.count) users have MFA enabled:"
    write-host "  - $MFAEmail x Email"
    write-host "  - $MFAfido2 x Fido2"
    write-host "  - $MFAapp x App"
    write-host "  - $MFAphone x Phone"
    write-host "  - $MFAsoftwareoath x SoftwareOAuth"
    write-host "  - $MFAtempaccess x TempAccess"
    write-host "  - $MFAhellobusiness x HelloBusiness"

    $filePath = "$OutputDir\MFAStatus.csv"
    $results | Export-Csv -Path $filePath -NoTypeInformation -Encoding $Encoding
    Write-logFile -Message "[INFO] Output written to $filePath" -Color "Green"
}