function Get-MFA {
    <#
        .SYNOPSIS
        Retrieves the MFA status for all users.
        Script inspired by: https://activedirectorypro.com/mfa-status-powershell/
    
        .DESCRIPTION
        Retrieves the MFA status for all users.
    
        .PARAMETER OutputDir
        OutputDir is the parameter specifying the output directory.
        Default: Output\MFA
    
        .PARAMETER Encoding
        Encoding is the parameter specifying the encoding of the CSV output file.
        Default: UTF8
        
        .EXAMPLE
        Get-MFA
        Retrieves the MFA status for all users.
    
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
        [string]$OutputDir = "Output\MFA",
        [string]$Encoding = "UTF8"
    )

    $authType = Get-GraphAuthType
    if ($authType -eq "Delegated") {
        Connect-MgGraph -Scopes UserAuthenticationMethod.Read.All,User.Read.All > $null
    }

    if (!(Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Force -Path $OutputDir > $null
        Write-LogFile -Message "[INFO] Creating the following directory: $OutputDir"
    }
  
    Write-LogFile -Message "[INFO] Running Get-MFA"
    Write-LogFile -Message "[INFO] Identifying all the authentication methods utilized within the environment" -Color "Green"     
  
    $results = @()
    $allUsers = @()
    $nextLink = "https://graph.microsoft.com/v1.0/users"

    do {
        $response = Invoke-MgGraphRequest -Uri $nextLink -Method Get -OutputType PSObject
        $allUsers += $response.value
        $nextLink = $response.'@odata.nextLink'
    } while ($nextLink)

    $MFAEmail = 0
    $MFAfido2 = 0
    $MFAapp = 0
    $MFAphone = 0
    $MFAsoftwareoath = 0
    $MFAhellobusiness = 0
    $MFAstatusAmount = 0
  
    foreach ($user in $allUsers) {  
        $userPrinc = $user.userPrincipalName
        $myObject = [PSCustomObject]@{
            user               = $userPrinc
            MFAstatus          = "Disabled"  # Default to 'Disabled'
            email              = $false
            fido2              = $false
            app                = $false
            password           = $false
            phone              = $false
            softwareoath       = $false
            hellobusiness      = $false
            temporaryAccessPass = $false
            certificateBasedAuthConfiguration = $false
        }
  
        try {
            $contentUri = "https://graph.microsoft.com/v1.0/users/$($user.id)/authentication/methods"
            $MFAData = Invoke-MgGraphRequest -Uri $contentUri -Method Get -OutputType PSObject
            if ($MFAData -and $MFAData.value) {
                ForEach ($method in $MFAData.value) {
                    $odataType = $method.'@odata.type'
                    
                    Switch ($odataType) {
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
                            if ($myObject.MFAstatus -ne "Enabled") {
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
                        "#microsoft.graph.windowsHelloForBusinessAuthenticationMethod" { 
                            $myObject.hellobusiness = $true 
                            $myObject.MFAstatus = "Enabled"
                        }
                        "#microsoft.graph.temporaryAccessPassAuthenticationMethod" { 
                            $myObject.temporaryAccessPass = $true 
                            $myObject.MFAstatus = "Enabled"
                        }
                        "#microsoft.graph.certificateBasedAuthConfiguration" { 
                            $myObject.certificateBasedAuthConfiguration = $true 
                            $myObject.MFAstatus = "Enabled"
                        }
                        Default {
                          Write-Output "Unknown method type: $odataType for user $userPrinc"
                      }
                    }
                }
            } 
            
            else {
                Write-LogFile -Message "[WARNING] No MFA data found for user $userPrinc" -Color "Yellow"
            }
        }

        catch {
            Write-LogFile -Message "[ERROR] Error while retrieving the MFA status for $userPrinc | Error: $_ " -Color "Red"
        }
        
        if ($myObject.MFAstatus -eq "Enabled") {
            $MFAstatusAmount++
        }
  
        $results += $myObject
    }
    
    $date = Get-Date -Format "yyyyMMddHHmm"
    $filePath = "$OutputDir\$($date)-MFA-AuthenticationMethods.csv"
    $results | Export-Csv -Path $filePath -NoTypeInformation -Encoding $Encoding
    Write-LogFile -Message "[INFO] Output written to $filePath" -Color "Green"
    
    $MFAEmail = (Import-Csv -Path "$filePath" -Delimiter "," | Where-Object { $_.email -eq $true } | Measure-Object).Count
    $MFAfido2 = (Import-Csv -Path "$filePath" -Delimiter "," | Where-Object { $_.fido2 -eq $true } | Measure-Object).Count
    $MFAapp = (Import-Csv -Path "$filePath" -Delimiter "," | Where-Object { $_.app -eq $true } | Measure-Object).Count
    $MFAphone = (Import-Csv -Path "$filePath" -Delimiter "," | Where-Object { $_.phone -eq $true } | Measure-Object).Count
    $MFAsoftwareoath = (Import-Csv -Path "$filePath" -Delimiter "," | Where-Object { $_.softwareoath -eq $true } | Measure-Object).Count
    $MFAhellobusiness = (Import-Csv -Path "$filePath" -Delimiter "," | Where-Object { $_.hellobusiness -eq $true } | Measure-Object).Count
    $MFAstatusAmount = (Import-Csv -Path "$filePath" -Delimiter "," | Where-Object { $_.MFAstatus -eq "Enabled" } | Measure-Object).Count
    $temporaryAccessPassAuthenticationMethod = (Import-Csv -Path "$filePath" -Delimiter "," | Where-Object { $_.temporaryAccessPass -eq $true } | Measure-Object).Count
    $certificateBasedAuthConfiguration = (Import-Csv -Path "$filePath" -Delimiter "," | Where-Object { $_.certificateBasedAuthConfiguration -eq $true } | Measure-Object).Count
  
    $totalUsers = $allUsers.Count
    Write-Host "$MFAstatusAmount out of $totalUsers users have MFA enabled:"
    Write-Host "  - $MFAEmail x Email"
    Write-Host "  - $MFAfido2 x Fido2"
    Write-Host "  - $MFAapp x Microsoft Authenticator App"
    Write-Host "  - $MFAphone x Phone"
    Write-Host "  - $MFAsoftwareoath x SoftwareOAuth"
    Write-Host "  - $MFAhellobusiness x HelloBusiness"
    Write-Host "  - $temporaryAccessPassAuthenticationMethod x Temporary Access Pass (TAP)"
    Write-Host "  - $certificateBasedAuthConfiguration x Certificate Based Auth Configuration"  

    write-host ""
    Write-logFile -Message "[INFO] Retrieving the user registration details" 

    $results = @()
    $filePath = "$OutputDir\$($date)-MFA-UserRegistrationDetails.csv"
    $nextLink = "https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails"

    do {
        $response = Invoke-MgGraphRequest -Uri $nextLink -Method Get -OutputType PSObject
        $userDetails = $response.value
        $nextLink = $response.'@odata.nextLink'

        ForEach ($detail in $userDetails) {
          $myObject = [PSCustomObject]@{}
          $detail.PSObject.Properties | ForEach-Object {
              $myObject | Add-Member -Type NoteProperty -Name $_.Name -Value $_.Value
          }
          $results += $myObject
        }
    } while ($nextLink)

    $results | Export-Csv -Path $filePath -NoTypeInformation -Encoding $Encoding
    Write-LogFile -Message "[INFO] Output written to $filePath" -Color "Green" 
}
  
