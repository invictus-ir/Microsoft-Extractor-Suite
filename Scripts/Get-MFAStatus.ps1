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

    .PARAMETER UserIds
    UserIds is the UserIds parameter filtering the log entries by the account of the user who performed the actions.

    .PARAMETER LogLevel
    Specifies the level of logging:
    None: No logging
    Minimal: Critical errors only
    Standard: Normal operational logging
    Default: Standard
    
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
        [string]$Encoding = "UTF8",
        [string[]]$UserIds,
        [ValidateSet('None', 'Minimal', 'Standard')]
        [string]$LogLevel = 'Standard'
    )

    Set-LogLevel -Level ([LogLevel]::$LogLevel)
    Write-LogFile -Message "=== Starting MFA Status Collection ===" -Color "Cyan" -Level Minimal

    $requiredScopes = @("UserAuthenticationMethod.Read.All","User.Read.All")
    $graphAuth = Get-GraphAuthType -RequiredScopes $RequiredScopes

    $summary = @{
        TotalUsers = 0
        MFAEnabled = 0
        MFADisabled = 0
        MethodCounts = @{
            Email = 0
            Fido2 = 0
            App = 0
            Phone = 0
            SoftwareOath = 0
            HelloBusiness = 0
            TemporaryAccessPass = 0
            CertificateBasedAuth = 0
        }
        StartTime = Get-Date
        ProcessingTime = $null
    }

    if (!(test-path $OutputDir)) {
        New-Item -ItemType Directory -Force -Path $OutputDir > $null
    }
    else {
        if (!(Test-Path -Path $OutputDir)) {
            Write-Error "[Error] Custom directory invalid: $OutputDir exiting script" -ErrorAction Stop
            Write-LogFile -Message "[Error] Custom directory invalid: $OutputDir" -Level Minimal
        }
    }
  
    Write-LogFile -Message "[INFO] Identifying authentication methods..." -Level Standard     
  
    $results = @()
    $allUsers = @()

    if ($UserIds) {
        Write-LogFile -Message "[INFO] Processing specific users..." -Level Standard
        foreach ($userId in $UserIds) {
            $userUri = "https://graph.microsoft.com/v1.0/users/$userId"
            try {
                $user = Invoke-MgGraphRequest -Uri $userUri -Method Get -OutputType PSObject
                $allUsers += $user
            } catch {
                Write-LogFile -Message "[WARNING] User with ID $userId not found" -Color "Yellow" -Level Minimal 
            }
        }
    } else {
        Write-LogFile -Message "[INFO] Processing all users..." -Level Standard
        $nextLink = "https://graph.microsoft.com/v1.0/users"
        do {
            $response = Invoke-MgGraphRequest -Uri $nextLink -Method Get -OutputType PSObject
            $allUsers += $response.value
            $nextLink = $response.'@odata.nextLink'
        } while ($nextLink)
    }

    $summary.TotalUsers = $allUsers.Count
    Write-LogFile -Message "[INFO] Found $($summary.TotalUsers) users to process" -Level Standard

    foreach ($user in $allUsers) {  
        $userPrinc = $user.userPrincipalName
        $myObject = [PSCustomObject]@{
            user               = $userPrinc
            MFAstatus          = "Disabled"
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
                            $summary.MethodCounts.Email++
                        }
                        "#microsoft.graph.fido2AuthenticationMethod" { 
                            $myObject.fido2 = $true 
                            $myObject.MFAstatus = "Enabled"
                            $summary.MethodCounts.Fido2++
                        }
                        "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod" { 
                            $myObject.app = $true 
                            $myObject.MFAstatus = "Enabled"
                            $summary.MethodCounts.App++
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
                            $summary.MethodCounts.Phone++
                        }
                        "#microsoft.graph.softwareOathAuthenticationMethod" { 
                            $myObject.softwareoath = $true 
                            $myObject.MFAstatus = "Enabled"
                            $summary.MethodCounts.SoftwareOath++
                        }
                        "#microsoft.graph.windowsHelloForBusinessAuthenticationMethod" { 
                            $myObject.hellobusiness = $true 
                            $myObject.MFAstatus = "Enabled"
                            $summary.MethodCounts.HelloBusiness++
                        }
                        "#microsoft.graph.temporaryAccessPassAuthenticationMethod" { 
                            $myObject.temporaryAccessPass = $true 
                            $myObject.MFAstatus = "Enabled"
                            $summary.MethodCounts.TemporaryAccessPass++
                        }
                        "#microsoft.graph.certificateBasedAuthConfiguration" { 
                            $myObject.certificateBasedAuthConfiguration = $true 
                            $myObject.MFAstatus = "Enabled"
                            $summary.MethodCounts.CertificateBasedAuth++
                        }
                        Default {
                          Write-LogFile -Message "[WARNING] Unknown method type: $odataType for user $userPrinc" -Level Standard -Color "Yellow"
                        }
                    }
                }
            } 
            
            else {
                Write-LogFile -Message "[WARNING] No MFA data found for user $userPrinc" -Level Standard -Color "Yellow"
            }
        }

        catch {
            Write-LogFile -Message "[ERROR] Error processing user $userPrinc : $_" -Level Minimal -Color "Red"
        }
        
        if ($myObject.MFAstatus -eq "Enabled") {
            $summary.MFAEnabled++
        } else {
            $summary.MFADisabled++
        }
  
        $results += $myObject
    }

    $summary.ProcessingTime = (Get-Date) - $summary.StartTime
    $date = Get-Date -Format "yyyyMMddHHmm"
    $authMethodsPath  = "$OutputDir\$($date)-MFA-AuthenticationMethods.csv"
    $results | Export-Csv -Path $authMethodsPath  -NoTypeInformation -Encoding $Encoding

    Write-LogFile -Message "`n[INFO] Retrieving user registration details..." -Level Standard
    $results = @()
    $registrationResults  = "$OutputDir\$($date)-MFA-UserRegistrationDetails.csv"
    $nextLink = "https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails"

    do {
        $response = Invoke-MgGraphRequest -Uri $nextLink -Method Get -OutputType PSObject
        $userDetails = $response.value
        $nextLink = $response.'@odata.nextLink'

        ForEach ($detail in $userDetails) {
            if (!$UserIds -or $UserIds -contains $detail.userPrincipalName) {
                $myObject = [PSCustomObject]@{}
                $detail.PSObject.Properties | ForEach-Object {
                    $value = if ($_.Value -is [System.Array]) {
                        ($_.Value -join ', ')
                    } else {
                        $_.Value
                    }
                    $myObject | Add-Member -Type NoteProperty -Name $_.Name -Value $value
                }
                $results += $myObject
            }
        }
    } while ($nextLink)

    $results | Export-Csv -Path $registrationResults  -NoTypeInformation -Encoding $Encoding
    Write-LogFile -Message "`n=== MFA Status Analysis Summary ===" -Color "Cyan" -Level Standard
    Write-LogFile -Message "`nMFA Status:" -Level Standard
    Write-LogFile -Message "  Total Users: $($summary.TotalUsers)" -Level Standard
    Write-LogFile -Message "  MFA Enabled: $($summary.MFAEnabled) users ($([math]::Round($summary.MFAEnabled/$summary.TotalUsers*100,1))%)" -Level Standard
    Write-LogFile -Message "  MFA Disabled: $($summary.MFADisabled) users ($([math]::Round($summary.MFADisabled/$summary.TotalUsers*100,1))%)" -Level Standard
    
    Write-LogFile -Message "`nAuthentication Methods:" -Level Standard
    Write-LogFile -Message "  - Email: $($summary.MethodCounts.Email)" -Level Standard
    Write-LogFile -Message "  - Fido2: $($summary.MethodCounts.Fido2)" -Level Standard
    Write-LogFile -Message "  - Microsoft Authenticator App: $($summary.MethodCounts.App)" -Level Standard
    Write-LogFile -Message "  - Phone: $($summary.MethodCounts.Phone)" -Level Standard
    Write-LogFile -Message "  - Software OAuth: $($summary.MethodCounts.SoftwareOath)" -Level Standard
    Write-LogFile -Message "  - Hello Business: $($summary.MethodCounts.HelloBusiness)" -Level Standard
    Write-LogFile -Message "  - Temporary Access Pass: $($summary.MethodCounts.TemporaryAccessPass)" -Level Standard
    Write-LogFile -Message "  - Certificate Based Auth: $($summary.MethodCounts.CertificateBasedAuth)" -Level Standard
    
    Write-LogFile -Message "`nOutput Files:" -Level Standard
    Write-LogFile -Message "  Authentication Methods: $authMethodsPath" -Level Standard
    Write-LogFile -Message "  Registration Details: $registrationResults " -Level Standard
    Write-LogFile -Message "Processing Time: $($summary.ProcessingTime.ToString('mm\:ss'))" -Color "Green" -Level Standard
    Write-LogFile -Message "===================================" -Color "Cyan" -Level Standard
}
      
    