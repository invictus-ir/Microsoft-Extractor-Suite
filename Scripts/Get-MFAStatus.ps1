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
    Debug: Verbose logging for debugging purposes
    Default: Standard

    .PARAMETER IncludePhoneNumbers
    When this switch is set, the script will collect and include phone numbers used for MFA in the output.
    Default: False
    
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

    .EXAMPLE
    Get-MFA -IncludePhoneNumbers
    Retrieves the MFA status for all users including their phone numbers used for MFA.
#>
    [CmdletBinding()]
    param(
        [string]$OutputDir,
        [string]$Encoding = "UTF8",
        [string[]]$UserIds,
        [ValidateSet('None', 'Minimal', 'Standard', 'Debug')]
        [string]$LogLevel = 'Standard',
        [switch]$IncludePhoneNumbers
    )

    Init-Logging
    if ($OutputDir) {
       Init-OutputDir -Component "MFA" -FilePostfix "AuthenticationMethods" -CustomOutputDir $OutputDir
    } else {
       Init-OutputDir -Component "MFA" -FilePostfix "AuthenticationMethods"
    }
    Write-LogFile -Message "=== Starting MFA Status Collection ===" -Color "Cyan" -Level Standard

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
  
    Write-LogFile -Message "[INFO] Identifying authentication methods..." -Level Standard     
  
    $results = @()
    $allUsers = @()
    $userPhoneMethodsCache = @{}
    $phoneNumberMap = @{}
    $phoneResults = @()

    if ($UserIds) {
        if ($isDebugEnabled) {
            Write-LogFile -Message "[DEBUG] Processing scenario: Specific users" -Level Debug
            Write-LogFile -Message "[DEBUG] Users to process: $($UserIds -join ', ')" -Level Debug
        }
        Write-LogFile -Message "[INFO] Processing specific users..." -Level Standard
        foreach ($userId in $UserIds) {
            $userUri = "https://graph.microsoft.com/v1.0/users/$userId"
            try {
                $user = Invoke-MgGraphRequest -Uri $userUri -Method Get -OutputType PSObject
                $allUsers += $user
                if ($isDebugEnabled) {
                    Write-LogFile -Message "[DEBUG] Successfully retrieved user: $($user.userPrincipalName)" -Level Debug
                }
            } catch {
                Write-LogFile -Message "[WARNING] User with ID $userId not found" -Color "Yellow" -Level Minimal 
                if ($isDebugEnabled) {
                    Write-LogFile -Message "[DEBUG] Error details for user $userId : $($_.Exception.Message)" -Level Debug
                }
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

    if ($IncludePhoneNumbers) {
        Write-LogFile -Message "[INFO] Collecting phone numbers for MFA..." -Level Standard  
        foreach ($user in $allUsers) {
            $userPrinc = $user.userPrincipalName
            try {
                $phoneMethods = Get-MgUserAuthenticationPhoneMethod -UserId $userPrinc -ErrorAction SilentlyContinue
                
                $userPhoneMethodsCache[$userPrinc] = $phoneMethods
                
                if ($phoneMethods -and $phoneMethods.Count -gt 0) {
                    $summary.PhoneNumberUsers++
                    
                    foreach ($phoneMethod in $phoneMethods) {
                        if (-not [string]::IsNullOrEmpty($phoneMethod.PhoneNumber)) {
                            if (-not $phoneNumberMap.ContainsKey($phoneMethod.PhoneNumber)) {
                                $phoneNumberMap[$phoneMethod.PhoneNumber] = @()
                            }
                            $phoneNumberMap[$phoneMethod.PhoneNumber] += $userPrinc
                        }
                    }
                }
            }
            catch {
                Write-LogFile -Message "[ERROR] Error retrieving phone methods for user $userPrinc : $_" -Level Minimal -Color "Red"
                $userPhoneMethodsCache[$userPrinc] = @()
            }
        }
    } 

    foreach ($user in $allUsers) {  
        $userPrinc = $user.userPrincipalName
        if ($isDebugEnabled) {
            Write-LogFile -Message "[DEBUG]   Processing user: $userPrinc" -Level Debug
        }
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
            if ($isDebugEnabled) {
                Write-LogFile -Message "[DEBUG]   Fetching auth methods from: $contentUri" -Level Debug
            }
            if ($MFAData -and $MFAData.value) {
                if ($isDebugEnabled) {
                    Write-LogFile -Message "[DEBUG]   Found $($MFAData.value.Count) authentication methods" -Level Debug
                }
                ForEach ($method in $MFAData.value) {
                    $odataType = $method.'@odata.type'
                    if ($isDebugEnabled) {
                        Write-LogFile -Message "[DEBUG]     Processing method: $odataType" -Level Debug
                    }
                    
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
                if ($isDebugEnabled) {
                    Write-LogFile -Message "[DEBUG]   MFAData is null or empty" -Level Debug
                    Write-LogFile -Message "[DEBUG]   MFAData: $($MFAData | ConvertTo-Json -Compress)" -Level Debug
                }
            }

            if ($IncludePhoneNumbers) {
                try {
                    $phoneMethods = Get-MgUserAuthenticationPhoneMethod -UserId $userPrinc -ErrorAction SilentlyContinue
                    if ($phoneMethods) {
                        foreach ($phoneMethod in $phoneMethods) {
                            $phoneObject = [PSCustomObject]@{
                                UserPrincipalName = $userPrinc
                                UserId = $user.id
                                PhoneNumber = $phoneMethod.PhoneNumber
                                PhoneType = $phoneMethod.PhoneType
                                SmsSignInState = $phoneMethod.SmsSignInState
                            }
                            $phoneResults += $phoneObject
                        }
                    }
                }
                catch {
                    Write-LogFile -Message "[ERROR] Error retrieving phone methods for user $userPrinc : $_" -Level Minimal -Color "Red"
                }
            }

            if ($IncludePhoneNumbers) {
                try {
                    $phoneMethods = Get-MgUserAuthenticationPhoneMethod -UserId $userPrinc -ErrorAction SilentlyContinue
                    if ($phoneMethods) {
                        foreach ($phoneMethod in $phoneMethods) {
                            $phoneObject = [PSCustomObject]@{
                                UserPrincipalName = $userPrinc
                                UserId = $user.id
                                PhoneNumber = $phoneMethod.PhoneNumber
                                PhoneType = $phoneMethod.PhoneType
                                SmsSignInState = $phoneMethod.SmsSignInState
                            }
                            $phoneResults += $phoneObject
                        }
                    }
                }
                catch {
                    Write-LogFile -Message "[ERROR] Error retrieving phone methods for user $userPrinc : $_" -Level Minimal -Color "Red"
                }
            }
        }

        catch {
            Write-LogFile -Message "[ERROR] Error processing user $userPrinc : $_" -Level Minimal -Color "Red"
            if ($isDebugEnabled) {
                Write-LogFile -Message "[DEBUG]   Error details:" -Level Debug
                Write-LogFile -Message "[DEBUG]     Exception type: $($_.Exception.GetType().Name)" -Level Debug
                Write-LogFile -Message "[DEBUG]     Error message: $($_.Exception.Message)" -Level Debug
                Write-LogFile -Message "[DEBUG]     Stack trace: $($_.ScriptStackTrace)" -Level Debug
            }
        }
        
        if ($myObject.MFAstatus -eq "Enabled") {
            $summary.MFAEnabled++
        } else {
            $summary.MFADisabled++
        }
  
        $results += $myObject
    }

    $summary.ProcessingTime = (Get-Date) - $summary.StartTime
    $results | Export-Csv -Path $script:outputFile  -NoTypeInformation -Encoding $Encoding

    Write-LogFile -Message "[INFO] Retrieving user registration details..." -Level Standard
    $results = @()
    $registrationResults  = "$script:outputFile"
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

            if ($IncludePhoneNumbers) {
                $userPrinc = $detail.userPrincipalName
                    
                if ($userPhoneMethodsCache.ContainsKey($userPrinc) -and $userPhoneMethodsCache[$userPrinc]) {
                    $phoneNumbers = @()
                    $phoneTypes = @()
                    $smsStates = @()
                    
                    foreach ($phoneMethod in $userPhoneMethodsCache[$userPrinc]) {
                        $phoneNumbers += $phoneMethod.PhoneNumber
                        $phoneTypes += $phoneMethod.PhoneType
                        $smsStates += $phoneMethod.SmsSignInState
                    }
                    
                    $myObject | Add-Member -Type NoteProperty -Name "MfaPhoneNumbers" -Value ($phoneNumbers -join "; ")
                    $myObject | Add-Member -Type NoteProperty -Name "MfaPhoneTypes" -Value ($phoneTypes -join "; ")
                    $myObject | Add-Member -Type NoteProperty -Name "MfaSmsSignInStates" -Value ($smsStates -join "; ")
                }
                else {
                    $myObject | Add-Member -Type NoteProperty -Name "MfaPhoneNumbers" -Value ""
                    $myObject | Add-Member -Type NoteProperty -Name "MfaPhoneTypes" -Value ""
                    $myObject | Add-Member -Type NoteProperty -Name "MfaSmsSignInStates" -Value ""
                }
            }
        }
    } while ($nextLink)

    if ($OutputDir) {
       Init-OutputDir -Component "MFA" -FilePostfix "UserRegistrationDetails" -CustomOutputDir $OutputDir
    } else {
       Init-OutputDir -Component "MFA" -FilePostfix "UserRegistrationDetails"
    }
    
    $authMethodsPath  = "$script:outputFile"
    $results | Export-Csv -Path $script:outputFile  -NoTypeInformation -Encoding $Encoding
    Write-LogFile -Message "`n=== MFA Status Analysis Summary ===" -Color "Cyan" -Level Standard
    Write-LogFile -Message "`nMFA Status:" -Level Standard
    Write-LogFile -Message "  Total Users: $($summary.TotalUsers)" -Level Standard
    Write-LogFile -Message "  MFA Enabled: $($summary.MFAEnabled) users ($([math]::Round($summary.MFAEnabled/$summary.TotalUsers*100,1))%)" -Level Standard
    Write-LogFile -Message "  MFA Disabled: $($summary.MFADisabled) users ($([math]::Round($summary.MFADisabled/$summary.TotalUsers*100,1))%)" -Level Standard
    if ($IncludePhoneNumbers) {
        Write-LogFile -Message "  Users with Phone MFA: $($summary.PhoneNumberUsers) users" -Level Standard
    }    
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
          
        