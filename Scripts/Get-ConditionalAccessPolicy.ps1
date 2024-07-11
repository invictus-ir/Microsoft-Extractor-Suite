
Function Get-ConditionalAccessPolicies {
<#
    .SYNOPSIS
    Retrieves all the conditional access policies. 

    .DESCRIPTION
    Retrieves the risky users from the Entra ID Identity Protection, which marks an account as being at risk based on the pattern of activity for the account.

    .PARAMETER OutputDir
    OutputDir is the parameter specifying the output directory.
    Default: Output\ConditionalAccessPolicies

    .PARAMETER Encoding
    Encoding is the parameter specifying the encoding of the CSV output file.
    Default: UTF8

    .PARAMETER Application
    Application is the parameter specifying App-only access (access without a user) for authentication and authorization.
    Default: Delegated access (access on behalf a user)
    
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
        [switch]$Application
    )

    $authType = Get-GraphAuthType
    if ($authType -eq "Delegated") {
        Connect-MgGraph -Scopes Policy.Read.All > $null
    }

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

    Write-logFile -Message "[INFO] Running Get-ConditionalAccess" -Color "Green"
    $results=@();

    try {
        get-MgIdentityConditionalAccessPolicy -all | ForEach-Object {
            $myObject = [PSCustomObject]@{
                DisplayName                   = "-"
                CreatedDateTime               = "-"
                Description                   = "-"
                Id                            = "-"
                ModifiedDateTime              = "-"
                State                         = "-"
                ClientAppTypes                = "-"
                ServicePrincipalRiskLevels    = "-"
                SignInRiskLevels              = "-"
                UserRiskLevels                = "-"
                BuiltInControls               = "-"
                CustomAuthenticationFactors   = "-"
                ClientOperatorAppTypes        = "-"
                TermsOfUse                    = "-"
                DisableResilienceDefaults     = "-"
            }

            $myobject.DisplayName = $_.DisplayName
            $myobject.CreatedDateTime = $_.CreatedDateTime
            $myobject.Description = $_.Description
            $myobject.Id = $_.Id
            $myobject.ModifiedDateTime = $_.ModifiedDateTime
            $myobject.State = $_.State
            $myobject.ClientAppTypes = $_.Conditions.ClientAppTypes | out-string
            $myobject.ServicePrincipalRiskLevels = $_.Conditions.ServicePrincipalRiskLevels | out-string
            $myobject.SignInRiskLevels = $_.Conditions.SignInRiskLevels | out-string
            $myobject.UserRiskLevels = $_.Conditions.UserRiskLevels | out-string
            $myobject.BuiltInControls = $_.GrantControls.BuiltInControls | out-string
            $myobject.CustomAuthenticationFactors = $_.GrantControls.CustomAuthenticationFactors | out-string
            $myobject.ClientOperatorAppTypes = $_.GrantControls.Operator | out-string
            $myobject.TermsOfUse = $_.GrantControls.TermsOfUse | out-string
            $myobject.DisableResilienceDefaults = $_.SessionControls.DisableResilienceDefaults | out-string
            $results+= $myObject;
        }
    }

    catch {
        write-logFile -Message "[INFO] Ensure you are connected to Microsoft Graph by running the Connect-MgGraph -Scopes Policy.Read.All command before executing this script" -Color "Yellow"
        Write-logFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" 
        throw
    }

    $date = [datetime]::Now.ToString('yyyyMMddHHmmss') 
    $filePath = "$OutputDir\$($date)-ConditionalAccessPolicy.csv"
    $results | Export-Csv -Path $filePath -NoTypeInformation -Encoding $Encoding
    Write-logFile -Message "[INFO] Output written to $filePath" -Color "Green" 
}
