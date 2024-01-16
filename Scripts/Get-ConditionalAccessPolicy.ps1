
Function Get-ConditionalAccessPolicies {
<#
    .SYNOPSIS
    Retrieves all the conditional access policies. 

    .DESCRIPTION
    Retrieves the risky users from the Entra ID Identity Protection, which marks an account as being at risk based on the pattern of activity for the account.
	The output will be written to: Output\UserInfo\

	.PARAMETER OutputDir
	OutputDir is the parameter specifying the output directory.
	Default: Output\UserInfo

	.PARAMETER Encoding
    Encoding is the parameter specifying the encoding of the CSV output file.
	Default: UTF8
    
    .EXAMPLE
    Get-ConditionalAccess
    Retrieves all the conditional access policies.
	
    .EXAMPLE
	Get-ConditionalAccess -Encoding utf32
	Retrieves all the conditional access policies and exports the output to a CSV file with UTF-32 encoding.
		
	.EXAMPLE
	Get-ConditionalAccess -OutputDir C:\Windows\Temp
	Retrieves all the conditional access policies and saves the output to the C:\Windows\Temp folder.	
#>
    [CmdletBinding()]
    param(
        [string]$OutputDir,
        [string]$Encoding
    )

    if ($Encoding -eq "" ){
        $Encoding = "UTF8"
    }

    Connect-MgGraph -Scopes Policy.Read.All -NoWelcome

    try {
        $areYouConnected = get-MgIdentityConditionalAccessPolicy -ErrorAction stop
    }
    catch {
        Write-logFile -Message "[WARNING] You must call Connect-MgGraph -Scopes Policy.Read.All' before running this script" -Color "Red"
        break
    }

    if ($OutputDir -eq "" ){
        $OutputDir = "Output\UserInfo"
        if (!(test-path $OutputDir)) {
            write-logFile -Message "[INFO] Creating the following directory: $OutputDir"
            New-Item -ItemType Directory -Force -Name $OutputDir | Out-Null
        }
    }

    Write-logFile -Message "[INFO] Running Get-ConditionalAccess" -Color "Green"
    $results=@();

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

    $filePath = "$OutputDir\ConditionalAccessPolicy.csv"
    $results | Export-Csv -Path $filePath -NoTypeInformation -Encoding $Encoding
    Write-logFile -Message "[INFO] Output written to $filePath" -Color "Green" 
}