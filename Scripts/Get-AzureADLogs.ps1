# This contains functions for getting Azure AD logging

function Get-ADSignInLogs {
<#
    .SYNOPSIS
    Get sign-in logs.

    .DESCRIPTION
    The Get-ADSignInLogs cmdlet collects the contents of the Azure Active Directory sign-in logs.
	The output will be written to: Output\AzureAD\SignInLogs.json

	.PARAMETER startDate
	The startDate parameter specifies the date from which all logs need to be collected.

	.PARAMETER endDate
    The Before parameter specifies the date endDate which all logs need to be collected.

	.PARAMETER OutputDir
    OutputDir is the parameter specifying the output directory.
	Default: Output\AzureAD

	.PARAMETER Encoding
    Encoding is the parameter specifying the encoding of the JSON output file.
	Default: UTF8

	.PARAMETER UserIds
    UserIds is the UserIds parameter filtering the log entries by the account of the user who performed the actions.
    
    .EXAMPLE
    Get-ADSignInLogs
	Get all sign-in logs.

    .EXAMPLE
    Get-ADAuditLogs -UserIds Test@invictus-ir.com
    Get sign-in logs for the user Test@invictus-ir.com.

	.EXAMPLE
    Get-ADSignInLogs -Before 2023-04-12
	Get sign-in logs before 2023-04-12.

	.EXAMPLE
    Get-ADSignInLogs -After 2023-04-12
	Get sign-in logs after 2023-04-12.
#>
	[CmdletBinding()]
	param(
		[string]$After,
		[string]$Before,
		[string]$outputDir,
		[string]$UserIds,
		[string]$Encoding
	)

	try {
		$areYouConnected = Get-AzureADAuditSignInLogs -ErrorAction stop
	}
	catch {
		Write-logFile -Message "[WARNING] You must call Connect-Azure before running this script" -Color "Red"
		break
	}

	Write-logFile -Message "[INFO] Running Get-AADSignInLogs" -Color "Green"

	if ($Encoding -eq "" ){
		$Encoding = "UTF8"
	}
	
	$date = [datetime]::Now.ToString('yyyyMMddHHmmss') 
	if ($OutputDir -eq "" ){
		$OutputDir = "Output\AzureAD\$date"
		if (!(test-path $OutputDir)) {
			write-logFile -Message "[INFO] Creating the following directory: $OutputDir"
			New-Item -ItemType Directory -Force -Name $OutputDir | Out-Null
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

	$filePath = "$OutputDir\SignInLogs.json"

	if (($After -eq "") -and ($Before -eq "")) {
		Write-logFile -Message "[INFO] Collecting the Azure Active Directory sign-in logs"

		if ($Userids){
			try{
				$signInLogs = Get-AzureADAuditSignInLogs -All $true -Filter "UserPrincipalName eq '$Userids'"
				$signInLogs | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath -Encoding $Encoding

				Write-logFile -Message "[INFO] Sign-in logs written to $filePath" -Color "Green"
			}
			catch{
				Start-Sleep -Seconds 20
				$signInLogs = Get-AzureADAuditSignInLogs -All $true -Filter "UserPrincipalName eq '$Userids'"
				$signInLogs | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath -Encoding $Encoding

				Write-logFile -Message "[INFO] Sign-in logs written to $filePath" -Color "Green"
			}
		}
		else{
			try{
				$signInLogs = Get-AzureADAuditSignInLogs -All $true
				$signInLogs | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath -Encoding $Encoding

				Write-logFile -Message "[INFO] Sign-in logs written to $filePath" -Color "Green"
			}
			catch{
				Start-Sleep -Seconds 20
				$signInLogs = Get-AzureADAuditSignInLogs -All $true
				$signInLogs | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath -Encoding $Encoding

				Write-logFile -Message "[INFO] Sign-in logs written to $filePath" -Color "Green"
			}
		}
	}

	elseif (($After -ne "") -and ($Before -eq "")) {
		Write-logFile -Message "[INFO] Collecting the Azure Active Directory sign in logs on or after $After"

		if ($Userids){
			try{
				$signInLogs = Get-AzureADAuditSignInLogs -All $true -Filter "UserPrincipalName eq '$Userids' and createdDateTime gt $After"
				$signInLogs | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath -Encoding $Encoding

				Write-logFile -Message "[INFO] Sign-in logs written to $filePath" -Color "Green"
			}
			catch{
				Start-Sleep -Seconds 20
				$signInLogs = Get-AzureADAuditSignInLogs -All $true -Filter "UserPrincipalName eq '$Userids' and createdDateTime gt $After"
				$signInLogs | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath -Encoding $Encoding

				Write-logFile -Message "[INFO] Sign-in logs written to $filePath" -Color "Green"
			}
		}
		else{
			try{
				$signInLogs = Get-AzureADAuditSignInLogs -All $true -Filter "createdDateTime gt $After"
				$signInLogs | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath -Encoding $Encoding

				Write-logFile -Message "[INFO] Sign-in logs written to $filePath" -Color "Green"
			}
			catch{
				Start-Sleep -Seconds 20
				$signInLogs = Get-AzureADAuditSignInLogs -All $true -Filter "createdDateTime gt $After"
				$signInLogs | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath -Encoding $Encoding

				Write-logFile -Message "[INFO] Sign-in logs written to $filePath" -Color "Green"
			}
		}
	}

	elseif (($Before -ne "") -and ($After -eq "")) {
		Write-logFile -Message "[INFO] Collecting the Azure Active Directory sign in logs on or before $Before"
		if ($Userids){
			try{
				$signInLogs = Get-AzureADAuditSignInLogs -All $true -Filter "UserPrincipalName eq '$Userids' and createdDateTime lt $Before"
				$signInLogs | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath -Encoding $Encoding

				Write-logFile -Message "[INFO] Sign-in logs written to $filePath" -Color "Green"
			}
			catch{
				Start-Sleep -Seconds 20
				$signInLogs = Get-AzureADAuditSignInLogs -All $true -Filter "UserPrincipalName eq '$Userids' and createdDateTime lt $Before"
				$signInLogs | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath -Encoding $Encoding

				Write-logFile -Message "[INFO] Sign-in logs written to $filePath" -Color "Green"
			}
		}
		else{
			try{
				$signInLogs = Get-AzureADAuditSignInLogs -All $true -Filter "createdDateTime lt $Before"
				$signInLogs | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath -Encoding $Encoding

				Write-logFile -Message "[INFO] Sign-in logs written to $filePath" -Color "Green"
			}
			catch{
				Start-Sleep -Seconds 20
				$signInLogs = Get-AzureADAuditSignInLogs -All $true -Filter "createdDateTime lt $Before"
				$signInLogs | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath -Encoding $Encoding

				Write-logFile -Message "[INFO] Sign-in logs written to $filePath" -Color "Green"
			}
		}
	}

	else {
		Write-logFile -Message "[WARNING] Please only provide a start date or end date" -Color "Red"
	}
}

function Get-ADAuditLogs {
<#
    .SYNOPSIS
    Get directory audit logs.

    .DESCRIPTION
    The Get-ADAuditLogs cmdlet collects the contents of the Azure Active Directory Audit logs.
	The output will be written to: "Output\AzureAD\Auditlogs.json

	.PARAMETER startDate
	The startDate parameter specifies the date from which all logs need to be collected.

	.PARAMETER endDate
    The endDate parameter specifies the date before which all logs need to be collected.

	.PARAMETER OutputDir
    outputDir is the parameter specifying the output directory.
	Default: Output\AzureAD

	.PARAMETER Encoding
    Encoding is the parameter specifying the encoding of the JSON output file.
	Default: UTF8

    .PARAMETER UserIds
    UserIds is the UserIds parameter filtering the log entries by the account of the user who performed the actions.
    
    .EXAMPLE
    Get-ADAuditLogs
	Get directory audit logs.

    .EXAMPLE
    Get-ADAuditLogs -UserIds Test@invictus-ir.com
    Get directory audit logs for the user Test@invictus-ir.com.

	.EXAMPLE
    Get-ADAuditLogs -endDate 2023-04-12
	Get directory audit logs before 2023-04-12.

	.EXAMPLE
    Get-ADAuditLogs -startDate 2023-04-12
	Get directory audit logs after 2023-04-12.
#>
	[CmdletBinding()]
	param(
		[string]$startDate,
		[string]$endDate,
		[string]$OutputDir,
        [string]$UserIds,
		[string]$Encoding
	)

	try {
		$areYouConnected = Get-AzureADAuditDirectoryLogs -ErrorAction stop
	}
	catch {
		Write-logFile -Message "[WARNING] You must call Connect-Azure or install AzureADPreview before running this script" -Color "Red"
		break
	}

	if ($Encoding -eq "" ){
		$Encoding = "UTF8"
	}

	Write-logFile -Message "[INFO] Running Get-ADAuditLogs" -Color "Green"
	
	$date = [datetime]::Now.ToString('yyyyMMddHHmmss') 
	if ($OutputDir -eq "" ){
		$OutputDir = "Output\AzureAD"
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

	$filePath = "$OutputDir\$($date)-Auditlogs.json"
	Write-logFile -Message "[INFO] Collecting the Directory Audit Logs"

	if ($endDate -and $After) {
		write-logFile -Message "[WARNING] Please provide only one of either a start date or end date" -Color "Red"
		return
	}

	$filter = ""
	if ($endDate) {
		$filter = "activityDateTime lt $endDate"
	}
	if ($startDate) {
		$filter = "activityDateTime gt $startDate"
	}

	if ($UserIds) {
		if ($filter) {
			$filter = " and $filter"
		}
		Get-AzureADAuditDirectoryLogs -All $true -Filter "initiatedBy/user/userPrincipalName eq '$Userids' $filter" | Select-Object Id,Category,CorrelationId,Result,ResultReason,ActivityDisplayName,@{N='ActivityDateTime';E={$_.ActivityDateTime.ToString()}},LoggedByService,OperationType,InitiatedBy,TargetResources,AdditionalDetails |
			ForEach-Object {
				$_ | ConvertTo-Json -Depth 100
			} |
			Out-File -FilePath $filePath -Encoding $Encoding
	} 
	else {
		Get-AzureADAuditDirectoryLogs -All $true -Filter $filter | Select-Object Id,Category,CorrelationId,Result,ResultReason,ActivityDisplayName,@{N='ActivityDateTime';E={$_.ActivityDateTime.ToString()}},LoggedByService,OperationType,InitiatedBy,TargetResources,AdditionalDetails |
			ForEach-Object {
				$_ | ConvertTo-Json -Depth 100
			} |
			Out-File -FilePath $filePath -Encoding $Encoding
	}
	Write-logFile -Message "[INFO] Directory audit logs written to $filePath" -Color "Green"
}
