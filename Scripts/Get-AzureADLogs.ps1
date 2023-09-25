# This contains functions for getting Azure AD logging

function Get-ADSignInLogs {
<#
    .SYNOPSIS
    Gets of sign ins logs.

    .DESCRIPTION
    The Get-AzureADAuditSignInLogs cmdlet collects the contents of the Azure Active Directory sign-in logs.
	The output will be written to: Output\AzureAD\SignInLogs.json

	.PARAMETER After
	The After parameter specifies the date from which all logs need to be collected.

	.PARAMETER Before
    The Before parameter specifies the date before which all logs need to be collected.

	.PARAMETER OutputDir
    OutputDir is the parameter specifying the output directory.
	Default: Output\AzureAD
    
    .EXAMPLE
    Get-ADSignInLogs
	Get all audit logs of sign ins.

	.EXAMPLE
    Get-ADSignInLogs -Before 2023-04-12
	Get audit logs before 2023-04-12.

	.EXAMPLE
    Get-ADSignInLogs -After 2023-04-12
	Get audit logs after 2023-04-12.
#>
	[CmdletBinding()]
	param(
		[string]$After,
		[string]$Before,
		[string]$outputDir
	)

	try {
		$areYouConnected = Get-AzureADAuditDirectoryLogs -ErrorAction stop
	}
	catch {
		Write-logFile -Message "[WARNING] You must call Connect-Azure before running this script" -Color "Red"
		break
	}

	Write-logFile -Message "[INFO] Running Get-AADSignInLogs" -Color "Green"

	$date = [datetime]::Now.ToString('yyyyMMddHHmmss') 
	if ($OutputDir -eq "" ){
		$OutputDir = "Output\AzureAD\$date\"
		if (!(test-path $OutputDir)) {
			write-logFile -Message "[INFO] Creating the following directory: $OutputDir"
			New-Item -ItemType Directory -Force -Name $OutputDir | Out-Null
		}
	}

	if (($After -eq "") -and ($Before -eq "")) {
		Write-logFile -Message "[INFO] Collecting the Azure Active Directory sign in logs"
		$filePath = "$OutputDir\SignInLogs.json"

		$signInLogs = Get-AzureADAuditSignInLogs -All $true
		$signInLogs | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath

		Write-logFile -Message "[INFO] Sign-in logs written to $filePath" -Color "Green"
	}

	elseif (($After -ne "") -and ($Before -eq "")) {
		Write-logFile -Message "[INFO] Collecting the Azure Active Directory sign in logs on or after $After"
		$filePath = "$OutputDir\SignInLogs.json"

		$signInLogs = Get-AzureADAuditSignInLogs -All $true -Filter "createdDateTime gt $After"
		$signInLogs | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath

		Write-logFile -Message "[INFO] Sign-in logs written to $filePath" -Color "Green"
	}

	elseif (($Before -ne "") -and ($After -eq "")) {
		Write-logFile -Message "[INFO] Collecting the Azure Active Directory sign in logs on or before $Before"
		$filePath = "$OutputDir\$date\SignInLogs.json"

		$signInLogs = Get-AzureADAuditSignInLogs -All $true -Filter "createdDateTime lt $Before"
		$signInLogs | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath

		Write-logFile -Message "[INFO] Sign-in logs written to $filePath" -Color "Green"
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
    The Get-AzureADAuditDirectoryLogs cmdlet to collect the contents of the Azure Active Directory Audit logs.
	The output will be written to: "Output\AzureAD\Auditlogs.json

	.PARAMETER After
	The After parameter specifies the date from which all logs need to be collected.

	.PARAMETER Before
    The Before parameter specifies the date before which all logs need to be collected.

	.PARAMETER OutputDir
    outputDir is the parameter specifying the output directory.
	Default: Output\AzureAD
    
    .EXAMPLE
    Get-ADAuditLogs
	Get directory audit logs.

	.EXAMPLE
    Get-ADAuditLogs -Before 2023-04-12
	Get directory audit logs before 2023-04-12.

	.EXAMPLE
    Get-ADAuditLogs -After 2023-04-12
	Get directory audit logs after 2023-04-12.
#>
	[CmdletBinding()]
	param(
		[string]$After,
		[string]$Before,
		[string]$OutputDir
	)

	try {
		$areYouConnected = Get-AzureADAuditDirectoryLogs -ErrorAction stop
	}
	catch {
		Write-logFile -Message "[WARNING] You must call Connect-Azure before running this script" -Color "Red"
		break
	}

	Write-logFile -Message "[INFO] Running Get-AADAuditLogs" -Color "Green"
	
	$date = [datetime]::Now.ToString('yyyyMMddHHmmss') 
	if ($OutputDir -eq "" ){
		$OutputDir = "Output\AzureAD\$date\"
		if (!(test-path $OutputDir)) {
			write-logFile -Message "[INFO] Creating the following directory: $OutputDir"
			New-Item -ItemType Directory -Force -Name $OutputDir | Out-Null
		}
	}

	if (($After -eq "") -and ($Before -eq "")) {
		Write-logFile -Message "[INFO] Collecting the Directory audit logs"
		$filePath = "$OutputDir\Auditlogs.json"
		
		$auditLogs = Get-AzureADAuditDirectoryLogs -All $true | Select-Object Id,Category,CorrelationId,Result,ResultReason,ActivityDisplayName,@{N='ActivityDateTime';E={$_.ActivityDateTime.ToString()}},LoggedByService,OperationType,InitiatedBy,TargetResources,AdditionalDetails
		$auditLogs | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath
		
		Write-logFile -Message "[INFO] Directory audit logs written to $filePath" -Color "Green"
	}

	elseif (($After -ne "") -and ($Before -eq "")) {
		Write-logFile -Message "[INFO] Collecting the Directory audit logs on or after $After"
		$filePath = "$OutputDir\Auditlogs.json"
		
		$auditLogs = Get-AzureADAuditDirectoryLogs -All $true -Filter "activityDateTime gt $After" | Select-Object Id,Category,CorrelationId,Result,ResultReason,ActivityDisplayName,@{N='ActivityDateTime';E={$_.ActivityDateTime.ToString()}},LoggedByService,OperationType,InitiatedBy,TargetResources,AdditionalDetails
		$auditLogs | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath
		
		Write-logFile -Message "[INFO] Directory audit logs written to $filePath" -Color "Green"
	}

	elseif (($Before -ne "") -and ($After -eq "")) {
		Write-logFile -Message "[INFO] Collecting the Directory audit logs logs on or before $Before"
		$filePath = "$OutputDir\Auditlogs.json"
		
		$auditLogs = Get-AzureADAuditDirectoryLogs -All $true -Filter "activityDateTime lt $Before" | Select-Object Id,Category,CorrelationId,Result,ResultReason,ActivityDisplayName,@{N='ActivityDateTime';E={$_.ActivityDateTime.ToString()}},LoggedByService,OperationType,InitiatedBy,TargetResources,AdditionalDetails
		$auditLogs | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath
		
		Write-logFile -Message "[INFO] Directory audit logs written to $filePath" -Color "Green"
	}

	else {
		Write-logFile -Message "[WARNING] Please only provide a start date or end date" -Color "Red"
	}
}
