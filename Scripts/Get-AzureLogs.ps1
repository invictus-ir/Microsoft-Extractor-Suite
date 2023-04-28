# This contains functions for getting Azure AD logging

function Get-ADSignInLogs {
<#
    .SYNOPSIS
    Get audit logs of sign ins.

    .DESCRIPTION
    The Get-AzureADAuditSignInLogs cmdlet gets an Azure Active Directory sign-in log.
	The output will be written to: Output\AzureAD\SignInLogs.json

	.PARAMETER After
	The After parameter specifies the date from which all logs need to be collected.

	.PARAMETER Before
    The Before parameter specifies the date before which all logs need to be collected.
    
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
		[string]$Before
	)

	try {
		$areYouConnected = Get-AzureADAuditSignInLogs -ErrorAction stop
	}
	catch {
		write-logFile -Message "[WARNING] You must call Connect-Azure before running this script" -Color "Red"
		break
	}

	write-logFile -Message "[INFO] Running Get-AADSignInLogs" -Color "Green"

	$outputDir = "Output\AzureAD"
	if (!(test-path $outputDir)) {
		write-logFile -Message "[INFO] Creating the following directory: $outputDir"
		New-Item -ItemType Directory -Force -Name $outputDir | Out-Null
	}

	if (($After -eq "") -and ($Before -eq "")) {
		write-logFile -Message "[INFO] Collecting the Azure Active Directory sign in logs"
		$filePath = "Output\AzureAD\SignInLogs.json"

		$signInLogs = Get-AzureADAuditSignInLogs -All $true
		$signInLogs | ConvertTo-Json | Out-File -FilePath $filePath

		write-logFile -Message "[INFO] Sign-in logs written to $filePath" -Color "Green"
	}

	elseif (($After -ne "") -and ($Before -eq "")) {
		write-logFile -Message "[INFO] Collecting the Azure Active Directory sign in logs on or after $After"
		$filePath = "Output\AzureAD\SignInLogs.json"

		$signInLogs = Get-AzureADAuditSignInLogs -Filter "createdDateTime gt $After"
		$signInLogs | ConvertTo-Json | Out-File -FilePath $filePath

		write-logFile -Message "[INFO] Sign-in logs written to $filePath" -Color "Green"
	}

	elseif (($Before -ne "") -and ($After -eq "")) {
		write-logFile -Message "[INFO] Collecting the Azure Active Directory sign in logs on or before $Before"
		$filePath = "Output\AzureAD\SignInLogs.json"

		$signInLogs = Get-AzureADAuditSignInLogs -Filter "createdDateTime lt $Before"
		$signInLogs | ConvertTo-Json | Out-File -FilePath $filePath

		write-logFile -Message "[INFO] Sign-in logs written to $filePath" -Color "Green"
	}

	else {
		write-logFile -Message "[WARNING] Please only provide 1 start date or end date" -Color "Red"
	}
}

function Get-ADAuditLogs {
<#
    .SYNOPSIS
    Get directory audit logs.

    .DESCRIPTION
    The Get-AzureADAuditDirectoryLogs cmdlet gets an Azure Active Directory audit log.
	The output will be written to: "Output\AzureAD\Auditlogs.json

	.PARAMETER After
	The After parameter specifies the date from which all logs need to be collected.

	.PARAMETER Before
    The Before parameter specifies the date before which all logs need to be collected.
    
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
		[string]$Before
	)

	try {
		$areYouConnected = Get-AzureADAuditSignInLogs -ErrorAction stop
	}
	catch {
		write-logFile -Message "[WARNING] You must call Connect-Azure before running this script" -Color "Red"
		break
	}

	write-logFile -Message "[INFO] Running Get-AADAuditLogs" -Color "Green"
	
	$outputDir = "Output\AzureAD"
	if (!(test-path $outputDir)) {
		write-logFile -Message "[INFO] Creating the following directory: $outputDir"
		New-Item -ItemType Directory -Force -Name $outputDir | Out-Null
	}

	if (($After -eq "") -and ($Before -eq "")) {
		write-logFile -Message "[INFO] Collecting the Directory audit logs"
		$filePath = "Output\AzureAD\Auditlogs.json"
		
		$auditLogs = Get-AzureADAuditDirectoryLogs -All $true | Select-Object Id,Category,CorrelationId,Result,ResultReason,ActivityDisplayName,@{N='ActivityDateTime';E={$_.ActivityDateTime.ToString()}},LoggedByService,OperationType,InitiatedBy,TargetResources,AdditionalDetails
		$auditLogs | ConvertTo-Json | Out-File -FilePath $filePath
		
		write-logFile -Message "[INFO] Directory audit logs written to $filePath" -Color "Green"
	}

	elseif (($After -ne "") -and ($Before -eq "")) {
		write-logFile -Message "[INFO] Collecting the Directory audit logs on or after $After"
		$filePath = "Output\AzureAD\Auditlogs.json"
		
		$auditLogs = Get-AzureADAuditDirectoryLogs -Filter "activityDateTime gt $After" | Select-Object Id,Category,CorrelationId,Result,ResultReason,ActivityDisplayName,@{N='ActivityDateTime';E={$_.ActivityDateTime.ToString()}},LoggedByService,OperationType,InitiatedBy,TargetResources,AdditionalDetails
		$auditLogs | ConvertTo-Json | Out-File -FilePath $filePath
		
		write-logFile -Message "[INFO] Directory audit logs written to $filePath" -Color "Green"
	}

	elseif (($Before -ne "") -and ($After -eq "")) {
		write-logFile -Message "[INFO] Collecting the Directory audit logs logs on or before $Before"
		$filePath = "Output\AzureAD\Auditlogs.json"
		
		$auditLogs = Get-AzureADAuditDirectoryLogs -Filter "activityDateTime lt $Before" | Select-Object Id,Category,CorrelationId,Result,ResultReason,ActivityDisplayName,@{N='ActivityDateTime';E={$_.ActivityDateTime.ToString()}},LoggedByService,OperationType,InitiatedBy,TargetResources,AdditionalDetails
		$auditLogs | ConvertTo-Json | Out-File -FilePath $filePath
		
		write-logFile -Message "[INFO] Directory audit logs written to $filePath" -Color "Green"
	}

	else {
		write-logFile -Message "[WARNING] Please only provide 1 start date or end date" -Color "Red"
	}
}
