function Get-ADSignInLogsGraph {
<#
    .SYNOPSIS
    Gets of sign ins logs.

    .DESCRIPTION
    The Get-ADSignInLogsGraph GraphAPI cmdlet collects the contents of the Azure Active Directory sign-in logs.
	The output will be written to: Output\AzureAD\SignInLogsGraph.json

	.PARAMETER After
	The After parameter specifies the date from which all logs need to be collected.

	.PARAMETER Before
    The Before parameter specifies the date before which all logs need to be collected.

	.PARAMETER OutputDir
    outputDir is the parameter specifying the output directory.
	Default: Output\AzureAD
    
    .EXAMPLE
    Get-ADSignInLogsGraph
	Get all audit logs of sign ins.

	.EXAMPLE
    Get-ADSignInLogsGraph -Before 2023-04-12
	Get audit logs before 2023-04-12.

	.EXAMPLE
    Get-ADSignInLogsGraph -After 2023-04-12
	Get audit logs after 2023-04-12.
#>
	[CmdletBinding()]
	param(
		[string]$After,
		[string]$Before,
		[string]$outputDir
	)

	try {
		$areYouConnected = Get-MgAuditLogSignIn -ErrorAction stop
	}
	catch {
		write-logFile -Message "[WARNING] You must call Connect-GraphAPI before running this script" -Color "Red"
		break
	}

	write-logFile -Message "[INFO] Running Get-ADSignInLogsGraph" -Color "Green"

	$date = [datetime]::Now.ToString('yyyyMMddHHmmss')

	if ($outputDir -eq "" ){
		$outputDir = "Output\AzureAD\$date\"
		if (!(test-path $outputDir)) {
			write-logFile -Message "[INFO] Creating the following directory: $outputDir"
			New-Item -ItemType Directory -Force -Name $outputDir | Out-Null
		}
	}

	if (($After -eq "") -and ($Before -eq "")) {
		write-logFile -Message "[INFO] Collecting the Azure Active Directory sign in logs"
		$filePath = "$outputDir\SignInLogsGraph.json"

		$signInLogs = Get-MgAuditLogSignIn -All | Select-Object AppDisplayName,AppId,AppliedConditionalAccessPolicies,ClientAppUsed,ConditionalAccessStatus,CorrelationId,@{N='CreatedDateTime';E={$_.CreatedDateTime.ToString()}},DeviceDetail,IPAddress,Id,IsInteractive,Location,ResourceDisplayName,ResourceId,RiskDetail,RiskEventTypes,RiskEventTypesV2,RiskLevelAggregated,RiskLevelDuringSignIn,RiskState,Status,UserDisplayName,UserId,UserPrincipalName,AdditionalProperties
		$signInLogs | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath

		write-logFile -Message "[INFO] Sign-in logs written to $filePath" -Color "Green"
	}

	elseif (($After -ne "") -and ($Before -eq "")) {
		write-logFile -Message "[INFO] Collecting the Azure Active Directory sign in logs on or after $After"
		$filePath = "$outputDir\SignInLogsGraph.json"

		$signInLogs = Get-MgAuditLogSignIn -All -Filter "createdDateTime gt $After" | Select-Object AppDisplayName,AppId,AppliedConditionalAccessPolicies,ClientAppUsed,ConditionalAccessStatus,CorrelationId,@{N='CreatedDateTime';E={$_.CreatedDateTime.ToString()}},DeviceDetail,IPAddress,Id,IsInteractive,Location,ResourceDisplayName,ResourceId,RiskDetail,RiskEventTypes,RiskEventTypesV2,RiskLevelAggregated,RiskLevelDuringSignIn,RiskState,Status,UserDisplayName,UserId,UserPrincipalName,AdditionalProperties
		$signInLogs | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath

		write-logFile -Message "[INFO] Sign-in logs written to $filePath" -Color "Green"
	}

	elseif (($Before -ne "") -and ($After -eq "")) {
		write-logFile -Message "[INFO] Collecting the Azure Active Directory sign in logs on or before $Before"
		$filePath = "$outputDir\SignInLogsGraph.json"

		$signInLogs = Get-MgAuditLogSignIn -All -Filter "createdDateTime lt $Before" | Select-Object AppDisplayName,AppId,AppliedConditionalAccessPolicies,ClientAppUsed,ConditionalAccessStatus,CorrelationId,@{N='CreatedDateTime';E={$_.CreatedDateTime.ToString()}},DeviceDetail,IPAddress,Id,IsInteractive,Location,ResourceDisplayName,ResourceId,RiskDetail,RiskEventTypes,RiskEventTypesV2,RiskLevelAggregated,RiskLevelDuringSignIn,RiskState,Status,UserDisplayName,UserId,UserPrincipalName,AdditionalProperties
		$signInLogs | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath

		write-logFile -Message "[INFO] Sign-in logs written to $filePath" -Color "Green"
	}

	else {
		write-logFile -Message "[WARNING] Please only provide a start date or end date" -Color "Red"
	}

}

function Get-ADAuditLogsGraph {
<#
    .SYNOPSIS
    Get directory audit logs.

    .DESCRIPTION
    The Get-ADAuditLogsGraph GraphAPI cmdlet to collect the contents of the Azure Active Directory Audit logs.
	The output will be written to: "Output\AzureAD\AuditlogsGraph.json

	.PARAMETER After
	The After parameter specifies the date from which all logs need to be collected.

	.PARAMETER Before
    The Before parameter specifies the date before which all logs need to be collected.

	.PARAMETER OutputDir
    outputDir is the parameter specifying the output directory.
	Default: Output\AzureAD
    
    .EXAMPLE
    Get-ADAuditLogsGraph
	Get directory audit logs.

	.EXAMPLE
    Get-ADAuditLogsGraph -Before 2023-04-12
	Get directory audit logs before 2023-04-12.

	.EXAMPLE
    Get-ADAuditLogsGraph -After 2023-04-12
	Get directory audit logs after 2023-04-12.
#>
	[CmdletBinding()]
	param(
		[string]$After,
		[string]$Before,
		[string]$outputDir
	)

	try {
		$areYouConnected = Get-MgAuditLogDirectoryAudit -ErrorAction stop
	}
	catch {
		Write-logFile -Message "[WARNING] You must call Connect-GraphAPI before running this script" -Color "Red"
		break
	}

	Write-logFile -Message "[INFO] Running Get-ADAuditLogsGraph" -Color "Green"
	
	$date = [datetime]::Now.ToString('yyyyMMddHHmmss') 

	if ($outputDir -eq "" ){
		$outputDir = "Output\AzureAD\$date\"
		if (!(test-path $outputDir)) {
			write-logFile -Message "[INFO] Creating the following directory: $outputDir"
			New-Item -ItemType Directory -Force -Name $outputDir | Out-Null
		}
	}

	if (($After -eq "") -and ($Before -eq "")) {
		Write-logFile -Message "[INFO] Collecting the Directory audit logs"
		$filePath = "$outputDir\AuditlogsGraph.json"
		
		$auditLogs = Get-MgAuditLogDirectoryAudit -All | Select-Object @{N='ActivityDateTime';E={$_.ActivityDateTime.ToString()}},ActivityDisplayName,AdditionalDetails,Category,CorrelationId,Id,InitiatedBy,LoggedByService,OperationType,Result,ResultReason,TargetResources,AdditionalProperties
		$auditLogs | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath
		
		Write-logFile -Message "[INFO] Directory audit logs written to $filePath" -Color "Green"
	}

	elseif (($After -ne "") -and ($Before -eq "")) {
		Write-logFile -Message "[INFO] Collecting the Directory audit logs on or after $After"
		$filePath = "$outputDir\AuditlogsGraph.json"
		
		$auditLogs = Get-MgAuditLogDirectoryAudit -All -Filter "activityDateTime gt $After" | Select-Object @{N='ActivityDateTime';E={$_.ActivityDateTime.ToString()}},ActivityDisplayName,AdditionalDetails,Category,CorrelationId,Id,InitiatedBy,LoggedByService,OperationType,Result,ResultReason,TargetResources,AdditionalProperties
		$auditLogs | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath
		
		Write-logFile -Message "[INFO] Directory audit logs written to $filePath" -Color "Green"
	}

	elseif (($Before -ne "") -and ($After -eq "")) {
		Write-logFile -Message "[INFO] Collecting the Directory audit logs logs on or before $Before"
		$filePath = "$outputDir\$date\AuditlogsGraph.json"
		
		$auditLogs = Get-MgAuditLogDirectoryAudit -All -Filter "activityDateTime lt $Before" | Select-Object @{N='ActivityDateTime';E={$_.ActivityDateTime.ToString()}},ActivityDisplayName,AdditionalDetails,Category,CorrelationId,Id,InitiatedBy,LoggedByService,OperationType,Result,ResultReason,TargetResources,AdditionalProperties
		$auditLogs | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath
		
		Write-logFile -Message "[INFO] Directory audit logs written to $filePath" -Color "Green"
	}

	else {
		Write-logFile -Message "[WARNING] Please only provide a start date or end date" -Color "Red"
	}
}
