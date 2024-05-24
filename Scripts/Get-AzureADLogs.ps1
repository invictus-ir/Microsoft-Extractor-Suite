# This contains functions for getting Azure AD logging

function Get-ADSignInLogs {
<#
	.SYNOPSIS
	Get sign-in logs.

	.DESCRIPTION
	The Get-ADSignInLogs cmdlet collects the contents of the Azure Active Directory sign-in logs.

	.PARAMETER startDate
	The startDate parameter specifies the date from which all logs need to be collected.

	.PARAMETER endDate
	The Before parameter specifies the date endDate which all logs need to be collected.

	.PARAMETER OutputDir
	OutputDir is the parameter specifying the output directory.
	Default: The output will be written to: Output\AzureAD\{date_SignInLogs}\SignInLogs.json

	.PARAMETER Encoding
	Encoding is the parameter specifying the encoding of the JSON output file.
	Default: UTF8

	.PARAMETER MergeOutput
	MergeOutput is the parameter specifying if you wish to merge outputs to a single file
	Default: No

	.PARAMETER UserIds
	UserIds is the UserIds parameter filtering the log entries by the account of the user who performed the actions.

	.PARAMETER Interval
    Interval is the parameter specifying the interval in which the logs are being gathered.
	Default: 720 minutes
	
	.EXAMPLE
	Get-ADSignInLogs
	Get all sign-in logs.

	.EXAMPLE
	Get-ADAuditLogs -UserIds Test@invictus-ir.com
	Get sign-in logs for the user Test@invictus-ir.com.

	.EXAMPLE
	Get-ADSignInLogs -endDate 2023-04-12
	Get sign-in logs before 2023-04-12.

	.EXAMPLE
	Get-ADSignInLogs -startDate 2023-04-12
	Get sign-in logs after 2023-04-12.
#>
	[CmdletBinding()]
	param(
		[string]$startDate,
		[string]$endDate,
		[string]$outputDir,
		[string]$UserIds,
		[switch]$MergeOutput,
		[string]$Encoding,
		[string]$Interval
	)

	try {
		import-module AzureADPreview -force -ErrorAction stop
		$areYouConnected = Get-AzureADAuditSignInLogs -ErrorAction stop
	}
	catch {
		Write-logFile -Message "[WARNING] You must call Connect-Azure or install AzureADPreview before running this script" -Color "Red"
		break
	}

	Write-logFile -Message "[INFO] Running Get-AADSignInLogs" -Color "Green"

	StartDateAz
	EndDate

	if ($Interval -eq "") {
		$Interval = 1440
		Write-LogFile -Message "[INFO] Setting the Interval to the default value of 1440"
	}

	if ($Encoding -eq "" ){
		$Encoding = "UTF8"
	}

	$date = [datetime]::Now.ToString('yyyyMMddHHmmss') 
	if ($OutputDir -eq "" ){
		$OutputDir = "Output\AzureAD\$($date)_SignInLogs"
		if (!(test-path $OutputDir)) {
			write-logFile -Message "[INFO] Creating the following directory: $OutputDir"
			New-Item -ItemType Directory -Force -Name $OutputDir | Out-Null
		}
	}

	if ($UserIds){
		Write-LogFile -Message "[INFO] UserID's eq $($UserIds)"
	}

	$filePath = "$OutputDir\SignInLogs.json"
		
	[DateTime]$currentStart = $script:StartDate
	[DateTime]$currentEnd = $script:EndDate
	[DateTime]$lastLog = $script:EndDate
	$currentDay = 0  

	Write-LogFile -Message "[INFO] Extracting all available Directory Sign-in Logs between $($currentStart.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")) and $($currentEnd.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"))" -Color "Green"
	if($currentStart -gt $script:EndDate){
		Write-LogFile -Message "[ERROR] $($currentStart.ToString("yyyy-MM-ddTHH:mm:ssZ")) is greather than $($script:EndDate.ToString("yyyy-MM-ddTHH:mm:ssZ")) - are you sure you put in the correct year? Exiting!" -Color "Red"
		return
	}

	while ($currentStart -lt $script:EndDate) {			
		$currentEnd = $currentStart.AddMinutes($Interval)
		$retryCount = 0
		$maxRetries = 3
		$success = $false

		while (-not $success -and $retryCount -lt $maxRetries) {
			try {
				if ($UserIds) {
					Write-LogFile -Message "[INFO] Collecting Directory Sign-in logs between $($currentStart.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")) and $($currentEnd.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"))."
					[Array]$results = Get-AzureADAuditSignInLogs -All $true -Filter "UserPrincipalName eq '$($UserIds)' and createdDateTime lt $($currentEnd.ToString("yyyy-MM-ddTHH:mm:ssZ")) and createdDateTime gt $($currentStart.ToString("yyyy-MM-ddTHH:mm:ssZ"))"
				} else {
					Write-LogFile -Message "[INFO] Collecting Directory Sign-in logs between $($currentStart.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")) and $($currentEnd.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"))."
					[Array]$results = Get-AzureADAuditSignInLogs -All $true -Filter "createdDateTime lt $($currentEnd.ToString("yyyy-MM-ddTHH:mm:ssZ")) and createdDateTime gt $($currentStart.ToString("yyyy-MM-ddTHH:mm:ssZ"))"
				}
				$success = $true
			}

			catch {
				$retryCount++
				if ($retryCount -lt $maxRetries) {
					Start-Sleep -Seconds 10
					Write-LogFile -Message "[WARNING] Failed to acquire logs. Retrying... Attempt $retryCount of $maxRetries" -Color "Yellow"
				} else {
					Write-LogFile -Message "[ERROR] Failed to acquire logs after $maxRetries attempts. Moving on." -Color "Red"
				}
			}
		}
				
		if ($null -eq $results -or $results.Count -eq 0) {
			Write-LogFile -Message "[WARNING] Empty data set returned between $($currentStart.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")) and $($currentEnd.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")). Moving On!" -Color "Yellow"				
		}
		else {					
			$currentCount = $results.Count	
			Write-LogFile -Message "[INFO] Found $currentCount Directory Sign-in Logs between $($currentStart.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")) and $($currentEnd.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"))" -Color "Green"
				
			$filePath = "$OutputDir\SignInLogs-$($CurrentStart.ToString("yyyyMMdd"))-$($CurrentEnd.ToString("yyyyMMdd")).json"
			$results | ConvertTo-Json -Depth 100 | Out-File -Append $filePath -Encoding $Encoding

			Write-LogFile -Message "[INFO] Successfully retrieved $($currentCount) records for the current time range."							
		}
		[Array]$results = @()
		$CurrentStart = $CurrentEnd
		$currentDay++
	}
	
	if ($MergeOutput.IsPresent)
	{
		Write-LogFile -Message "[INFO] Merging output files into one file"
		$outputDirMerged = "$OutputDir\Merged\"
		If (!(test-path $outputDirMerged)) {
			Write-LogFile -Message "[INFO] Creating the following directory: $outputDirMerged"
			New-Item -ItemType Directory -Force -Path $outputDirMerged | Out-Null  
		}

		$allJsonObjects = @()

		Get-ChildItem $OutputDir -Filter *.json | ForEach-Object {
			$content = Get-Content -Path $_.FullName -Raw
			$jsonObjects = $content | ConvertFrom-Json
			$allJsonObjects += $jsonObjects
		}
	
		$allJsonObjects | ConvertTo-Json -Depth 100 | Set-Content "$outputDirMerged\SignInLogs-Combined.json"
	}
	
	Write-LogFile -Message "[INFO] Acquisition complete, check the $($OutputDir) directory for your files.." -Color "Green"		
}
	
function Get-ADAuditLogs {
<#
	.SYNOPSIS
	Get directory audit logs.

	.DESCRIPTION
	The Get-ADAuditLogs cmdlet collects the contents of the Azure Active Directory Audit logs.

	.PARAMETER startDate
	The startDate parameter specifies the date from which all logs need to be collected.

	.PARAMETER endDate
	The endDate parameter specifies the date before which all logs need to be collected.

	.PARAMETER OutputDir
	outputDir is the parameter specifying the output directory.
	Default: The output will be written to: "Output\AzureAD\{date_AuditLogs}\Auditlogs.json

	.PARAMETER Encoding
	Encoding is the parameter specifying the encoding of the JSON output file.
	Default: UTF8

	.PARAMETER MergeOutput
	MergeOutput is the parameter specifying if you wish to merge outputs to a single file
	Default: No

	.PARAMETER UserIds
	UserIds is the UserIds parameter filtering the log entries by the account of the user who performed the actions.

	.PARAMETER Interval
    Interval is the parameter specifying the interval in which the logs are being gathered.
	Default: 720 minutes
	
	.EXAMPLE
	Get-ADAuditLogs
	Get directory audit logs.

	.EXAMPLE
	Get-ADAuditLogs -UserIds Test@invictus-ir.com
	Get directory audit logs for the user Test@invictus-ir.com.

	.EXAMPLE
	Get-ADAuditLogs -endDate 2024-04-12T01:00:00Z
	Get directory audit logs before 2023-04-12 at 01:00.

	.EXAMPLE
	Get-ADAuditLogs -startDate 2024-04-12T01:00:00Z
	Get directory audit logs after 2023-04-12 at 01:00.

	.EXAMPLE
	Get-ADAuditLogs -startDate 2024-04-12T01:00:00Z -endDate 2024-04-12T02:00:00Z
	Get directory audit logs after 2023-04-12 between 01:00 and 02:00
#>
	[CmdletBinding()]
	param(
		[string]$startDate,
		[string]$endDate,
		[string]$outputDir,
		[string]$UserIds,
		[switch]$MergeOutput,
		[string]$Encoding,
		[string]$Interval
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
	
	StartDateAz
	EndDate

	if ($Interval -eq "") {
		$Interval = 720
		Write-LogFile -Message "[INFO] Setting the Interval to the default value of 720 (Larger values may result in out of memory errors)"
	}


	$date = [datetime]::Now.ToString('yyyyMMddHHmmss') 
	if ($OutputDir -eq "" ){
		$OutputDir = "Output\AzureAD\$($date)_AuditLogs"
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

	if ($UserIds){
		Write-LogFile -Message "[INFO] UserID's eq $($UserIds)"
	}

	$filePath = "$OutputDir\$($date)-Auditlogs.json"

	[DateTime]$currentStart = $script:StartDate
	[DateTime]$currentEnd = $script:EndDate
	$currentDay = 0  

	Write-LogFile -Message "[INFO] Extracting all available Directory Audit Logs between $($currentStart.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")) and $($currentEnd.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"))" -Color "Green"
	if($currentStart -gt $script:EndDate){
		Write-LogFile -Message "[ERROR] $($currentStart.ToString("yyyy-MM-ddTHH:mm:ssZ")) is greather than $($script:EndDate.ToString("yyyy-MM-ddTHH:mm:ssZ")) - are you sure you put in the correct year? Exiting!" -Color "Red"
		return
	}

	while ($currentStart -lt $script:EndDate) {			
		$currentEnd = $currentStart.AddMinutes($Interval)
		$retryCount = 0
		$maxRetries = 3
		$success = $false

		while (-not $success -and $retryCount -lt $maxRetries) {
			try {
				if ($UserIds) {
					Write-LogFile -Message "[INFO] Collecting Directory Audit logs between $($currentStart.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")) and $($currentEnd.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"))."
					[Array]$results = Get-AzureADAuditDirectoryLogs -All $true -Filter "initiatedBy/user/userPrincipalName eq '$UserIds' and activityDateTime gt $($currentStart.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")) and activityDateTime lt $($currentEnd.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"))" | Select-Object Id,Category,CorrelationId,Result,ResultReason,ActivityDisplayName,@{N='ActivityDateTime';E={$_.ActivityDateTime.ToString()}},LoggedByService,OperationType,InitiatedBy,TargetResources,AdditionalDetails
				} else {
					Write-LogFile -Message "[INFO] Collecting Directory Audit logs between $($currentStart.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")) and $($currentEnd.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"))."
					[Array]$results = Get-AzureADAuditDirectoryLogs -All $true -Filter "activityDateTime gt $($currentStart.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")) and activityDateTime lt $($currentEnd.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"))" | Select-Object Id,Category,CorrelationId,Result,ResultReason,ActivityDisplayName,@{N='ActivityDateTime';E={$_.ActivityDateTime.ToString()}},LoggedByService,OperationType,InitiatedBy,TargetResources,AdditionalDetails
				}
				$success = $true
			}
			catch {
				$retryCount++
				if ($retryCount -lt $maxRetries) {
					Start-Sleep -Seconds 10
					Write-LogFile -Message "[WARNING] Failed to acquire logs. Retrying... Attempt $retryCount of $maxRetries" -Color "Yellow"
				} else {
					Write-LogFile -Message "[ERROR] Failed to acquire logs after $maxRetries attempts. Moving on." -Color "Red"
				}
			}
		}

		if ($null -eq $results -or $results.Count -eq 0) {
			Write-LogFile -Message "[WARNING] Empty data set returned between $($currentStart.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")) and $($currentEnd.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")). Moving On!" -Color "Yellow"		
		}
		else {					
			$currentCount = $results.Count		
			Write-LogFile -Message "[INFO] Found $currentCount Directory Audit Logs between $($currentStart.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")) and $($currentEnd.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"))" -Color "Green"
				
			$filePath = "$OutputDir\AuditLogs-$($CurrentStart.ToString("yyyyMMddHHmmss"))-$($CurrentEnd.ToString("yyyyMMddHHmmss")).json"
			$results | ConvertTo-Json -Depth 100 | Out-File -Append $filePath -Encoding $Encoding

			Write-LogFile -Message "[INFO] Successfully retrieved $($currentCount) records for the current time range."							
		}
		[Array]$results = @()
		$CurrentStart = $CurrentEnd
		$currentDay++
	}
	
	if ($MergeOutput.IsPresent)
	{
		Write-LogFile -Message "[INFO] Merging output files into one file"
		$outputDirMerged = "$OutputDir\Merged\"
		If (!(test-path $outputDirMerged)) {
			Write-LogFile -Message "[INFO] Creating the following directory: $outputDirMerged"
			New-Item -ItemType Directory -Force -Path $outputDirMerged | Out-Null
		}

		$allJsonObjects = @()

		Get-ChildItem $OutputDir -Filter *.json | ForEach-Object {
			$content = Get-Content -Path $_.FullName -Raw
			$jsonObjects = $content | ConvertFrom-Json
			$allJsonObjects += $jsonObjects
		}
	
		$allJsonObjects | ConvertTo-Json -Depth 100 | Set-Content "$outputDirMerged\AuditLogs-Combined.json"
	}
	
	Write-LogFile -Message "[INFO] Acquisition complete, check the $($OutputDir) directory for your files.." -Color "Green"		
}
