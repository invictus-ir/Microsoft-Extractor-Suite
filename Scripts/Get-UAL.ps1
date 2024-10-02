# This contains functions for getting the unified audit log entries
$resultSize = 5000

function Get-UALAll
{
<#
    .SYNOPSIS
    Gets all the unified audit log entries.

    .DESCRIPTION
    Makes it possible to extract all unified audit data out of a Microsoft 365 environment. 
	The output will be written to: Output\UnifiedAuditLog\

	.PARAMETER UserIds
    UserIds is the UserIds parameter filtering the log entries by the account of the user who performed the actions.

	.PARAMETER StartDate
    startDate is the parameter specifying the start date of the date range.
	Default: Today -90 days

	.PARAMETER EndDate
    endDate is the parameter specifying the end date of the date range.
	Default: Now

	.PARAMETER Interval
    Interval is the parameter specifying the interval in which the logs are being gathered.
	Default: 720 minutes

	.PARAMETER Output
    Output is the parameter specifying the CSV or JSON output type.
	Default: CSV

	.PARAMETER OutputDir
	OutputDir is the parameter specifying the output directory.
	Default: Output\UnifiedAuditLog

 	.PARAMETER MergeOutput
    MergeOutput is the parameter specifying if you wish to merge CSV outputs to a single file.

	.PARAMETER Encoding
    Encoding is the parameter specifying the encoding of the CSV/JSON output file.
	Default: UTF8

	.PARAMETER ObjecIDs 
    The ObjectIds parameter filters the log entries by object ID. The object ID is the target object that was acted upon, and depends on the RecordType and Operations values of the event.
	You can enter multiple values separated by commas.
    
    .EXAMPLE
    Get-UALAll
	Gets all the unified audit log entries.
	
	.EXAMPLE
	Get-UALAll -UserIds Test@invictus-ir.com
	Gets all the unified audit log entries for the user Test@invictus-ir.com.
	
	.EXAMPLE
	Get-UALAll -UserIds "Test@invictus-ir.com,HR@invictus-ir.com"
	Gets all the unified audit log entries for the users Test@invictus-ir.com and HR@invictus-ir.com.
	
	.EXAMPLE
	Get-UALAll -UserIds Test@invictus-ir.com -StartDate 1/4/2023 -EndDate 5/4/2023
	Gets all the unified audit log entries between 1/4/2023 and 5/4/2023 for the user Test@invictus-ir.com.
	
	.EXAMPLE
	Get-UALAll -UserIds -Interval 720
	Gets all the unified audit log entries with a time interval of 720.

 	.EXAMPLE
	Get-UALAll -UserIds Test@invictus-ir.com -MergeOutput
	Gets all the unified audit log entries for the user Test@invictus-ir.com and adds a combined output JSON file at the end of acquisition
	
	.EXAMPLE
	Get-UALAll -UserIds Test@invictus-ir.com -Output JSON
	Gets all the unified audit log entries for the user Test@invictus-ir.com in JSON format.
	
#>
	[CmdletBinding()]
	param (
        [string]$StartDate,
        [string]$EndDate,
        [string]$UserIds = "*",
        [int]$Interval = 720,
        [string]$Output = "CSV",
        [switch]$MergeOutput,
        [string]$OutputDir,
        [string]$Encoding = "UTF8",
		[string]$ObjectIds
    )
	
	try {
		$areYouConnected = Get-AdminAuditLogConfig -ErrorAction stop
	}
	catch {
		write-logFile -Message "[INFO] Ensure you are connected to M365 by running the Connect-M365 command before executing this script" -Color "Yellow"
		Write-logFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Color "Red"
		throw
	}

	write-logFile -Message "[INFO] Running Get-UALAll" -Color "Green"

	StartDate
	EndDate
	
	$date = [datetime]::Now.ToString('yyyyMMddHHmmss') 
	if ($OutputDir -eq "" ){
		$OutputDir = "Output\UnifiedAuditLog\$date"
		If (!(test-path $OutputDir)) {
			Write-LogFile -Message "[INFO] Creating the following directory: $OutputDir"
			New-Item -ItemType Directory -Force -Name $OutputDir > $null
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
	
	$resetInterval = $Interval
	
	[DateTime]$currentStart = $script:StartDate
	[DateTime]$currentEnd = $script:EndDate

	Write-LogFile -Message "[INFO] Extracting all available audit logs between $($currentStart.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK")) and $($currentEnd.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK"))" -Color "Green"
	
	$baseSearchQuery = @{
        UserIds    = $UserIds
    }

	if ($ObjectIds) {
        $baseSearchQuery.ObjectIds = $ObjectIds
        Write-LogFile -Message "[INFO] Filtering by ObjectIds: $ObjectIds" -Color "Green"
    }

	while ($currentStart -lt $script:EndDate) {	
		$currentEnd = $currentStart.AddMinutes($Interval)
		$amountResults = Search-UnifiedAuditLog -StartDate $currentStart -EndDate $currentEnd @baseSearchQuery -ResultSize 1 | Select-Object -First 1 -ExpandProperty ResultCount

		if ($null -eq $amountResults) {
			Write-LogFile -Message "[INFO] No audit logs between $($currentStart.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK")) and $($currentEnd.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK")). Moving on!"
			$CurrentStart = $CurrentEnd
		}
		
		elseif ($amountResults -gt 5000) {
			while ($amountResults -gt 5000) {
				$amountResults = Search-UnifiedAuditLog -StartDate $currentStart -EndDate $CurrentEnd -ResultSize 1 @baseSearchQuery | Select-Object -First 1 -ExpandProperty ResultCount
				if ($amountResults -lt 5000) {
					if ($Interval -eq 0) {
						Exit
					}
				}

				else {
					Write-LogFile -Message "[WARNING] $amountResults entries between $($currentStart.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK")) and $($currentEnd.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK")) exceeding the maximum of 5000 of entries" -Color "Red"
					$interval = [math]::Round(($Interval/(($amountResults/5000)*1.25)),2)
					$currentEnd = $currentStart.AddMinutes($Interval)
					Write-LogFile -Message "[INFO] Temporary lowering time interval to $Interval minutes" -Color "Yellow"
				}
			}
		}
															
		else {
			$Interval = $resetInterval
			
			if ($currentEnd -gt $script:EndDate) {
				$currentEnd = $script:EndDate
			}
			
			$currentTries = 0
			$sessionID = $currentStart.ToString("yyyyMMddHHmmss")
				
			while ($true) {
				[Array]$results = Search-UnifiedAuditLog -StartDate $CurrentStart -EndDate $currentEnd -SessionCommand ReturnLargeSet -ResultSize $resultSize @baseSearchQuery 
				$currentCount = 0
				
				if ($null -eq $results -or $results.Count -eq 0) {
					if ($currentTries -lt $retryCount) {
						Write-LogFile -Message "[WARNING] The download encountered an issue and there might be incomplete data" -Color "Red"
						Write-LogFile -Message "[INFO] Sleeping 10 seconds before we try again" -Color "Red"
						Start-Sleep -Seconds 10
						$currentTries = $currentTries + 1
						continue
					}
					
					else{
						Write-LogFile -Message "[WARNING] Empty data set returned between $($currentStart.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK")) and $($currentEnd.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK")). Retry count reached. Moving forward!"
						break
					}
				}
				
				else {					
					$currentTotal = $results[0].ResultCount
					$currentCount = $currentCount + $results.Count
					Write-LogFile -Message "[INFO] Found $currentTotal audit logs between $($currentStart.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK")) and $($currentEnd.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK"))"
					
					if ($currentTotal -eq $results[$results.Count - 1].ResultIndex) {
						$message = "[INFO] Successfully retrieved $($currentCount) records out of total $($currentTotal) for the current time range. Moving on!"
						
						if ($Output -eq "JSON")
						{
							$results = $results | ForEach-Object {
								$_.AuditData = $_.AuditData | ConvertFrom-Json
								$_
							}

							$json = $results | ConvertTo-Json -Depth 100
							$json | Out-File -Append "$OutputDir/UAL-$sessionID.json" -Encoding $Encoding
							Add-Content "$OutputDir/UAL-$sessionID.json" "`n"
							Write-LogFile -Message $message  -Color "Green"
						}
						elseif ($Output -eq "CSV") {
							$results | export-CSV "$OutputDir/UAL-$sessionID.csv" -NoTypeInformation -Append -Encoding $Encoding
							Write-LogFile -Message $message -Color "Green"
						}
						
						break
					}
				}				
			}
			$CurrentStart = $CurrentEnd
		}
	}

	if ($Output -eq "CSV" -and ($MergeOutput.IsPresent)) {
		Write-LogFile -Message "[INFO] Merging output files into one file"
		Merge-OutputFiles -OutputDir $OutputDir -OutputType "CSV" -MergedFileName "UAL-Combined.csv"
	}
	elseif ($Output -eq "JSON" -and ($MergeOutput.IsPresent)) {
		Write-LogFile -Message "[INFO] Merging output files into one file"
		Merge-OutputFiles -OutputDir $OutputDir -OutputType "JSON" -MergedFileName "UAL-Combined.json"
	}

	Write-LogFile -Message "[INFO] Acquisition complete, check the Output directory for your files.." -Color "Green"
}
	
function Get-UALGroup
{
<#
    .SYNOPSIS
    Gets the selected group of unified audit log entries.

    .DESCRIPTION
    Makes it possible to extract a group of specific unified audit data out of a Microsoft 365 environment.
	You can for example extract all Exchange or Azure logging in one go.
	The output will be written to: Output\UnifiedAuditLog\

	.PARAMETER UserIds
    UserIds is the UserIds parameter filtering the log entries by the account of the user who performed the actions.

	.PARAMETER StartDate
    startDate is the parameter specifying the start date of the date range.
	Default: Today -90 days

	.PARAMETER EndDate
    endDate is the parameter specifying the end date of the date range.
	Default: Now

	.PARAMETER Interval
    Interval is the parameter specifying the interval in which the logs are being gathered.
	Default: 1440 minutes

	.PARAMETER Group
    Group is the group of logging needed to be extracted.
	Options are: Exchange, Azure, Sharepoint, Skype and Defender

	.PARAMETER Output
    Output is the parameter specifying the CSV or JSON output type.
	Default: CSV

	.PARAMETER OutputDir
	OutputDir is the parameter specifying the output directory.
	Default: Output\UnifiedAuditLog
 
 	.PARAMETER MergeOutput
    MergeOutput is the parameter specifying if you wish to merge CSV outputs to a single file.
    
	.PARAMETER Encoding
    Encoding is the parameter specifying the encoding of the CSV/JSON output file.
	Default: UTF8

	.PARAMETER ObjecIDs 
    The ObjectIds parameter filters the log entries by object ID. The object ID is the target object that was acted upon, and depends on the RecordType and Operations values of the event.
	You can enter multiple values separated by commas.
	
	.EXAMPLE
	Get-UALGroup -Group Azure
	Gets the Azure related unified audit log entries.
	
	.EXAMPLE
	Get-UALGroup -Group Exchange -UserIds Test@invictus-ir.com
	Gets the Exchange related unified audit log entries for the user Test@invictus-ir.com.
	
	.EXAMPLE
	Get-UALGroup -Group Exchange -UserIds "Test@invictus-ir.com,HR@invictus-ir.com"
	Gets all the unified audit log entries between 1/4/2023 and 5/4/2023 for the users Test@invictus-ir.com and HR@invictus-ir.com.
	
	.EXAMPLE
	Get-UALGroup -Group Azure -StartDate 1/4/2023 -EndDate 5/4/2023
	Gets all the Azure related unified audit log entries between 1/4/2023 and 5/4/2023.
	
	.EXAMPLE
	Get-UALGroup -Group Defender -UserIds Test@invictus-ir.com -Interval 720 -Output JSON
	Gets all the Defender related unified audit log entries for the user Test@invictus-ir.com in JSON format with a time interval of 720.

  	.EXAMPLE
	Get-UALGroup -Group Exchange -MergeOutput
	Gets the Azure related unified audit log entries and adds a combined output JSON file at the end of acquisition
#>
	[CmdletBinding()]
	param(
		[string]$StartDate,
		[string]$EndDate,
		[string]$UserIds = "*",
		[string]$Interval = 1440,
		[string]$Group,
		[string]$Output = "CSV",
  		[switch]$MergeOutput,
		[string]$OutputDir,
		[string]$Encoding = "UTF8",
		[string]$ObjectIds
	)

	try {
		$areYouConnected = Get-AdminAuditLogConfig -ErrorAction stop
	}
	catch {
		write-logFile -Message "[INFO] Ensure you are connected to M365 by running the Connect-M365 command before executing this script" -Color "Yellow"
		Write-logFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Color "Red"
		throw
	}
	
	if ($Group -eq "Exchange") {
		$recordTypes = "ExchangeAdmin","ExchangeAggregatedOperation","ExchangeItem","ExchangeItemGroup","ExchangeItemAggregated","ComplianceDLPExchange","ComplianceSupervisionExchange","MipAutoLabelExchangeItem"	
		$recordFile = "Exchange"
	}
	elseif ($Group -eq "Azure") {
		$recordTypes = "AzureActiveDirectory","AzureActiveDirectoryAccountLogon","AzureActiveDirectoryStsLogon"
		$recordFile = "Azure"
	}
	elseif ($Group -eq "Sharepoint") {
		$recordTypes = "ComplianceDLPSharePoint","SharePoint","SharePointFileOperation","SharePointSharingOperation","SharepointListOperation", "ComplianceDLPSharePointClassification","SharePointCommentOperation", "SharePointListItemOperation", "SharePointContentTypeOperation", "SharePointFieldOperation","MipAutoLabelSharePointItem","MipAutoLabelSharePointPolicyLocation"
		$recordFile = "Sharepoint"
	}
	elseif ($Group -eq "Skype") {
		$recordTypes = "SkypeForBusinessCmdlets","SkypeForBusinessPSTNUsage","SkypeForBusinessUsersBlocked"
		$recordFile = "Skype"
	}
	elseif ($Group -eq "Defender") {
		$recordTypes = "ThreatIntelligence", "ThreatFinder","ThreatIntelligenceUrl","ThreatIntelligenceAtpContent","Campaign","AirInvestigation","WDATPAlerts","AirManualInvestigation","AirAdminActionInvestigation","MSTIC","MCASAlerts"
		$recordFile = "Defender"
	}
	else {
		Write-LogFile -Message "[WARNING] Invalid input. Select Exchange, Azure, Sharepoint, Defender or Skype" -Color red
	}

	write-logFile -Message "[INFO] Running Get-UALGroup" -Color "Green"

	StartDate
	EndDate
	
	if ($OutputDir -eq "" ){
		$OutputDir = "Output\UnifiedAuditLog\$recordFile"
		if (!(test-path $OutputDir)) {
			write-logFile -Message "[INFO] Creating the following directory: $OutputDir"
			New-Item -ItemType Directory -Force -Name $OutputDir > $null
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

	write-logFile -Message "[INFO] Extracting all available audit logs between $($script:StartDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK")) and $($script:EndDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK"))"
	write-logFile -Message "[INFO] The following RecordType(s) are configured to be extracted:"

	$baseSearchQuery = @{
        UserIds    = $UserIds
    }

	if ($ObjectIds) {
        $baseSearchQuery.ObjectIds = $ObjectIds
        Write-LogFile -Message "[INFO] Filtering by ObjectIds: $ObjectIds" -Color "Green"
    }
	
	foreach ($record in $recordTypes) {
		write-logFile -Message "-$record"
	}
	
	foreach ($record in $recordTypes) {
		$resetInterval = $interval
		[DateTime]$currentStart = $script:StartDate
		[DateTime]$currentEnd = $script:EndDate
		
		$specificResult = Search-UnifiedAuditLog -StartDate $script:StartDate -EndDate $script:EndDate -RecordType $record @baseSearchQuery -ResultSize 1 |  Format-List -Property ResultCount| out-string -Stream | select-string ResultCount
		
		if (($null -ne $specificResult) -and ($specificResult -ne 0)) {
			$number = $specificResult.tostring().split(":")[1]
			write-logFile -Message "[INFO]$($number) Records found for $record" -Color "Green"

			while ($currentStart -lt $script:EndDate) {	
				$currentEnd = $currentStart.AddMinutes($Interval)
				$amountResults = Search-UnifiedAuditLog -StartDate $currentStart -EndDate $currentEnd -RecordType $record @baseSearchQuery -ResultSize 1 | Select-Object -First 1 -ExpandProperty ResultCount

				if ($null -eq $amountResults) {
					Write-LogFile -Message "[INFO] No audit logs between $($currentStart.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK")) and $($currentEnd.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK")). Moving on!"
					$CurrentStart = $CurrentEnd
				}

				elseif ($amountResults -gt 5000) {
					while ($amountResults -gt 5000) {
						$amountResults = Search-UnifiedAuditLog -StartDate $currentStart -EndDate $currentEnd -RecordType $record @baseSearchQuery -ResultSize 1 | Select-Object -First 1 -ExpandProperty ResultCount
						if ($amountResults -lt 5000) {
							if ($Interval -eq 0) {
								Exit
							}
						}

						else {
							Write-LogFile -Message "[WARNING] $amountResults entries between $($currentStart.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK")) and $($currentEnd.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK")) exceeding the maximum of 5000 of entries" -Color "Red"
							$interval = [math]::Round(($Interval/(($amountResults/5000)*1.25)),2)
							$currentEnd = $currentStart.AddMinutes($Interval)
							Write-LogFile -Message "[INFO] Temporary lowering time interval to $Interval minutes" -Color "Yellow"
						}
					}
				}
														
				else {
					$Interval = $ResetInterval
				
					
					if ($currentEnd -gt $script:EndDate) {
						$currentEnd = $script:EndDate
					}
					
					$CurrentTries = 0
					$SessionID = $currentStart.ToString("yyyyMMddHHmmss")
						
					while ($true) {					
						[Array]$results = Search-UnifiedAuditLog -StartDate $currentStart -EndDate $currentEnd -RecordType $record @baseSearchQuery -SessionCommand ReturnLargeSet -ResultSize $ResultSize
						$currentCount = 0
						
						if ($null -eq $results -or $results.Count -eq 0) {
							if ($currentTries -lt $retryCount) {
								Write-LogFile -Message "[WARNING] The download encountered an issue and there might be incomplete data" -Color "Red"
								Write-LogFile -Message "[INFO] Sleeping 10 seconds before we try again" -Color "Red"
								Start-Sleep -Seconds 10
								$currentTries = $currentTries + 1
								continue
							}
							
							else{
								Write-LogFile -Message "[WARNING] Empty data set returned between $($currentStart.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK")) and $($currentEnd.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK")). Retry count reached. Moving forward!"
								break
							}
						}
						
						else {	
							$currentTotal = $results[0].ResultCount
							$currentCount = $currentCount + $results.Count
							Write-LogFile -Message "[INFO] Found $currentTotal audit logs between $($currentStart.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK")) and $($currentEnd.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK"))" -Color "Green"

							if ($currentTotal -eq $results[$results.Count - 1].ResultIndex){
								$message = "[INFO] Successfully retrieved $($currentCount) records out of total $($currentTotal) for the current time range. Moving on!"
								
								if ($Output -eq "JSON")
								{
									$results = $results | ForEach-Object {
										$_.AuditData = $_.AuditData | ConvertFrom-Json
										$_
									}

									$json = $results | ConvertTo-Json -Depth 100
									$json | Out-File -Append "$OutputDir/UAL-$sessionID.json" -Encoding $Encoding
									Add-Content "$OutputDir/UAL-$sessionID.json" "`n"
									Write-LogFile -Message $message -Color "Green"
								}
								elseif ($Output -eq "CSV")
								{
									$results | export-CSV "$OutputDir/UAL-$sessionID.csv" -NoTypeInformation -Append -Encoding $Encoding
									Write-LogFile -Message $message -Color "Green"
								}
								break
							}
						}
					}
				}
				
				$currentStart = $currentEnd
			}
		}
		else {
			Write-LogFile -message "[INFO] No Records found for $Record"
		}
	}
	if ($Output -eq "CSV" -and ($MergeOutput.IsPresent)) {
		Write-LogFile -Message "[INFO] Merging output files into one file"
		Merge-OutputFiles -OutputDir $OutputDir -OutputType "CSV" -MergedFileName "UAL-Combined.csv"
	}
	elseif ($Output -eq "JSON" -and ($MergeOutput.IsPresent)) {
		Write-LogFile -Message "[INFO] Merging output files into one file"
		Merge-OutputFiles -OutputDir $OutputDir -OutputType "JSON" -MergedFileName "UAL-Combined.json"
	}
	
	Write-LogFile -Message "[INFO] Acquisition complete, check the Output directory for your files.." -Color "Green"
}

function Get-UALSpecific
{
<#
    .SYNOPSIS
    Gets specific record types of unified audit log.

    .DESCRIPTION
    Makes it possible to extract a group of specific unified audit data out of a Microsoft 365 environment.
	You can for example extract all Exchange or Azure logging in one go.
	The output will be written to: Output\UnifiedAuditLog\

	.PARAMETER UserIds
    UserIds is the UserIds parameter filtering the log entries by the account of the user who performed the actions.

	.PARAMETER StartDate
    startDate is the parameter specifying the start date of the date range.
	Default: Today -90 days

	.PARAMETER EndDate
    endDate is the parameter specifying the end date of the date range.
	Default: Now

	.PARAMETER Interval
    Interval is the parameter specifying the interval in which the logs are being gathered.
	Default: 1440 minutes

	.PARAMETER RecordType
    The RecordType parameter filters the log entries by record type.
	Options are: ExchangeItem, ExchangeAdmin, etc. A total of 236 RecordTypes are supported.

	.PARAMETER Output
    Output is the parameter specifying the CSV or JSON output type.
	Default: CSV

	.PARAMETER OutputDir
	OutputDir is the parameter specifying the output directory.
	Default: Output\UnifiedAuditLog

	.PARAMETER Encoding
    Encoding is the parameter specifying the encoding of the CSV output file.
	Default: UTF8

  	.PARAMETER MergeOutput
    MergeOutput is the parameter specifying if you wish to merge CSV/JSON outputs to a single file.

	.PARAMETER ObjecIDs 
    The ObjectIds parameter filters the log entries by object ID. The object ID is the target object that was acted upon, and depends on the RecordType and Operations values of the event.
	You can enter multiple values separated by commas.

	.EXAMPLE
	Get-UALSpecific -RecordType ExchangeItem
	Gets the ExchangeItem logging from the unified audit log.
	
	.EXAMPLE
	Get-UALSpecific -RecordType MipAutoLabelExchangeItem -UserIds Test@invictus-ir.com
	Gets the MipAutoLabelExchangeItem logging from the unified audit log for the user Test@invictus-ir.com.
	
	.EXAMPLE
	Get-UALSpecific -RecordType PrivacyInsights -UserIds "Test@invictus-ir.com,HR@invictus-ir.com"
	Gets the PrivacyInsights logging from the unified audit log for the uses Test@invictus-ir.com and HR@invictus-ir.com.
	
	.EXAMPLE
	Get-UALSpecific -RecordType ExchangeAdmin -StartDate 1/4/2023 -EndDate 5/4/2023
	Gets the ExchangeAdmin logging from the unified audit log entries between 1/4/2023 and 5/4/2023.
	
	.EXAMPLE
	Get-UALSpecific -RecordType MicrosoftFlow -UserIds Test@invictus-ir.com -StartDate 25/3/2023 -EndDate 5/4/2023 -Interval 720 -Output JSON
	Gets all the MicrosoftFlow logging from the unified audit log for the user Test@invictus-ir.com in JSON format with a time interval of 720.

  	.EXAMPLE
	Get-UALSpecific -RecordType MipAutoLabelExchangeItem -MergeOutput
	Gets the ExchangeItem logging from the unified audit log and adds a combined output JSON file at the end of acquisition
#>
	[CmdletBinding()]
	param(
		[string]$StartDate,
		[string]$EndDate,
		[string]$UserIds = "*",
		[string]$Interval = 1440,
		[Parameter(Mandatory=$true)]$RecordType,
		[string]$Output = "CSV",
  		[switch]$MergeOutput,
  		[string]$OutputDir,
		[string]$Encoding = "UTF8",
		[string]$ObjectIds
	)

	try {
		$areYouConnected = Get-AdminAuditLogConfig -ErrorAction stop
	}
	catch {
		write-logFile -Message "[INFO] Ensure you are connected to M365 by running the Connect-M365 command before executing this script" -Color "Yellow"
		Write-logFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Color "Red"
		throw
	}
	
	write-logFile -Message "[INFO] Running Get-UALSpecific" -Color "Green"

	StartDate
	EndDate

	if ($Output -eq "JSON") {
		$Output = "JSON"
		write-logFile -Message "[INFO] Output set to JSON"
	}
	else {
		$Output = "CSV"
		Write-LogFile -Message "[INFO] Output set to CSV"
	}

	write-logFile -Message "[INFO] Extracting all available audit logs between $($script:StartDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK")) and $($script:EndDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK"))"
	write-logFile -Message "[INFO] The following RecordType(s) are configured to be extracted:"

	$baseSearchQuery = @{
        UserIds    = $UserIds
    }

	if ($ObjectIds) {
        $baseSearchQuery.ObjectIds = $ObjectIds
        Write-LogFile -Message "[INFO] Filtering by ObjectIds: $ObjectIds" -Color "Green"
    }

	foreach ($record in $recordType) {
		write-logFile -Message "-$record"
	}
	
	foreach ($record in $recordType) {
		
		$resetInterval = $Interval
		[DateTime]$currentStart = $script:StartDate
		[DateTime]$currentEnd = $script:EndDate
		
		$specificResult = Search-UnifiedAuditLog -StartDate $script:StartDate -EndDate $script:EndDate -RecordType $record @baseSearchQuery -ResultSize 1 | Select-Object -First 1 -ExpandProperty ResultCount
		
		if (($null -ne $specificResult) -and ($specificResult -ne 0)) {
			if ($OutputDir -eq "" ){
				$OutputDir = "Output\UnifiedAuditLog\$record"
				if (!(test-path $OutputDir)) {
					write-logFile -Message "[INFO] Creating the following output directory: $OutputDir"
					New-Item -ItemType Directory -Force -Name $OutputDir > $null
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

			$number = $specificResult.tostring().split(":")[1]
			write-logFile -Message "[INFO]$($number) Records found for $record" -Color "Green"
			
			while ($currentStart -lt $script:EndDate) {	
				$currentEnd = $currentStart.AddMinutes($Interval)
				$amountResults = Search-UnifiedAuditLog -StartDate $currentStart -EndDate $currentEnd -RecordType $record @baseSearchQuery -ResultSize 1 | Select-Object -First 1 -ExpandProperty ResultCount
				
				
				if ($null -eq $amountResults) {
					Write-LogFile -Message "[INFO] No audit logs between $($currentStart.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK")) and $($currentEnd.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK")). Moving on!"
					$CurrentStart = $CurrentEnd
				}
				
				elseif ($amountResults -gt 5000) {
					while ($amountResults -gt 5000) {
						$amountResults = Search-UnifiedAuditLog -StartDate $currentStart -EndDate $currentEnd -RecordType $record @baseSearchQuery -ResultSize 1 | Select-Object -First 1 -ExpandProperty ResultCount
						if ($amountResults -lt 5000) {
							if ($Interval -eq 0) {
								Exit
							}
						}

						else {
							Write-LogFile -Message "[WARNING] $amountResults entries between $($currentStart.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK")) and $($currentEnd.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK")) exceeding the maximum of 5000 of entries" -Color "Red"
							$interval = [math]::Round(($Interval/(($amountResults/5000)*1.25)),2)
							$currentEnd = $currentStart.AddMinutes($Interval)
							Write-LogFile -Message "[INFO] Temporary lowering time interval to $Interval minutes" -Color "Yellow"
						}
					}
				}				
														
				else {
					$Interval = $ResetInterval
				
					if ($currentEnd -gt $script:endDate) {
						$currentEnd = $script:endDate
					}
					
					$currentTries = 0
					$sessionID = $currentStart.ToString("yyyyMMddHHmmss")
						
					while ($true) {					
						[Array]$results = Search-UnifiedAuditLog -StartDate $currentStart -EndDate $currentEnd -RecordType $record @baseSearchQuery -SessionCommand ReturnLargeSet -ResultSize $ResultSize
						$CurrentCount = 0
						
						if ($null -eq $results -or $results.Count -eq 0) {
							if ($currentTries -lt $retryCount) {
								$currentTries = $currentTries + 1
								continue
							}
							else {
								Write-LogFile -Message "[INFO] No audit logs between $($currentStart.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK")) and $($currentEnd.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK"))"
								break
							}
						}
								
						$currentTotal = $results[0].ResultCount
						$currentCount = $currentCount + $results.Count
						Write-LogFile -Message "[INFO] Found $currentTotal audit logs between $($currentStart.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK")) and $($currentEnd.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK"))" -Color "Green"

						if ($currentTotal -eq $results[$results.Count - 1].ResultIndex) {
							$message = "[INFO] Successfully retrieved $($currentCount) records out of total $($currentTotal) for the current time range. Moving on!"

							if ($Output -eq "JSON")
							{
								$results = $results | ForEach-Object {
									$_.AuditData = $_.AuditData | ConvertFrom-Json
									$_
								}

								$json = $results | ConvertTo-Json -Depth 100
								$json | Out-File -Append "$OutputDir/UAL-$sessionID.json" -Encoding $Encoding
								Add-Content "$OutputDir/UAL-$sessionID.json" "`n"
								Write-LogFile -Message $message -Color "Green"
							}
							elseif ($Output -eq "CSV")
							{
								$results | export-CSV "$OutputDir/UAL-$sessionID.csv" -NoTypeInformation -Append -Encoding $Encoding
								Write-LogFile -Message $message -Color "Green"
							}
							break
						}
					}
				}
		
				$currentStart = $currentEnd
			}
		}
		else {
			Write-LogFile -Message "[INFO] No Records found for $record"
		}
	}

	if ($Output -eq "CSV" -and ($MergeOutput.IsPresent)) {
		Write-LogFile -Message "[INFO] Merging output files into one file"
		Merge-OutputFiles -OutputDir $OutputDir -OutputType "CSV" -MergedFileName "UAL-Combined.csv"
	}
	elseif ($Output -eq "JSON" -and ($MergeOutput.IsPresent)) {
		Write-LogFile -Message "[INFO] Merging output files into one file"
		Merge-OutputFiles -OutputDir $OutputDir -OutputType "JSON" -MergedFileName "UAL-Combined.json"
	}

	Write-LogFile -Message "[INFO] Acquisition complete, check the Output directory for your files.." -Color "Green"
}

function Get-UALSpecificActivity
{
<#
    .SYNOPSIS
    Gets specific activities from the unified audit log.

    .DESCRIPTION
    Makes it possible to extract a group of specific unified audit activities out of a Microsoft 365 environment.
	You can for example extract all Inbox Rules or Azure Changes in one go.
	The output will be written to: Output\UnifiedAuditLog\

	.PARAMETER UserIds
    UserIds is the UserIds parameter filtering the log entries by the account of the user who performed the actions.

	.PARAMETER StartDate
    startDate is the parameter specifying the start date of the date range.
	Default: Today -90 days

	.PARAMETER EndDate
    endDate is the parameter specifying the end date of the date range.
	Default: Now

	.PARAMETER Interval
    Interval is the parameter specifying the interval in which the logs are being gathered.
	Default: 1440 minutes

 	.PARAMETER ActivityType
    The ActivityType parameter filters the log entries by operation or activity type.
	Options are: New-MailboxRule, MailItemsAccessed, etc. A total of 108 common ActivityTypes are supported.

	.PARAMETER Output
    Output is the parameter specifying the CSV or JSON output type.
	Default: CSV

	.PARAMETER OutputDir
	OutputDir is the parameter specifying the output directory.
	Default: Output\UnifiedAuditLog

	.PARAMETER MergeOutput
    MergeOutput is the parameter specifying if you wish to merge CSV/JSON outputs into a single file at the end of the acquisition.

	.PARAMETER Encoding
    Encoding is the parameter specifying the encoding of the CSV/JSON output file.
	Default: UTF8

	.EXAMPLE
	Get-UALSpecificActivity -ActivityType New-InboxRule
	Gets the New-InboxRule logging from the unified audit log.
	
	.EXAMPLE
	Get-UALSpecificActivity -ActivityType FileDownloaded -UserIds Test@invictus-ir.com
	Gets the Sharepoint FileDownload logging from the unified audit log for the user Test@invictus-ir.com.
	
	.EXAMPLE
	Get-UALSpecificActivity -ActivityType Add service principal. -UserIds "Test@invictus-ir.com,HR@invictus-ir.com"
	Gets the Add Service Principal. logging from the unified audit log for the uses Test@invictus-ir.com and HR@invictus-ir.com.
	
	.EXAMPLE
	Get-UALSpecificActivity -ActivityType MailItemsAccessed -StartDate 1/4/2023 -EndDate 5/4/2023
	Gets the MailItemsAccessed logging from the unified audit log entries between 1/4/2023 and 5/4/2023.
	
	.EXAMPLE
	Get-UALSpecificActivity -ActivityType MailItemsAccessed -UserIds Test@invictus-ir.com -StartDate 25/3/2023 -EndDate 5/4/2023 -Interval 720 -Output JSON
	Gets all the MailItemsAccessed logging from the unified audit log for the user Test@invictus-ir.com in JSON format with a time interval of 720.
#>
	[CmdletBinding()]
	param(
		[string]$StartDate,
		[string]$EndDate,
		[string]$UserIds = "*",
		[string]$Interval = 1440,
		[Parameter(Mandatory=$true)]$ActivityType,
		[string]$Output = "CSV",
		[string]$OutputDir,
		[string]$Encoding = "UTF8",
        [switch]$MergeOutput
	)

	try {
		$areYouConnected = Get-AdminAuditLogConfig -ErrorAction stop
	}
	catch {
		write-logFile -Message "[INFO] Ensure you are connected to M365 by running the Connect-M365 command before executing this script" -Color "Yellow"
		throw
	}
	
	write-logFile -Message "[INFO] Running Get-UALSpecificActivity" -Color "Green"

	StartDate
	EndDate
	
	if ($Output -eq "JSON") {
		$Output = "JSON"
		write-logFile -Message "[INFO] Output set to JSON"
	}
	else
	{
		$Output = "CSV"
		write-logFile -Message "[INFO] Output set to CSV"
	}

	write-logFile -Message "[INFO] Extracting all available audit logs between $($script:StartDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK")) and $($script:EndDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK"))"
	write-logFile -Message "[INFO] The following ActivityType(s) are configured to be extracted:"

	foreach ($record in $ActivityType) {
		write-logFile -Message "-$record"
	}
	
	foreach ($record in $ActivityType) {
		
		$resetInterval = $Interval
		[DateTime]$currentStart = $script:StartDate
		[DateTime]$currentEnd = $script:EndDate
		
		$specificResult = Search-UnifiedAuditLog -StartDate $script:StartDate -EndDate $script:EndDate -Operations $record -UserIds $UserIds -ResultSize 1 | Select-Object -First 1 -ExpandProperty ResultCount
		
		if (($null -ne $specificResult) -and ($specificResult -ne 0)) {
			if ($OutputDir -eq "" ){
				$OutputDir = "Output\UnifiedAuditLog\$record\"
				if (!(test-path $OutputDir)) {
					write-logFile -Message "[INFO] Creating the following output directory: $OutputDir"
					New-Item -ItemType Directory -Force -Name $OutputDir > $null 
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

			$number = $specificResult.tostring().split(":")[1]
			write-logFile -Message "[INFO]$($number) Records found for $record" -Color "Green"
			
			while ($currentStart -lt $script:EndDate) {	
				$currentEnd = $currentStart.AddMinutes($Interval)
				$amountResults = Search-UnifiedAuditLog -UserIds $UserIds -StartDate $currentStart -EndDate $currentEnd -Operations $record -ResultSize 1 | Select-Object -First 1 -ExpandProperty ResultCount
				
				
				if ($null -eq $amountResults) {
					Write-LogFile -Message "[INFO] No audit logs between $($currentStart.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK")) and $($currentEnd.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK")). Moving on!"
					$CurrentStart = $CurrentEnd
				}
				
				elseif ($amountResults -gt 5000) {
					while ($amountResults -gt 5000) {
						$amountResults = Search-UnifiedAuditLog -StartDate $currentStart -EndDate $currentEnd -UserIds $UserIds -Operations $record -ResultSize 1 | Select-Object -First 1 -ExpandProperty ResultCount
						if ($amountResults -lt 5000) {
							if ($Interval -eq 0) {
								Exit
							}
						}

						else {
							Write-LogFile -Message "[WARNING] $amountResults entries between $($currentStart.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK")) and $($currentEnd.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK")) exceeding the maximum of 5000 of entries" -Color "Red"
							$interval = [math]::Round(($Interval/(($amountResults/5000)*1.25)),2)
							$currentEnd = $currentStart.AddMinutes($Interval)
							Write-LogFile -Message "[INFO] Temporary lowering time interval to $Interval minutes" -Color "Yellow"
						}
					}
				}				
														
				else {
					$Interval = $ResetInterval
				
					if ($currentEnd -gt $script:endDate) {
						$currentEnd = $script:endDate
					}
					
					$currentTries = 0
					$sessionID = $currentStart.ToString("yyyyMMddHHmmss")
						
					while ($true) {					
						[Array]$results = Search-UnifiedAuditLog -StartDate $currentStart -EndDate $currentEnd -UserIds $UserIds -Operations $record -SessionCommand ReturnLargeSet -ResultSize $ResultSize
						$CurrentCount = 0
						
						if ($null -eq $results -or $results.Count -eq 0) {
							if ($currentTries -lt $retryCount) {
								$currentTries = $currentTries + 1
								continue
							}
							else {
								Write-LogFile -Message "[INFO] No audit logs between $($currentStart.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK")) and $($currentEnd.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK"))"
								break
							}
						}
								
						$currentTotal = $results[0].ResultCount
						$currentCount = $currentCount + $results.Count
						Write-LogFile -Message "[INFO] Found $currentTotal audit logs between $($currentStart.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK")) and $($currentEnd.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK"))"

						if ($currentTotal -eq $results[$results.Count - 1].ResultIndex) {
							$message = "[INFO] Successfully retrieved $($currentCount) records out of total $($currentTotal) for the current time range. Moving on!"

							if ($Output -eq "JSON")
							{
								$results = $results | ForEach-Object {
									$_.AuditData = $_.AuditData | ConvertFrom-Json
									$_
								}

								$json = $results | ConvertTo-Json -Depth 100
								$json | Out-File -Append "$OutputDir/UAL-$sessionID.json" -Encoding $Encoding
								Add-Content "$OutputDir/UAL-$sessionID.json" "`n"
								Write-LogFile -Message $message -Color "Green"
							}
							elseif ($Output -eq "CSV")
							{
								$results | export-CSV "$OutputDir/UAL-$sessionID.csv" -NoTypeInformation -Append -Encoding $Encoding
								Write-LogFile -Message $message -Color "Green"
							}
							break
						}
					}
				}
		
				$currentStart = $currentEnd
			}
		}
		else {
			Write-LogFile -Message "[INFO] No Records found for $record"
		}
	}
	if ($Output -eq "CSV" -and ($MergeOutput.IsPresent)) {
		Write-LogFile -Message "[INFO] Merging output files into one file"
		Merge-OutputFiles -OutputDir $OutputDir -OutputType "CSV" -MergedFileName "UAL-Combined.csv"
	}
	elseif ($Output -eq "JSON" -and ($MergeOutput.IsPresent)) {
		Write-LogFile -Message "[INFO] Merging output files into one file"
		Merge-OutputFiles -OutputDir $OutputDir -OutputType "JSON" -MergedFileName "UAL-Combined.json"
	}

	Write-LogFile -Message "[INFO] Acquisition complete, check the Output directory for your files.." -Color "Green"
}
