$resultSize = 5000

function Get-UAL {
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
	Default: Today -180 days

	.PARAMETER EndDate
    endDate is the parameter specifying the end date of the date range.
	Default: Now

	.PARAMETER Output
    Output is the parameter specifying the CSV, JSON, or SOF-ELK output type. The SOF-ELK output can be imported into the platform of the same name.
	Default: CSV

	.PARAMETER OutputDir
	OutputDir is the parameter specifying the output directory.
	Default: Output\UnifiedAuditLog

 	.PARAMETER MergeOutput
    MergeOutput is the parameter specifying if you wish to merge CSV/JSON/SOF-ELK outputs to a single file.

	.PARAMETER Encoding
    Encoding is the parameter specifying the encoding of the CSV/JSON output file.
	Default: UTF8

	.PARAMETER ObjecIDs 
    The ObjectIds parameter filters the log entries by object ID. The object ID is the target object that was acted upon, and depends on the RecordType and Operations values of the event.
	You can enter multiple values separated by commas.

	.DESCRIPTION
	Makes it possible to extract all unified audit data out of a Microsoft 365 environment. 
	The output will be written to: Output\UnifiedAuditLog\

	.PARAMETER Interval
	Interval is the parameter specifying the interval in which the logs are being gathered.

	.PARAMETER Group
    Group is the group of logging needed to be extracted.
	Options are: Exchange, Azure, Sharepoint, Skype and Defender

    .PARAMETER RecordType
    The RecordType parameter filters the log entries by record type.
	Options are: ExchangeItem, ExchangeAdmin, etc. A total of 353 RecordTypes are supported.

 	.PARAMETER Operation
    The Operation parameter filters the log entries by operation or activity type.
	Options are: New-MailboxRule, MailItemsAccessed, etc. A total of 108 common Operations are supported.

	.PARAMETER LogLevel
	Specifies the level of logging:
	None: No logging
	Minimal: Critical errors only
	Standard: Normal operational logging
	Default: Standard
	
	.EXAMPLE
	Get-UAL
	Gets all the unified audit log entries.
	
	.EXAMPLE
	Get-UAL -UserIds Test@invictus-ir.com
	Gets all the unified audit log entries for the user Test@invictus-ir.com.
	
	.EXAMPLE
	Get-UAL -UserIds "Test@invictus-ir.com,HR@invictus-ir.com"
	Gets all the unified audit log entries for the users Test@invictus-ir.com and HR@invictus-ir.com.
	
	.EXAMPLE
	Get-UAL -UserIds Test@invictus-ir.com -StartDate 1/4/2024 -EndDate 5/4/2024
	Gets all the unified audit log entries between 1/4/2024 and 5/4/2024 for the user Test@invictus-ir.com.
	
	.EXAMPLE
	Get-UAL -UserIds -Interval 720
	Gets all the unified audit log entries with a time interval of 720.

	 .EXAMPLE
	Get-UAL -UserIds Test@invictus-ir.com -MergeOutput
	Gets all the unified audit log entries for the user Test@invictus-ir.com and adds a combined output JSON file at the end of acquisition
	
	.EXAMPLE
	Get-UAL -UserIds Test@invictus-ir.com -Output JSON
	Gets all the unified audit log entries for the user Test@invictus-ir.com in JSON format.	

	.EXAMPLE
	Get-UAL -Group Azure
	Gets the Azure related unified audit log entries.

    .EXAMPLE
	Get-UAL -RecordType ExchangeItem
	Gets the ExchangeItem logging from the unified audit log.

	.EXAMPLE
	Get-UAL -RecordType ExchangeItem -Group Azure
	Gets the ExchangeItem and all Azure related logging from the unified audit log.

	.EXAMPLE
	Get-UAL -Operation New-InboxRule
	Gets the New-InboxRule logging from the unified audit log.
#>

	[CmdletBinding()]
		param (
			[string]$StartDate,
			[string]$EndDate,
			[string]$UserIds = "*",
			[decimal]$Interval,
			[ValidateSet("Exchange", "Azure", "Sharepoint", "Skype", "Defender")]
			[string]$Group = $null,
			[array]$RecordType = $null,
			[array]$Operation = $null,
			[ValidateSet("CSV", "JSON", "SOF-ELK")]
			[string]$Output = "CSV",
			[switch]$MergeOutput,
			[string]$OutputDir,
			[string]$Encoding = "UTF8",
			[string]$ObjectIds,
			[ValidateSet('None', 'Minimal', 'Standard')]
			[string]$LogLevel = 'Standard'
		)

	Set-LogLevel -Level ([LogLevel]::$LogLevel)
	$stats = @{
		StartTime = Get-Date
		ProcessingTime = $null
		TotalRecords = 0
		FilesCreated = 0
		IntervalAdjustments = 0
	}

	Write-LogFile -Message "=== Starting Unified Audit Log Collection ===" -Color "Cyan" -Level Minimal

	try {
		$areYouConnected = Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-1) -EndDate (Get-Date) -ResultSize 1 -ErrorAction Stop
	}
	catch {
		write-logFile -Message "[INFO] Ensure you are connected to M365 by running the Connect-M365 command before executing this script" -Color "Yellow" -Level Minimal
		Write-logFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Color "Red" -Level Minimal
		throw
	}

	StartDateUAL -Quiet
	EndDate -Quiet

	$baseSearchQuery = @{
		UserIds = $UserIds
	}	

	if ($ObjectIds) {
        $baseSearchQuery.ObjectIds = $ObjectIds
    }

	if ($Operation) {
		$baseSearchQuery.Operations = $Operation
	}

	$totalResults = 0
	$recordTypes = [System.Collections.ArrayList]::new()

	$date = [datetime]::Now.ToString('yyyyMMddHHmmss')
	if ($OutputDir -eq "") {
		$OutputDir = "Output\UnifiedAuditLog\$date"
		If (!(test-path $OutputDir)) {
			New-Item -ItemType Directory -Force -Name $OutputDir > $null
		}
	} else {
		if (!(Test-Path -Path $OutputDir)) {
			Write-Error "[Error] Custom directory invalid: $OutputDir exiting script" -ErrorAction Stop
			Write-LogFile -Message "[Error] Custom directory invalid: $OutputDir exiting script" -Level Minimal
		}
	}

	$GroupRecordTypes = @{
        "Exchange" = @("ExchangeAdmin","ExchangeAggregatedOperation","ExchangeItem","ExchangeItemGroup",
                      "ExchangeItemAggregated","ComplianceDLPExchange","ComplianceSupervisionExchange",
                      "MipAutoLabelExchangeItem")
        "Azure" = @("AzureActiveDirectory","AzureActiveDirectoryAccountLogon","AzureActiveDirectoryStsLogon")
        "Sharepoint" = @("ComplianceDLPSharePoint","SharePoint","SharePointFileOperation","SharePointSharingOperation",
                        "SharepointListOperation","ComplianceDLPSharePointClassification","SharePointCommentOperation",
                        "SharePointListItemOperation","SharePointContentTypeOperation","SharePointFieldOperation",
                        "MipAutoLabelSharePointItem","MipAutoLabelSharePointPolicyLocation")
        "Skype" = @("SkypeForBusinessCmdlets","SkypeForBusinessPSTNUsage","SkypeForBusinessUsersBlocked")
        "Defender" = @("ThreatIntelligence","ThreatFinder","ThreatIntelligenceUrl","ThreatIntelligenceAtpContent",
                      "Campaign","AirInvestigation","WDATPAlerts","AirManualInvestigation",
                      "AirAdminActionInvestigation","MSTIC","MCASAlerts")
    }

    if ($Group) {
        if ($null -eq $GroupRecordTypes[$Group]) {
            Write-LogFile -Message "[WARNING] Invalid input for -Group. Select Exchange, Azure, Sharepoint, Defender or Skype" -Color "Red" -Level Minimal
            return
        }
        $recordTypes.AddRange($GroupRecordTypes[$Group])
    }

	if ($RecordType) {
		if ($RecordType -is [string]) {
			$recordTypesArray = $RecordType.Split(',').Trim()
			foreach ($item in $recordTypesArray) {
				[void]$recordTypes.Add($item)
			}
		} else {
			# Handle array input
			foreach ($item in $RecordType) {
				[void]$recordTypes.Add($item)
			}
		}
	}

	Write-LogFile -Message "Start date: $($script:StartDate.ToString('yyyy-MM-dd HH:mm:ss'))" -Level Standard
	Write-LogFile -Message "End date: $($script:EndDate.ToString('yyyy-MM-dd HH:mm:ss'))" -Level Standard
	Write-LogFile -Message "Output format: $Output" -Level Standard
	Write-LogFile -Message "Output Directory: $OutputDir" -Level Standard
	if ($recordTypes.Count -gt 0) {
		Write-LogFile -Message "`nThe following RecordType(s) are configured to be extracted:" -Level Standard
		foreach ($record in $recordTypes) {
			Write-LogFile -Message "  - $record" -Level Standard
		}
	}
	if ($Operation) {
		Write-LogFile -Message "`nThe following Operation(s) are configured to be extracted:" -Level Standard
		foreach ($activity in $Operation) {
			Write-LogFile -Message "- $activity" -Level Standard
		}
	}
    Write-LogFile -Message "----------------------------------------`n" -Level Standard

	if ($recordTypes.Count -eq 0) {
        [void]$recordTypes.Add("*")
    }

	$maxRetries = 3
    $baseDelay = 10
	$retryCount = 0 

	foreach ($record in $recordTypes) {
		if ($record -ne "*") {
			Write-LogFile -Message "=== Processing RecordType: $record ===" -Color "Cyan" -Level Standard
			$baseSearchQuery.RecordType = $record
		} else {
			$baseSearchQuery.Remove('RecordType')
		}
	
		$retryAttempt = 0
		$success = $false
		while (!$success -and $retryAttempt -lt $maxRetries) {
			try {
				$totalResults = Search-UnifiedAuditLog -StartDate $script:StartDate -EndDate $script:EndDate @baseSearchQuery -ResultSize 1 | Select-Object -First 1 -ExpandProperty ResultCount
				if ($null -ne $totalResults) {
					$message = if ($record -eq "*") {
						"[INFO] Total number of events during the acquisition period: $totalResults"
					} else {
						"[INFO] The record '$record' contains $totalResults events during the acquisition period"
					}
					
					Write-LogFile -Message $message -Level Standard -color "Green"
				}
				$success = $true
			}
			catch {
				if ($_.Exception.Message -like "*server side error*" -or 
					$_.Exception.Message -like "*operation could not be completed*") {
					
					$retryAttempt++
					if ($retryAttempt -eq $maxRetries) {
						Write-LogFile -Message "[ERROR] Maximum retry attempts reached for initial count. Last error: $($_.Exception.Message)" -Color "Red" -Level Minimal
						throw
					}
					
					Write-LogFile -Message "[WARNING] Server-side error on initial count attempt $retryAttempt of $maxRetries. Waiting $baseDelay seconds..." -Color "Yellow" -Level Minimal
					Start-Sleep -Seconds $baseDelay
					$baseDelay *= 2
					continue
				}
				else {
					throw
				}
			}
		}

		if ($null -eq $totalResults -or $totalResults -eq 0) {
			$message = if ($record -eq "*") {
				"[INFO] No records found!"
			} else {
				"[INFO] No records found for RecordType: $record"
			}
            Write-LogFile -Message "[INFO] No records found for RecordType: $record" -Level Standard -Color "Yellow"
            continue
        }

        if (!$PSBoundParameters.ContainsKey('Interval')) {
            $totalMinutes = ($script:EndDate - $script:StartDate).TotalMinutes
            $estimatedIntervals = [math]::Ceiling($totalResults / 50000)
            
            if ($estimatedIntervals -eq 0) {
                $Interval = $totalMinutes
            } else {
                $Interval = [math]::Max(1, [math]::Floor($totalMinutes / $estimatedIntervals))
            }
        }

		$resetInterval = $Interval
		[DateTime]$currentStart = $script:StartDate
		[DateTime]$currentEnd = $script:EndDate
		$finalEndDate = $script:EndDate.ToUniversalTime()

		$maxRetries = 3
		$baseDelay = 10
		$retryCount = 0 

		while ($currentStart -lt $finalEndDate) {	
			$currentEnd = $currentStart.AddMinutes($Interval)
	
			if ($currentEnd -gt $finalEndDate) {
				$currentEnd = $finalEndDate
			}

			if ($currentEnd -le $currentStart) {
				Write-LogFile -Message "[INFO] Reached end of date range" -Level Standard
				break
			}
			
			$retryAttempt = 0
			$currentDelay = $baseDelay
			$success = $false
	
			while (!$success -and $retryAttempt -lt $maxRetries) {
				try {
					$amountResults = Search-UnifiedAuditLog -StartDate $currentStart -EndDate $currentEnd @baseSearchQuery -ResultSize 1 | Select-Object -First 1 -ExpandProperty ResultCount
					if ($null -eq $amountResults) {
						$retryAttempt = 0
						$maxNullRetries = 3
						$success = $false
	
						while (!$success -and $retryAttempt -lt $maxNullRetries) {
							Start-Sleep -Seconds (5 * ($retryAttempt + 1)) 
							
							try {
								# Try with a different session ID
								$tempSessionId = [Guid]::NewGuid().ToString()
								$verifyResult = Search-UnifiedAuditLog -StartDate $currentStart -EndDate $currentEnd `
									@baseSearchQuery -ResultSize 1 -SessionId $tempSessionId
									
								if ($null -ne $verifyResult) {
									$amountResults = $verifyResult | Select-Object -First 1 -ExpandProperty ResultCount
									$success = $true
									break
								}
							}
							catch {
								Write-LogFile -Message "[WARNING] Retry attempt $($retryAttempt + 1) failed for period verification" -Level Standard
							}
							$retryAttempt++
						}
	
	
						if ($null -eq $amountResults) {
							if ($currentStart -ne $currentEnd) {
								Write-LogFile -Message "[INFO] No audit logs between $($currentStart.ToString('yyyy-MM-dd HH:mm:ss')) and $($currentEnd.ToString('yyyy-MM-dd HH:mm:ss')). Moving on!" -Level Standard
							}
							$CurrentStart = $CurrentEnd
							$success = $true
						}
					} 
					elseif ($amountResults -gt 50000) {
						while ($amountResults -gt 50000) {		
							$amountResults = Search-UnifiedAuditLog -StartDate $currentStart -EndDate $currentEnd @baseSearchQuery -ResultSize 1 | 
							Select-Object -First 1 -ExpandProperty ResultCount
	
							$oldInterval = $Interval 
	
							if ($amountResults -gt 50000) {
								$stats.IntervalAdjustments++
	
								if ($amountResults -gt 1000000) {
									$divisor = ($amountResults/50000) * 4
								} elseif ($amountResults -gt 500000) {
									$divisor = ($amountResults/50000) * 3
								} elseif ($amountResults -gt 200000) {
									$divisor = ($amountResults/50000) * 2
								} elseif ($amountResults -gt 100000) {
									$divisor = ($amountResults/50000) * 1.5
								} else {
									$divisor = ($amountResults/50000) * 1.25
								}
	
								$newInterval = [math]::Max([math]::Round(($Interval/$divisor), 2), 0.1)
	
								$calculatedInterval = $Interval/$divisor
								$newInterval = if ($calculatedInterval -lt 1) {
									[math]::Max([math]::Round($calculatedInterval, 3), 0.1)
								} else {
									[math]::Max([math]::Round($calculatedInterval, 0), 1)
								}
							
								# Safety check to prevent getting stuck
								if ($newInterval -ge $oldInterval) {
									$newInterval = [math]::Max($Interval * 0.5, 1)
								}
	
								$Interval = $newInterval
								Write-LogFile -Message "[WARNING] $amountResults entries between $($currentStart.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK")) and $($currentEnd.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK")) exceeding the maximum of 50000 entries" -Color "Red" -Level Standard
								Write-LogFile -Message "[INFO] Temporary lowering time interval from $oldInterval to $newInterval minutes" -Color "Yellow" -Level Standard
								$currentEnd = $currentStart.AddMinutes($Interval)
							}
							elseif ($amountResults -eq 0) {
								# Double check with a smaller result size
								$verifyResults = Search-UnifiedAuditLog -StartDate $currentStart -EndDate $currentEnd @baseSearchQuery -ResultSize 1
								if ($null -ne $verifyResults) {
									# If we find results, adjust interval and retry
									$Interval = [math]::Max($Interval * 0.5, 1)
									$currentEnd = $currentStart.AddMinutes($Interval)
									continue
								}
								# Break the loop if no results are found
								Write-LogFile -Message "[INFO] No results found in this time period, moving to next interval" -Level Standard
								$currentEnd = $currentStart.AddMinutes($Interval)
							}
							
							if ($Interval -eq 0) {
								Exit
							}
						}
					}
					
					elseif ($amountResults -gt 0) { 
						$Interval = $resetInterval
						if ($currentEnd -gt $script:EndDate) {
							$currentEnd = $script:EndDate
						}
						
						if ($null -eq $amountResults) {
							break
						}
											
						Write-LogFile -Message "[INFO] Found $amountResults audit logs between $($currentStart.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK")) and $($currentEnd.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK"))" -Level Standard -Color "Green"
	
						$retryAttempt = 0
						$currentDelay = $baseDelay
						$success = $false
	
						while (!$success -and $retryAttempt -lt $maxRetries) {
							try {
								do {
									$sessionID = $currentStart.ToString("yyyyMMddHHmmss")					
									$batchSuccess = $false
									$batchAttempts = 0
									$maxBatchRetries = 3
									[Array]$allResults = @()
									$totalProcessed = 0
									$backoffDelay = 10
	
									while (!$batchSuccess -and $batchAttempts -lt $maxBatchRetries) {
										try {
											$allResults = @()
											$totalProcessed = 0
	
											while ($totalProcessed -lt $amountResults) {
												[Array]$results = Search-UnifiedAuditLog -StartDate $CurrentStart -EndDate $currentEnd -SessionCommand ReturnLargeSet -SessionId $sessionId -ResultSize $resultSize @baseSearchQuery
												
												if ($null -ne $results -and $results.Count -gt 0) {
													$allResults += $results
													$totalProcessed += $results.Count
													Write-LogFile -Message "[INFO] Retrieved $($results.Count) records (Total: $totalProcessed / $amountResults)" -Level Standard
													$backoffDelay = 10
												}
												else {
													Write-LogFile -Message "[WARNING] Microsoft returned corrupt data for the period $($currentStart.ToString('yyyy-MM-dd HH:mm:ss')) to $($currentEnd.ToString('yyyy-MM-dd HH:mm:ss'))... Retrying the entire batch... " -Color "Yellow" -Level Minimal
													$batchAttempts++
													$allResults = @()
													$totalProcessed = 0
													$sessionId = [Guid]::NewGuid().ToString()
													Start-Sleep -Seconds $backoffDelay
													$backoffDelay = [Math]::Min(30, $backoffDelay * 2)
													break
												}
											}
	
											if ($totalProcessed -eq $amountResults) {
												$batchSuccess = $true
											}
										}
										catch {
											if ($_.Exception.Message -like "*server side error*" -or 
												$_.Exception.Message -like "*operation could not be completed*" -or 
												$_.Exception.Message -like "*timed out*") {	
													Write-LogFile -Message "[WARNING] Server error encountered. Restarting entire batch." -Color "Yellow" -Level Standard
												$allResults = @()
												$totalProcessed = 0
												$sessionId = [Guid]::NewGuid().ToString()										
												Start-Sleep -Seconds $backoffDelay
												$backoffDelay = [Math]::Min(30, $backoffDelay * 2)
												continue
											} else {
												Write-LogFile -Message "[ERROR] Unexpected error: $($_.Exception.Message)" -Color "Red" -Level Standard
											}
										}
									}
								} while ($totalProcessed -lt $amountResults -and $batchSuccess -eq $false)
	
								if ($totalProcessed -ne $amountResults) {
									Write-LogFile -Message "[WARNING] Retrieved record count ($totalProcessed) differs from expected ($amountResults). Retrying entire batch." -Level Standard -Color "Yellow"
									$allResults = @()
									$totalProcessed = 0
									$sessionId = [Guid]::NewGuid().ToString()
									continue
								}
								else {
									$success = $true
	
									if ($totalProcessed -gt 0) {
										$sessionID = $currentStart.ToString("yyyyMMddHHmmss") + "-" + $currentEnd.ToString("yyyyMMddHHmmss")
										$outputPath = Join-Path $OutputDir ("UAL-" + $sessionID)
										$stats.TotalRecords += $totalProcessed
										
										if ($Output -eq "JSON" -or $Output -eq "SOF-ELK") {
											$stats.FilesCreated++
											$allResults = $allResults | ForEach-Object {
												$_.AuditData = $_.AuditData | ConvertFrom-Json
												$_
											}
											if ($Output -eq "JSON") {
												$json = $allResults | ConvertTo-Json -Depth 100
												$json | Out-File -Append "$OutputDir/UAL-$sessionID.json" -Encoding $Encoding
											} 
											elseif ($Output -eq "SOF-ELK") {
												# Encoding is hard-coded to UTF8 as UTF16 causes problems when importing the data into SOF-ELK
												foreach ($item in $allResults) {
													$item.AuditData | ConvertTo-Json -Compress -Depth 100 | 
														Out-File -Append "$OutputDir/UAL-$sessionID.json" -Encoding UTF8
												}
											}
											Add-Content "$OutputDir/UAL-$sessionID.json" "`n"
										}
										elseif ($Output -eq "CSV") {
											$stats.FilesCreated++
											$allResults | export-CSV "$outputPath.csv" -NoTypeInformation -Append -Encoding $Encoding
										}
										Write-LogFile -Message "[INFO] Successfully retrieved $totalProcessed records for the current time range. Moving on!" -Level Minimal -Color "Green"
									}
								}
							}
							catch {
								if ($_.Exception.Message -like "*server side error*" -or 
									$_.Exception.Message -like "*operation could not be completed*") {
									
									$retryAttempt++
									if ($retryAttempt -eq $maxRetries) {
										Write-LogFile -Message "[ERROR] Maximum retry attempts reached for interval check. Last error: $($_.Exception.Message)" -Color "Red" -Level Minimal
										throw
									}
									
									Write-LogFile -Message "[WARNING] Server-side error on attempt $retryAttempt of $maxRetries. Waiting $currentDelay seconds..." -Color "Yellow" -Level Minimal
									Start-Sleep -Seconds $currentDelay
									$currentDelay *= 2
									continue
								}
								else {
									throw
								}
							}			
						}
						$CurrentStart = $CurrentEnd
					}
				}
				catch {
					if ($_.Exception.Message -like "*server side error*" -or 
						$_.Exception.Message -like "*operation could not be completed*") {
						
						$retryAttempt++
						if ($retryAttempt -eq $maxRetries) {
							Write-LogFile -Message "[ERROR] Maximum retry attempts reached for interval check. Last error: $($_.Exception.Message)" -Color "Red" -Level Minimal
							throw
						}
						
						Write-LogFile -Message "[WARNING] Server-side error on attempt $retryAttempt of $maxRetries. Waiting $currentDelay seconds..." -Color "Yellow" -Level Minimal
						Start-Sleep -Seconds $currentDelay
						$currentDelay *= 2
						continue
					}
					else {
						throw
					}
				}
			}
		}
	
		if ($Output -eq "CSV" -and ($MergeOutput.IsPresent)) {
			Write-LogFile -Message "[INFO] Merging output files into one file" -Level standard
			Merge-OutputFiles -OutputDir $OutputDir -OutputType "CSV" -MergedFileName "UAL-Combined.csv"
		}
		elseif ($Output -eq "JSON" -and ($MergeOutput.IsPresent)) {
			Write-LogFile -Message "[INFO] Merging output files into one file" -Level standard
			Merge-OutputFiles -OutputDir $OutputDir -OutputType "JSON" -MergedFileName "UAL-Combined.json"
		}
		elseif ($Output -eq "SOF-ELK" -and ($MergeOutput.IsPresent)) {
			Write-LogFile -Message "[INFO] Merging output files into one file" -Level standard
			Merge-OutputFiles -OutputDir $OutputDir -OutputType "SOF-ELK" -MergedFileName "UAL-Combined.json"
		}
	}
	$stats.ProcessingTime = (Get-Date) - $stats.StartTime
	Write-LogFile -Message "`n=== Collection Summary ===" -Color "Cyan" -Level Standard
	Write-LogFile -Message "Start date: $($script:StartDate.ToString('yyyy-MM-dd HH:mm:ss'))" -Level Standard
	Write-LogFile -Message "End date: $($script:EndDate.ToString('yyyy-MM-dd HH:mm:ss'))" -Level Standard
	Write-LogFile -Message "Total Records: $($stats.TotalRecords)" -Level Standard
	Write-LogFile -Message "Files Created: $($stats.FilesCreated)" -Level Standard
	Write-LogFile -Message "Interval Adjustments: $($stats.IntervalAdjustments)" -Level Standard
	Write-LogFile -Message "Output Directory: $OutputDir" -Level Standard
	Write-LogFile -Message "Processing Time: $($stats.ProcessingTime.ToString('hh\:mm\:ss'))" -Level Standard -Color "Green"
	Write-LogFile -Message "===================================" -Color "Cyan" -Level Standard
}
