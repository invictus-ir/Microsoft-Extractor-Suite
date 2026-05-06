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
    Output is the parameter specifying the CSV, JSON, JSONL or SOF-ELK output type. The SOF-ELK output can be imported into the platform of the same name.
	Default: CSV

	.PARAMETER OutputDir
	OutputDir is the parameter specifying the output directory.
	Default: Output\UnifiedAuditLog

 	.PARAMETER MergeOutput
    MergeOutput is the parameter specifying if you wish to merge CSV/JSON/JSONL/SOF-ELK outputs to a single file.

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

 	.PARAMETER Operations
    The Operations parameter filters the log entries by operations or activity type.
	Options are: New-MailboxRule, MailItemsAccessed, etc.

	.PARAMETER IPAddresses
	The IPAddresses parameter filters the log entries by the IP address of the client that performed the action.
	You can enter multiple values separated by commas.

	.PARAMETER LogLevel
	Specifies the level of logging:
	None: No logging
	Minimal: Critical errors only
	Standard: Normal operational logging
	Default: Standard
	Debug: Verbose logging for debugging purposes

	.PARAMETER AuditDataOnly
	AuditDataOnly is a switch parameter that extracts only the AuditData property from each log entry.
	When enabled, the output will contain only the parsed AuditData JSON content without the wrapper properties
	like CreationDate, UserIds, Operations, etc (those are also found in the AuditData).

	.PARAMETER TargetEventsPerWindow
	The ideal number of events we aim to retrieve per window. The Microsoft API caps a single
	non-session call at 5000 events; this target is what we steer toward when adapting the interval. Lower
	values are safer (more headroom below the cap, fewer cap-hit retries) but produce more API calls.
	Higher values produce fewer calls but increase the chance of hitting the 5000 cap and having to shrink
	and refetch. The shrink threshold is derived as TargetEventsPerWindow * 1.5 (capped by the API at 5000).
	Default: 3000

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
	Get-UAL -UserIds Test@invictus-ir.com -StartDate 2026-04-01 -EndDate 2026-04-05
	Gets all the unified audit log entries between 2026-04-01 and 2026-04-05 for the user Test@invictus-ir.com.

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
	Get-UAL -Operations New-InboxRule
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
			[array]$Operations = $null,
			[ValidateSet("CSV", "JSON", "SOF-ELK", "JSONL")]
			[string]$Output = "CSV",
			[switch]$MergeOutput,
			[string]$OutputDir,
			[string]$IPAddresses,
			[string]$Encoding = "UTF8",
			[string]$ObjectIds,
			[ValidateSet('None', 'Minimal', 'Standard', 'Debug')]
			[string]$LogLevel = 'Standard',
			[switch]$AuditDataOnly,
			[Parameter()]
			[ValidateRange(1, 5000)]
			[int]$TargetEventsPerWindow = 3000
		)

	Init-Logging
    Init-OutputDir -Component "UnifiedAuditLog" -FilePostfix "UAL" -CustomOutputDir $OutputDir
	$OutputDir = Split-Path $script:outputFile -Parent
	Write-LogFile -Message "=== Starting Unified Audit Log Collection ===" -Color "Cyan" -Level Standard

	$stats = @{
		StartTime = Get-Date
		ProcessingTime = $null
		TotalRecords = 0
		FilesCreated = 0
		IntervalAdjustments = 0
	}

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

	if ($isDebugEnabled) {
        $totalDays = ($script:EndDate - $script:StartDate).TotalDays
        Write-LogFile -Message "[DEBUG] Date range:" -Level Debug
        Write-LogFile -Message "[DEBUG]   Start: $($script:StartDate.ToString('yyyy-MM-dd HH:mm:ss'))" -Level Debug
        Write-LogFile -Message "[DEBUG]   End: $($script:EndDate.ToString('yyyy-MM-dd HH:mm:ss'))" -Level Debug
        Write-LogFile -Message "[DEBUG]   Span: $([Math]::Round($totalDays, 2)) days" -Level Debug
    }

	$baseSearchQuery = @{}
	if ($UserIds -and $UserIds -ne "*") {
		$baseSearchQuery.UserIds = $UserIds
	}
	if ($IPAddresses) {
        $baseSearchQuery.IPAddresses = $IPAddresses
    }

	if ($ObjectIds) {
        $baseSearchQuery.ObjectIds = $ObjectIds
    }

	if ($Operations) {
		$baseSearchQuery.Operations = $Operations
	}

	$recordTypes = [System.Collections.ArrayList]::new()

	$GroupRecordTypes = @{
        "Exchange" = @("ExchangeAdmin","ExchangeAggregatedOperation","ExchangeItem","ExchangeItemGroup",
                      "ExchangeItemAggregated","ComplianceDLPExchange","ComplianceSupervisionExchange",
                      "MipAutoLabelExchangeItem","ExchangeSearch","ComplianceDLPExchangeClassification","ComplianceCCExchangeExecutionResult",
					  "CdpComplianceDLPExchangeClassification","ComplianceDLMExchange","ComplianceDLPExchangeDiscovery")
        "Azure" = @("AzureActiveDirectory","AzureActiveDirectoryAccountLogon","AzureActiveDirectoryStsLogon")
        "Sharepoint" = @("ComplianceDLPSharePoint","SharePoint","SharePointFileOperation","SharePointSharingOperation",
                        "SharepointListOperation","ComplianceDLPSharePointClassification","SharePointCommentOperation",
                        "SharePointListItemOperation","SharePointContentTypeOperation","SharePointFieldOperation",
                        "MipAutoLabelSharePointItem","MipAutoLabelSharePointPolicyLocation","OnPremisesSharePointScannerDlp","SharePointSearch",
						"SharePointAppPermissionOperation","ComplianceDLPSharePointClassificationExtended","CdpComplianceDLPSharePointClassification",
						"SharePointESignature","ComplianceDLMSharePoint","SharePointContentSecurityPolicy")
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

		if ($isDebugEnabled) {
            Write-LogFile -Message "[DEBUG] Added record types from group '$Group'" -Level Debug
            Write-LogFile -Message "[DEBUG]   Total record types from group: $($recordTypes.Count)" -Level Debug
        }
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

		if ($isDebugEnabled) {
            Write-LogFile -Message "[DEBUG] Added explicit record types: $RecordType" -Level Debug
            Write-LogFile -Message "[DEBUG]   Total record types after addition: $($recordTypes.Count)" -Level Debug
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
	if ($Operations) {
		Write-LogFile -Message "`nThe following Operation(s) are configured to be extracted:" -Level Standard
		foreach ($activity in $Operations) {
			Write-LogFile -Message "- $activity" -Level Standard
		}
	}
    Write-LogFile -Message "----------------------------------------`n" -Level Standard

	if ($recordTypes.Count -eq 0) {
        [void]$recordTypes.Add("*")
		if ($isDebugEnabled) {
            Write-LogFile -Message "[DEBUG] No record types specified, using wildcard (*)" -Level Debug
        }
    }

	$TARGET_EVENTS    = $TargetEventsPerWindow
	$SHRINK_THRESHOLD = [math]::Min($resultSize - 100, [int]($TARGET_EVENTS * 1.5))
	$GROW_THRESHOLD   = [math]::Max(1, [int]($TARGET_EVENTS / 3))
	$MIN_INTERVAL     = 0.1
	$MAX_INTERVAL     = [math]::Max(60, ($script:EndDate - $script:StartDate).TotalMinutes)
	$maxRetries = 3
	$baseDelay  = 10

	foreach ($record in $recordTypes) {
		if ($record -ne "*") {
			Write-LogFile -Message "=== Processing RecordType: $record ===" -Color "Cyan" -Level Standard
			$baseSearchQuery.RecordType = $record
		} else {
			$baseSearchQuery.Remove('RecordType')
		}

		if (-not $PSBoundParameters.ContainsKey('Interval')) {
			$probeMinutes = 60
			$probeStart   = $script:EndDate.AddMinutes(-$probeMinutes)
			if ($probeStart -lt $script:StartDate) { $probeStart = $script:StartDate }

			$probeAttempt    = 0
			$probeMaxRetries = 3
			$probeDelay      = 5
			$probeCount      = $null
			$probeFailed     = $false

			while ($probeAttempt -lt $probeMaxRetries -and $null -eq $probeCount) {
				try {
					$probeResults = Search-UnifiedAuditLog -StartDate $probeStart -EndDate $script:EndDate @baseSearchQuery -ResultSize $resultSize -ErrorAction Stop
					$probeCount   = if ($probeResults) { $probeResults.Count } else { 0 }
				}
				catch {
					$probeAttempt++
					if ($probeAttempt -ge $probeMaxRetries) {
						Write-LogFile -Message "[WARNING] Probe failed after $probeMaxRetries attempts. Using fallback interval. Last error: $($_.Exception.Message)" -Color "Yellow" -Level Standard
						$probeFailed = $true
					}
					else {
						Start-Sleep -Seconds $probeDelay
						$probeDelay *= 2
					}
				}
			}

			if ($probeFailed) {
				$Interval = 60
			}
			elseif ($probeCount -eq 0) {
				$Interval = [math]::Min($MAX_INTERVAL, 1440)
    			Write-LogFile -Message "[INFO] 0 recent events. Starting at $Interval min (will grow if windows remain empty)." -Level Standard
			}
			elseif ($probeCount -ge $resultSize) {
				$Interval = [math]::Max($MIN_INTERVAL, $probeMinutes / 2)
				Write-LogFile -Message "[WARNING] Probe returned $resultSize events (API cap hit) in the last $probeMinutes min. Starting with a reduced interval of $Interval min to avoid missing events." -Color "Yellow" -Level Standard
			}
			else {
				$eventsPerMin = $probeCount / $probeMinutes
				$Interval     = [math]::Min($MAX_INTERVAL, [math]::Max($MIN_INTERVAL, $TARGET_EVENTS / $eventsPerMin))
				Write-LogFile -Message "[INFO] $probeCount events in last $probeMinutes min. Initial interval: $([math]::Round($Interval, 2)) min" -Color "Green" -Level Standard
			}
		}
		else {
			Write-LogFile -Message "[INFO] Using user-specified interval: $Interval minutes" -Level Standard
		}

		[DateTime]$currentStart = $script:StartDate
		$finalEndDate = $script:EndDate.ToUniversalTime()

		while ($currentStart -lt $finalEndDate) {
			$currentEnd = $currentStart.AddMinutes($Interval)
			if ($currentEnd -gt $finalEndDate) { $currentEnd = $finalEndDate }
			if ($currentEnd -le $currentStart) {
				Write-LogFile -Message "[INFO] Reached end of date range" -Level Standard
				break
			}

			$retryAttempt = 0
			$currentDelay = $baseDelay
			$success      = $false
			$results      = $null

			while (!$success -and $retryAttempt -lt $maxRetries) {
				try {
					$callWarnings = [System.Collections.ArrayList]::new()
					$performance = Measure-Command {
						[Array]$script:queryResults = Search-UnifiedAuditLog -StartDate $currentStart -EndDate $currentEnd @baseSearchQuery -ResultSize $resultSize -WarningVariable +callWarnings
					}
					 $cancelWarning = $callWarnings | Where-Object { "$_" -like "*task was canceled*" -or "$_" -like "*Failed to process request*" }
					if ($cancelWarning) {
						throw [System.Exception]::new("task was canceled (warning from Search-UnifiedAuditLog: $($cancelWarning[0]))")
					}
					$results = $script:queryResults
					$success = $true

					if ($isDebugEnabled) {
						Write-LogFile -Message "[DEBUG] Fetch took $([math]::round($performance.TotalSeconds, 2)) seconds" -Level Debug
					}
				}
				catch {
					if ($_.Exception.Message -like "*server side error*" -or
						$_.Exception.Message -like "*operation could not be completed*" -or
						$_.Exception.Message -like "*timed out*" -or
						$_.Exception.Message -like "*task was canceled*") {

						$retryAttempt++
						if ($retryAttempt -ge $maxRetries) {
							Write-LogFile -Message "[ERROR] Max retries reached for window $($currentStart.ToString('yyyy-MM-dd HH:mm:ss')) -> $($currentEnd.ToString('yyyy-MM-dd HH:mm:ss')). Skipping. Last error: $($_.Exception.Message)" -Color "Red" -Level Minimal
							$results = @()
							$success = $true
							break
						}

						Write-LogFile -Message "[WARNING] Server-side error on attempt $retryAttempt of $maxRetries. Waiting $currentDelay seconds..." -Color "Yellow" -Level Minimal
						Start-Sleep -Seconds $currentDelay
						$currentDelay *= 2
						continue
					}
					else {
						Write-LogFile -Message "[ERROR] Unknown error: $($_.Exception.Message)" -Color "Red" -Level Minimal
						throw
					}
				}
			}

			$count = if ($results) { $results.Count } else { 0 }

			if ($count -ge $resultSize) {
				$stats.IntervalAdjustments++

				if ($Interval -le $MIN_INTERVAL) {
       				Write-LogFile -Message "[ERROR] Window $($currentStart.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssK')) -> $($currentEnd.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssK')) has 5000+ events in the minimum interval ($MIN_INTERVAL min). Cannot shrink further; writing partial data and advancing. SOME EVENTS IN THIS RANGE ARE NOT CAPTURED." -Color "Red" -Level Minimal
				}
				else {
					$oldInterval = $Interval
					$Interval    = [math]::Max($MIN_INTERVAL, $Interval * 0.5)
					Write-LogFile -Message "[WARNING] Window $($currentStart.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssK')) -> $($currentEnd.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssK')) returned $count events (API cap). Shrinking interval $oldInterval -> $Interval min and refetching." -Color "Red" -Level Standard
					
					if ($isDebugEnabled) {
						Write-LogFile -Message "[DEBUG] Cap hit details:" -Level Debug
						Write-LogFile -Message "[DEBUG]   Count: $count (cap: $resultSize)" -Level Debug
						Write-LogFile -Message "[DEBUG]   Old interval: $oldInterval min" -Level Debug
						Write-LogFile -Message "[DEBUG]   New interval: $Interval min" -Level Debug
					}
					continue
				}
			}

			if ($count -gt 0) {
				Write-LogFile -Message "[INFO] Found $count audit logs between $($currentStart.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssK')) and $($currentEnd.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssK'))" -Level Standard -Color "Green"

				$sessionID  = $currentStart.ToString("yyyyMMddHHmmss") + "-" + $currentEnd.ToString("yyyyMMddHHmmss")
				$outputPath = Join-Path $OutputDir ("UAL-" + $sessionID)
				$stats.TotalRecords += $count
				$stats.FilesCreated++

				# Extract only AuditData if flag is set
				if ($AuditDataOnly) {
					$outputData = $results | Select-Object -ExpandProperty AuditData
				} else {
					$outputData = $results
				}

				if ($Output -eq "JSON" -or $Output -eq "SOF-ELK") {
					if (!$AuditDataOnly) {
						$outputData = $outputData | ForEach-Object {
							$_.AuditData = $_.AuditData | ConvertFrom-Json
							$_
						}
					}

					if ($Output -eq "JSON") {
						if ($AuditDataOnly) {
							$outputData | Out-File -Append "$OutputDir/UAL-$sessionID.json" -Encoding $Encoding
						} else {
							$json = $outputData | ConvertTo-Json -Depth 100
							$json | Out-File -Append "$OutputDir/UAL-$sessionID.json" -Encoding $Encoding
						}
					}
					elseif ($Output -eq "SOF-ELK") {
						if ($AuditDataOnly) {
							$outputData | Out-File -Append "$OutputDir/UAL-$sessionID.json" -Encoding UTF8
						} else {
							foreach ($item in $outputData) {
								$item.AuditData | ConvertTo-Json -Compress -Depth 100 |
									Out-File -Append "$OutputDir/UAL-$sessionID.json" -Encoding UTF8
							}
						}
					}
					Add-Content "$OutputDir/UAL-$sessionID.json" "`n"
				}
				elseif ($Output -eq "JSONL") {
					if ($AuditDataOnly) {
						$outputData | ForEach-Object {
							$_ | Out-File -Append "$outputPath.jsonl" -Encoding $Encoding
						}
					} else {
						$outputData | ForEach-Object {
							$_ | ConvertTo-Json -Compress -Depth 100 | Out-File -Append "$outputPath.jsonl" -Encoding $Encoding
						}
					}
				}
				elseif ($Output -eq "CSV") {
					if ($AuditDataOnly) {
						$parsedData = $outputData | ForEach-Object {
							$_ | ConvertFrom-Json
						}
						$parsedData | Export-CSV "$outputPath.csv" -NoTypeInformation -Append -Encoding $Encoding
					} else {
						$outputData | Export-CSV "$outputPath.csv" -NoTypeInformation -Append -Encoding $Encoding
					}
				}
			}

			if (-not $PSBoundParameters.ContainsKey('Interval')) {
				if ($count -ge $SHRINK_THRESHOLD) {
					$oldInterval = $Interval
					$Interval    = [math]::Max($MIN_INTERVAL, $Interval * 0.8)
					if ($oldInterval -ne $Interval) {
						$stats.IntervalAdjustments++
						if ($isDebugEnabled) {
							Write-LogFile -Message "[DEBUG] Pre-shrink: $oldInterval -> $Interval min (count=$count near cap)" -Level Debug
						}
					}
				}
				elseif ($count -lt $GROW_THRESHOLD -and $Interval -lt $MAX_INTERVAL) {
					$oldInterval = $Interval
					$growFactor  = if ($count -lt ($GROW_THRESHOLD / 2)) { 3.0 } else { 1.5 }
					$Interval    = [math]::Min($MAX_INTERVAL, $Interval * $growFactor)
					if ($oldInterval -ne $Interval -and $isDebugEnabled) {
						Write-LogFile -Message "[DEBUG] Grow: $oldInterval -> $Interval min (count=$count well under target)" -Level Debug
					}
				}
			}

			$currentStart = $currentEnd
		}
	}

	if ($MergeOutput.IsPresent) {
        Write-LogFile -Message "[INFO] Merging all output files into one file" -Level Standard

        switch ($Output) {
            "CSV" { Merge-OutputFiles -OutputDir $OutputDir -OutputType "CSV" -MergedFileName "UAL-Combined.csv" }
            "JSON" { Merge-OutputFiles -OutputDir $OutputDir -OutputType "JSON" -MergedFileName "UAL-Combined.json" }
			"JSONL" { Merge-OutputFiles -OutputDir $OutputDir -OutputType "JSONL" -MergedFileName "UAL-Combined.jsonl" }
            "SOF-ELK" { Merge-OutputFiles -OutputDir $OutputDir -OutputType "SOF-ELK" -MergedFileName "UAL-Combined.json" }
        }
    }

	$stats.ProcessingTime = (Get-Date) - $stats.StartTime

	$summary = [ordered]@{
		"Date Range" = [ordered]@{
			"Start Date" = $script:StartDate.ToString('yyyy-MM-dd HH:mm:ss')
			"End Date" = $script:EndDate.ToString('yyyy-MM-dd HH:mm:ss')
		}
		"Collection Statistics" = [ordered]@{
			"Total Records" = $stats.TotalRecords
			"Files Created" = $stats.FilesCreated
			"Interval Adjustments" = $stats.IntervalAdjustments
		}
		"Export Details" = [ordered]@{
			"Output Directory" = $OutputDir
			"Processing Time" = $stats.ProcessingTime.ToString('hh\:mm\:ss')
		}
	}

	Write-Summary -Summary $summary -Title "Unified Audit Log Collection Summary" -SkipExportDetails
}
