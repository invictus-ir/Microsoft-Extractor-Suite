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
	Options are: New-MailboxRule, MailItemsAccessed, etc.

	.PARAMETER LogLevel
	Specifies the level of logging:
	None: No logging
	Minimal: Critical errors only
	Standard: Normal operational logging
	Default: Standard
	Debug: Verbose logging for debugging purposes

	.PARAMETER MaxItemsPerInterval
    Specifies the maximum number of items to process in a single interval. Must be between 5000 and 50000.
    Lower this value if you're experiencing timeouts with large data sets.
    Default: 50000
	
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

	.EXAMPLE
    Get-UAL -MaxItemsPerInterval 20000
    Gets all the unified audit log entries with a maximum of 20000 items per interval, useful when experiencing timeouts.
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
			[ValidateSet('None', 'Minimal', 'Standard', 'Debug')]
			[string]$LogLevel = 'Standard',
			[Parameter()] 
			[ValidateRange(5000, 50000)]
			[int]$MaxItemsPerInterval = 50000
		)

	Set-LogLevel -Level ([LogLevel]::$LogLevel)
	$isDebugEnabled = $script:LogLevel -eq [LogLevel]::Debug

	$stats = @{
		StartTime = Get-Date
		ProcessingTime = $null
		TotalRecords = 0
		FilesCreated = 0
		IntervalAdjustments = 0
	}

	Write-LogFile -Message "=== Starting Unified Audit Log Collection ===" -Color "Cyan" -Level Standard

    if ($isDebugEnabled) {
        Write-LogFile -Message "[DEBUG] PowerShell Version: $($PSVersionTable.PSVersion)" -Level Debug
        
        $exchangeModule = Get-Module -Name ExchangeOnlineManagement -ErrorAction SilentlyContinue
        if ($exchangeModule) {
            Write-LogFile -Message "[DEBUG] ExchangeOnlineManagement Module Version: $($exchangeModule.Version)" -Level Debug
        } else {
            Write-LogFile -Message "[DEBUG] ExchangeOnlineManagement Module not loaded" -Level Debug
        }

		$orgUnit = Get-OrganizationalUnit | Where-Object { $_.Name -like "*onmicrosoft.com" } | Select-Object -First 1        
		if ($orgUnit) {
			Write-LogFile -Message "[DEBUG] Tenant Name: $($orgUnit.Name)" -Level Debug
			Write-LogFile -Message "[DEBUG] Canonical Name: $($orgUnit.CanonicalName)" -Level Debug
			Write-LogFile -Message "[DEBUG] Distinguished Name: $($orgUnit.DistinguishedName)" -Level Debug
			Write-LogFile -Message "[DEBUG] Organization ID: $($orgUnit.OrganizationId)" -Level Debug
			Write-LogFile -Message "[DEBUG] Exchange Object ID: $($orgUnit.ExchangeObjectId)" -Level Debug
		}

		$connectionInfo = Get-ConnectionInformation -ErrorAction Stop
        Write-LogFile -Message "[DEBUG] Connection Status: $($connectionInfo.State)" -Level Debug
        Write-LogFile -Message "[DEBUG] Connection Type: $($connectionInfo.TokenStatus)" -Level Debug
        Write-LogFile -Message "[DEBUG] Connected Account: $($connectionInfo.UserPrincipalName)" -Level Debug	
        
        Write-LogFile -Message "[DEBUG] Script parameters:" -Level Debug
        Write-LogFile -Message "[DEBUG]   StartDate: $StartDate" -Level Debug
        Write-LogFile -Message "[DEBUG]   EndDate: $EndDate" -Level Debug
        Write-LogFile -Message "[DEBUG]   UserIds: $UserIds" -Level Debug
        Write-LogFile -Message "[DEBUG]   Group: $Group" -Level Debug
        Write-LogFile -Message "[DEBUG]   Output: $Output" -Level Debug
        Write-LogFile -Message "[DEBUG]   MaxItemsPerInterval: $MaxItemsPerInterval" -Level Debug
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
			New-Item -ItemType Directory -Force -Path $OutputDir > $null
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
	if ($Operation) {
		Write-LogFile -Message "`nThe following Operation(s) are configured to be extracted:" -Level Standard
		foreach ($activity in $Operation) {
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

	$maxRetries = 3
    $baseDelay = 3
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

				if ($null -ne $totalResults -and $totalResults -gt 0) {
					$message = if ($record -eq "*") {
						"[INFO] Total number of events during the acquisition period: $totalResults"
					} else {
						"[INFO] The record '$record' contains $totalResults events during the acquisition period"
					}
					
					Write-LogFile -Message $message -Level Standard -color "Green"
					$success = $true
				}
				else {
					# If we got null or zero, check if it's due to timeout
					$retryAttempt++
            
					# On last attempt, check the recent period
					if ($retryAttempt -eq $maxRetries) {
						Write-LogFile -Message "[INFO] Full period search returned zero results. This may occur in large environments due to API timeouts." -Level Standard -Color "Yellow"

						$last24HoursStart = $script:EndDate.AddHours(-24)
						$recentResults = Search-UnifiedAuditLog -StartDate $last24HoursStart -EndDate $script:EndDate @baseSearchQuery -ResultSize 1 | 
										 Select-Object -First 1 -ExpandProperty ResultCount
						
						if ($null -ne $recentResults -and $recentResults -gt 0) {
							Write-LogFile -Message "[INFO] Found $recentResults recent events in the last 24 hours." -Level Standard -Color "Green"
							Write-LogFile -Message "[INFO] The initial count likely timed out due to the large data volume... Proceeding with retrieval using smaller time chunks..." -Level Standard -Color "Green"
							
							$totalDays = ($script:EndDate - $script:StartDate).TotalDays
    						$estimatedTotalRecords = [math]::Ceiling($recentResults * $totalDays)
							
							$totalResults = 1  # Set to non-zero to force the script to continue
							$success = $true
							break
						} else {
							Write-LogFile -Message "[INFO] No recent events found in the last 24 hours either." -Level Standard -Color "Yellow"
							$success = $true
						}
					} else {
						Write-LogFile -Message "[WARNING] Zero results returned, retrying attempt $retryAttempt of $maxRetries..." -Color "Yellow" -Level Minimal
						Start-Sleep -Seconds (2 * $retryAttempt)
					}
				}
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
            Write-LogFile -Message $message -Level Standard -Color "Yellow"
            continue
        }

		if (!$PSBoundParameters.ContainsKey('Interval')) {
			$totalMinutes = ($script:EndDate - $script:StartDate).TotalMinutes
		
			if ($null -ne $totalResults -And $totalResults -gt 1) {
				$estimatedIntervals = [math]::Ceiling($totalResults / $MaxItemsPerInterval)
				
				if ($estimatedIntervals -lt 2) {
					$Interval = $totalMinutes
				} else {
					$Interval = [math]::Max(1, [math]::Floor(($totalMinutes / $estimatedIntervals) / 1.2))					
				}
				
				Write-LogFile -Message "[INFO] Using interval of $Interval minutes based on estimated $totalResults records" -Level Standard -Color "Green"
			} 
			else { 
				$Interval = 60
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
					elseif ($amountResults -gt $MaxItemsPerInterval) {
						while ($amountResults -gt $MaxItemsPerInterval) {		
							$amountResults = Search-UnifiedAuditLog -StartDate $currentStart -EndDate $currentEnd @baseSearchQuery -ResultSize 1 | 
							Select-Object -First 1 -ExpandProperty ResultCount
	
							$oldInterval = $Interval 
	
							if ($amountResults -gt $MaxItemsPerInterval) {
								$stats.IntervalAdjustments++
	
								if ($amountResults -gt 1000000) {
									$divisor = ($amountResults/$MaxItemsPerInterval) * 4
								} elseif ($amountResults -gt $MaxItemsPerInterval) {
									$divisor = ($amountResults/$MaxItemsPerInterval) * 3
								} elseif ($amountResults -gt 200000) {
									$divisor = ($amountResults/$MaxItemsPerInterval) * 2
								} elseif ($amountResults -gt 100000) {
									$divisor = ($amountResults/$MaxItemsPerInterval) * 1.5
								} else {
									$divisor = ($amountResults/$MaxItemsPerInterval) * 1.25
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
								Write-LogFile -Message "[WARNING] $amountResults entries between $($currentStart.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK")) and $($currentEnd.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK")) exceeding the maximum of $MaxItemsPerInterval entries" -Color "Red" -Level Standard
								Write-LogFile -Message "[INFO] Temporary lowering time interval from $oldInterval to $newInterval minutes" -Color "Yellow" -Level Standard
								$currentEnd = $currentStart.AddMinutes($Interval)

								if ($isDebugEnabled) {
									Write-LogFile -Message "[DEBUG] Interval adjustment details:" -Level Debug
									Write-LogFile -Message "[DEBUG]   Record count: $amountResults" -Level Debug
									Write-LogFile -Message "[DEBUG]   Max items per interval: $MaxItemsPerInterval" -Level Debug
									Write-LogFile -Message "[DEBUG]   Records/Max ratio: $([Math]::Round($amountResults/$MaxItemsPerInterval, 2))" -Level Debug
									Write-LogFile -Message "[DEBUG]   Applied divisor: $divisor" -Level Debug
									Write-LogFile -Message "[DEBUG]   Old interval: $oldInterval minutes" -Level Debug
									Write-LogFile -Message "[DEBUG]   New interval: $newInterval minutes" -Level Debug
									Write-LogFile -Message "[DEBUG]   Time span reduction: $([Math]::Round(100 - (($newInterval/$oldInterval) * 100), 2))%" -Level Debug
								}		
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
									$batchSuccess = $false
									$batchAttempts = 0
									$maxBatchRetries = 3
									$backoffDelay = 10

									while (!$batchSuccess -and $batchAttempts -lt $maxBatchRetries) {
										try {
											[Array]$allResults = @()
											$totalProcessed = 0
											$sessionId = [Guid]::NewGuid().ToString()

											if ($isDebugEnabled) {
                                                Write-LogFile -Message "[DEBUG]   Starting batch retrieval with session ID: $sessionId" -Level Debug
                                                Write-LogFile -Message "[DEBUG]   Using result size: $resultSize" -Level Debug
                                            }

											while ($totalProcessed -lt $amountResults) {
                                                
                                                if ($isDebugEnabled) {
													Write-LogFile -Message "[DEBUG]   Fetching Unified Audit Log" -Level Debug
                                                    Write-LogFile -Message "[DEBUG]   Fetching results batch ($totalProcessed/$amountResults processed so far)" -Level Debug
                                                }
												$performance = Measure-Command {
													if ($amountResults -gt 5000) {
                                                        [Array]$results = Search-UnifiedAuditLog -StartDate $CurrentStart -EndDate $currentEnd -SessionCommand ReturnLargeSet -SessionId $sessionId -ResultSize $resultSize @baseSearchQuery
                                                    } else {
                                                        [Array]$results = Search-UnifiedAuditLog -StartDate $CurrentStart -EndDate $currentEnd -ResultSize $resultSize @baseSearchQuery
                                                    }
												}

												if ($isDebugEnabled) {
                                                    Write-LogFile -Message "[DEBUG]   Fetch UAL took $([math]::round($performance.TotalSeconds, 2)) seconds" -Level Debug
                                                }

												if ($null -ne $results -and $results.Count -gt 0) {
													$expectedSize = [math]::min($resultSize, ($amountResults - $totalProcessed))
													$allResults += $results
													$totalProcessed += $results.Count
													Write-LogFile -Message "[INFO] Retrieved $($results.Count) records (Total: $totalProcessed / $amountResults)" -Level Standard
													$backoffDelay = 10

													# Check returned dataset size, to do an early restart if this is incorrect
													if($results.Count -ne $expectedSize) {
														if ($isDebugEnabled) {
                                                            Write-LogFile -Message "[DEBUG]   WARNING: Batch size mismatch - expected $expectedSize but got $($results.Count)" -Level Debug
                                                        }
														break
													}
												} else {
													if ($isDebugEnabled) {
                                                        Write-LogFile -Message "[DEBUG]   WARNING: Empty dataset returned" -Level Debug
                                                    }
												}
											}

											if ($totalProcessed -ne $amountResults) {
												Write-LogFile -Message "[WARNING] Retrieved record count ($totalProcessed) does not match the expected count ($amountResults). Verifying the count..." -Color "Yellow" -Level Standard

												$verifiedCount = Search-UnifiedAuditLog -StartDate $currentStart -EndDate $currentEnd @baseSearchQuery `
													-ResultSize 1 | Select-Object -First 1 -ExpandProperty ResultCount
						
												if ($null -eq $verifiedCount) {
													$verifiedCount = 0
												}
						
												if ($verifiedCount -ne $amountResults) {
													Write-LogFile -Message "[INFO] Adjusted expected count from $amountResults to $verifiedCount after revalidating the API response." -Color "Green" -Level Standard
													$amountResults = $verifiedCount
												}
						
												# Check if the verified count matches what we collected
												if ($totalProcessed -eq $amountResults) {
													$batchSuccess = $true
												}
												else {
													Write-LogFile -Message "[WARNING] Retrieved record count ($totalProcessed) still does not match the verified count ($amountResults). Retrying batch..." -Color "Yellow" -Level Standard

													$batchAttempts++
													Start-Sleep -Seconds $backoffDelay
													$backoffDelay = [Math]::Min(30, $backoffDelay * 2)
													continue
												}
											}
											else {
												$batchSuccess = $true
											}
										}
										catch {
											if ($_.Exception.Message -like "*server side error*" -or 
												$_.Exception.Message -like "*operation could not be completed*" -or 
												$_.Exception.Message -like "*timed out*") {	
													Write-LogFile -Message "[WARNING] Server error encountered. Restarting entire batch." -Color "Yellow" -Level Standard
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
										Write-LogFile -Message "[INFO] Successfully retrieved $totalProcessed records for the current time range. Moving on!" -Level Standard -Color "Green"
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
									Write-LogFile -Message "[ERROR] Unknown error type has occured" -Color "Red" -Level Minimal
									Write-Host $_.Exception.Message
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
						Write-LogFile -Message "[ERROR] Unknown error type has occured" -Color "Red" -Level Minimal
						throw
					}
				}
			}
		}
	}

	if ($MergeOutput.IsPresent) {
        Write-LogFile -Message "[INFO] Merging all output files into one file" -Level Standard
        
        switch ($Output) {
            "CSV" { Merge-OutputFiles -OutputDir $OutputDir -OutputType "CSV" -MergedFileName "UAL-Combined.csv" }
            "JSON" { Merge-OutputFiles -OutputDir $OutputDir -OutputType "JSON" -MergedFileName "UAL-Combined.json" }
            "SOF-ELK" { Merge-OutputFiles -OutputDir $OutputDir -OutputType "SOF-ELK" -MergedFileName "UAL-Combined.json" }
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
