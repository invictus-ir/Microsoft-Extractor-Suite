function Get-GraphEntraSignInLogs {
    <#
    .SYNOPSIS
    Gets of sign-ins logs.

    .DESCRIPTION
    The Get-GraphEntraSignInLogs GraphAPI cmdlet collects the contents of the Azure Entra ID sign-in logs.

    .PARAMETER startDate
	The startDate parameter specifies the date from which all logs need to be collected.

	.PARAMETER endDate
    The Before parameter specifies the date endDate which all logs need to be collected.

	.PARAMETER MergeOutput
	MergeOutput is the parameter specifying if you wish to merge outputs to a single file
	Default: No

	.PARAMETER Output
    Output is the parameter specifying the JSON or SOF-ELK output type. The SOF-ELK output can be imported into the platform of the same name.
	Default: JSON

	.PARAMETER LogLevel
    Specifies the level of logging:
    None: No logging
    Minimal: Critical errors only
    Standard: Normal operational logging
	Debug: Verbose logging for debugging purposes
    Default: Standard
	

    .PARAMETER OutputDir
    outputDir is the parameter specifying the output directory.
    Default: The output will be written to: Output\EntraID\{date_SignInLogs}\{timestamp}-{eventType}-SignInLogs.json

    .PARAMETER Encoding
    Encoding is the parameter specifying the encoding of the JSON output file.
    Default: UTF8

	.PARAMETER EventTypes
    Specifies which types of sign-in events to collect. Can be one or more of:
    - All: Collects all event types (default)
    - interactiveUser: User sign-ins requiring user interaction
    - nonInteractiveUser: Automated user sign-ins
    - servicePrincipal: Application sign-ins
    - managedIdentity: Azure managed identity sign-ins
    Default: 'All'

    .PARAMETER UserIds
    UserIds is the UserIds parameter filtering the log entries by the account of the user who performed the actions.

    .EXAMPLE
    Get-GraphEntraSignInLogs
    Get all audit logs of sign-ins.

    .EXAMPLE
    Get-GraphEntraSignInLogs -Application
    Get all audit logs of sign-ins via application authentication.

    .EXAMPLE
    Get-GraphEntraSignInLogs -endDate 2025-04-12
    Get audit logs before 2025-04-12.

    .EXAMPLE
    Get-GraphEntraSignInLogs -startDate 2025-04-12
    Get audit logs after 2025-04-12.

	EXAMPLE
    Get-GraphEntraSignInLogs -EventTypes interactiveUser
    Get only interactive user sign-in logs.

    .EXAMPLE
    Get-GraphEntraSignInLogs -EventTypes interactiveUser,servicePrincipal
    Get both interactive user and service principal sign-in logs.

	.EXAMPLE
    Get-GraphEntraSignInLogs -Output SOF-ELK -MergeOutput
    Get the Entra ID SignIn Log in a format compatible with the SOF-ELK platform and merge all data into a single file.
#>
    [CmdletBinding()]
    param(
        [string]$startDate,
		[string]$endDate,
		[ValidateSet("JSON", "SOF-ELK")] 
		[string]$Output = "JSON",
        [string]$OutputDir,
		[string[]]$UserIds,
		[switch]$MergeOutput,
        [string]$Encoding = "UTF8",
        [ValidateSet('None', 'Minimal', 'Standard', 'Debug')]
        [string]$LogLevel = 'Standard',
		[Parameter()]
		[ValidateSet('All', 'interactiveUser', 'nonInteractiveUser', 'servicePrincipal', 'managedIdentity')]
		[string[]]$EventTypes = @('All')
	)

	Init-Logging
    Init-OutputDir -Component "EntraID" -SubComponent "SignInLogs" -FilePostfix "SignInLogs" -CustomOutputDir $OutputDir

    $summary = @{
        TotalRecords = 0
        StartTime = Get-Date
        ProcessingTime = $null
        TotalFiles = 0
    }

	if ($isDebugEnabled) {
        Write-LogFile -Message "[DEBUG] PowerShell Version: $($PSVersionTable.PSVersion)" -Level Debug
        Write-LogFile -Message "[DEBUG] Input parameters:" -Level Debug
        Write-LogFile -Message "[DEBUG]   StartDate: $startDate" -Level Debug
        Write-LogFile -Message "[DEBUG]   EndDate: $endDate" -Level Debug
        Write-LogFile -Message "[DEBUG]   Output: $Output" -Level Debug
        Write-LogFile -Message "[DEBUG]   OutputDir: $OutputDir" -Level Debug
        Write-LogFile -Message "[DEBUG]   UserIds: $UserIds" -Level Debug
        Write-LogFile -Message "[DEBUG]   MergeOutput: $($MergeOutput.IsPresent)" -Level Debug
        Write-LogFile -Message "[DEBUG]   Encoding: $Encoding" -Level Debug
        Write-LogFile -Message "[DEBUG]   LogLevel: $LogLevel" -Level Debug
        Write-LogFile -Message "[DEBUG]   EventTypes: $($EventTypes -join ', ')" -Level Debug
        
        $graphModule = Get-Module -Name Microsoft.Graph* -ErrorAction SilentlyContinue
        if ($graphModule) {
            Write-LogFile -Message "[DEBUG] Microsoft Graph Modules loaded:" -Level Debug
            foreach ($module in $graphModule) {
                Write-LogFile -Message "[DEBUG]   - $($module.Name) v$($module.Version)" -Level Debug
            }
        } else {
            Write-LogFile -Message "[DEBUG] No Microsoft Graph modules loaded" -Level Debug
        }
    }

	Write-LogFile -Message "=== Starting Sign-in Log Collection ===" -Color "Cyan" -Level Standard
	$requiredScopes = @("AuditLog.Read.All", "Directory.Read.All")
    $graphAuth = Get-GraphAuthType -RequiredScopes $RequiredScopes
	$OutputDir = Split-Path $script:outputFile -Parent

	StartDateAz -Quiet
    EndDate -Quiet

	$StartDate = $script:StartDate.ToString("yyyy-MM-ddTHH:mm:ss'Z'", [System.Globalization.CultureInfo]::InvariantCulture)
	$EndDate = $script:EndDate.ToString("yyyy-MM-ddTHH:mm:ss'Z'", [System.Globalization.CultureInfo]::InvariantCulture)

	Write-LogFile -Message "Start Date: $StartDate" -Level Standard
    Write-LogFile -Message "End Date: $EndDate" -Level Standard
    Write-LogFile -Message "Output Format: $Output" -Level Standard

    if ($UserIds) {
        Write-LogFile -Message "Filtering for User: $UserIds" -Level Standard
    }
    Write-LogFile -Message "----------------------------------------`n" -Level Standard

	$eventTypeMapping = @{
		'interactiveUser' = @{
			displayName = 'interactiveUser'
			filename = 'interactiveUser'
			filterQuery = "(signInEventTypes/any(t: t eq 'interactiveUser'))"
		}
		'nonInteractiveUser' = @{
			displayName = 'nonInteractiveUser'
			filename = 'nonInteractiveUser'
			filterQuery = "(signInEventTypes/any(t: t eq 'nonInteractiveUser'))"
		}
		'interactiveUserAndNonInteractiveUser' = @{
			displayName = 'interactiveUser & nonInteractiveUser'
			filename = 'interactiveUser-nonInteractiveUser'
			filterQuery = "(signInEventTypes/any(t: t eq 'interactiveUser' or t eq 'nonInteractiveUser'))"
		}
		'servicePrincipal' = @{
			displayName = 'servicePrincipal'
			filename = 'servicePrincipal'
			filterQuery = "(signInEventTypes/any(t: t eq 'servicePrincipal'))"
		}
		'managedIdentity' = @{
			displayName = 'managedIdentity'
			filename = 'managedIdentity'
			filterQuery = "(signInEventTypes/any(t: t eq 'managedIdentity'))"
		}
	}

	$eventTypesToProcess = @()
	if ($EventTypes -contains 'All') {
		if ($UserIds -and $UserIds.Count -gt 0) {
			$eventTypesToProcess = @('interactiveUserAndNonInteractiveUser')
			Write-LogFile -Message "[INFO] Filtering by users - skipping servicePrincipal and managedIdentity (will be empty)" -Level Standard -Color "Yellow"
		} else {
			$eventTypesToProcess = @('interactiveUserAndNonInteractiveUser', 'servicePrincipal', 'managedIdentity')
		}
	} elseif ($EventTypes -contains 'interactiveUser' -and $EventTypes -contains 'nonInteractiveUser') {
		$remainingTypes = $EventTypes | Where-Object { $_ -ne 'interactiveUser' -and $_ -ne 'nonInteractiveUser' }
		$eventTypesToProcess = @('interactiveUserAndNonInteractiveUser') + $remainingTypes
	}
	else {
		$eventTypesToProcess = $EventTypes
	}

	foreach ($eventType in $eventTypesToProcess) {
		$currentEventType = $eventTypeMapping[$eventType]
		Write-LogFile -Message "[INFO] Acquiring the $($currentEventType.displayName) sign-in logs" -Level Standard -Color "Cyan"

		if ($isDebugEnabled) {
            Write-LogFile -Message "[DEBUG] Event type configuration:" -Level Debug
            Write-LogFile -Message "[DEBUG]   Display name: $($currentEventType.displayName)" -Level Debug
            Write-LogFile -Message "[DEBUG]   Filename pattern: $($currentEventType.filename)" -Level Debug
            Write-LogFile -Message "[DEBUG]   Filter query: $($currentEventType.filterQuery)" -Level Debug
        }

		$eventTypeDir = Join-Path -Path $OutputDir -ChildPath $currentEventType.displayName
		if (!(Test-Path $eventTypeDir)) {
			New-Item -ItemType Directory -Force -Path $eventTypeDir > $null
		}
        
        $filterQuery = "createdDateTime ge $StartDate and createdDateTime le $EndDate"

		if ($UserIds -and $UserIds.Count -gt 0) {
			$userFilters = $UserIds | ForEach-Object { "startsWith(userPrincipalName, '$_')" }
			$filterQuery += " and (" + ($userFilters -join " or ") + ")"
		}
        
		$filterQuery += " and $($currentEventType.filterQuery)"
        $encodedFilterQuery = [System.Web.HttpUtility]::UrlEncode($filterQuery)
        $apiUrl = "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=$encodedFilterQuery"
        
		if ($isDebugEnabled) {
            Write-LogFile -Message "[DEBUG] API configuration:" -Level Debug
            Write-LogFile -Message "[DEBUG]   Base URL: https://graph.microsoft.com/beta/auditLogs/signIns" -Level Debug
            Write-LogFile -Message "[DEBUG]   Filter query (decoded): $filterQuery" -Level Debug
            Write-LogFile -Message "[DEBUG]   Full API URL: $apiUrl" -Level Debug
        }

        $eventTypeSummary = @{
            EventType = $currentEventType.displayName
            RecordCount = 0
            Files = 0
        }

		try {
			Do {
				$retryCount = 0
				$maxRetries = 3
				$success = $false
				$tokenRetryCount = 0
    			$maxTokenRetries = 5  

				while (-not $success -and $retryCount -lt $maxRetries) {
					try {
						$response = Invoke-MgGraphRequest -Uri $apiUrl -Method Get -ContentType "application/json; odata.metadata=minimal; odata.streaming=true;" -OutputType Json
						$responseJson = $response | ConvertFrom-Json 
						$success = $true
					}
					catch {
						if (($_.Exception.Message -like "*Skip token is null*" -or 
							$_.Exception.Message -like "*token*expired*" -or
							$_.Exception.Message -like "*Bad Request*") -and 
							$tokenRetryCount -lt $maxTokenRetries) {
							
							$tokenRetryCount++
							Write-LogFile -Message "[WARNING] Token expired or invalid. Reconnecting and retrying... Attempt $tokenRetryCount of $maxTokenRetries" -Level Standard -Color "Yellow"

							if ($isDebugEnabled) {
                                Write-LogFile -Message "[DEBUG] Token error details:" -Level Debug
                                Write-LogFile -Message "[DEBUG]   Error message: $($_.Exception.Message)" -Level Debug
                                Write-LogFile -Message "[DEBUG]   Token retry count: $tokenRetryCount" -Level Debug
                            }
							
							# Re-authenticate to refresh the token
							$graphAuth = Get-GraphAuthType -RequiredScopes $RequiredScopes -Force
							Start-Sleep -Seconds 20
							continue
						}
						
						$retryCount++
						if ($retryCount -lt $maxRetries) {
							Write-LogFile -Message "[WARNING] Failed to acquire logs. Retrying... Attempt $retryCount of $maxRetries" -Level Standard -Color "Yellow"
							Start-Sleep -Seconds 15
							if ($isDebugEnabled) {
                                Write-LogFile -Message "[DEBUG] API call error details:" -Level Debug
                                Write-LogFile -Message "[DEBUG]   Exception type: $($_.Exception.GetType().Name)" -Level Debug
                                Write-LogFile -Message "[DEBUG]   Full error: $($_.Exception.ToString())" -Level Debug
                                Write-LogFile -Message "[DEBUG]   Stack trace: $($_.ScriptStackTrace)" -Level Debug
                            }
						}
						else {
							Write-LogFile -Message "[ERROR] Failed to acquire logs after $maxRetries attempts. Error: $($_.Exception.Message)" -Level Minimal -Color "Red"
							throw
						}
					}
				}
			
				if ($responseJson.value) {
					$date = [datetime]::Now.ToString('yyyyMMddHHmmss') 
					$filePath = Join-Path -Path $eventTypeDir -ChildPath "$($date)-$($currentEventType.filename)-SignInLogs.json"

					if ($isDebugEnabled) {
                        Write-LogFile -Message "[DEBUG] Processing response data:" -Level Debug
                        Write-LogFile -Message "[DEBUG]   Records in batch: $($responseJson.value.Count)" -Level Debug
                        Write-LogFile -Message "[DEBUG]   Output file: $filePath" -Level Debug
                    }

					if ($Output -eq "JSON" ) {
						$responseJson.value | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath -Append -Encoding $Encoding	
					} 
					elseif ($Output -eq "SOF-ELK"){
						# UTF8 is fixed, as it is required by SOF-ELK
						foreach ($item in $responseJson.value) {
							$item | ConvertTo-Json -Depth 100 -Compress | Out-File -FilePath $filePath -Append -Encoding UTF8	
						}
					}

					$currentBatchCount = ($responseJson.value | Measure-Object).Count
					$summary.TotalRecords += $currentBatchCount
					$summary.TotalFiles++
					$eventTypeSummary.RecordCount += $currentBatchCount
                    $eventTypeSummary.Files++

					$dates = $responseJson.value | ForEach-Object {
						[DateTime]::Parse($_.CreatedDateTime, [System.Globalization.CultureInfo]::InvariantCulture)
					} | Sort-Object
					
					$from =  $dates | Select-Object -First 1
					$to = ($dates | Select-Object -Last 1)
					Write-LogFile -Message "[INFO] Retrieved $currentBatchCount records between $from and $to" -Level Standard -Color "Green"
				}
				$apiUrl = $responseJson.'@odata.nextLink'
			} While ($apiUrl)

			if ($MergeOutput.IsPresent) {
				Write-LogFile -Message "[INFO] Merging output files for $eventType" -Level Standard
				if ($Output -eq "JSON") {
					Merge-OutputFiles -OutputDir $eventTypeDir -OutputType "JSON" -MergedFileName "SignInLogs-$($currentEventType.filename)-Combined.json"
				}
				elseif ($Output -eq "SOF-ELK") {
				Merge-OutputFiles -OutputDir $eventTypeDir -OutputType "SOF-ELK" -MergedFileName "SignInLogs-$($currentEventType.filename)-Combined.json"				}
			}

			Write-LogFile -Message "`nSummary for $($currentEventType.displayName):" -Color "Cyan" -Level Standard
            Write-LogFile -Message "  Records: $($eventTypeSummary.RecordCount)" -Level Standard
            Write-LogFile -Message "  Files: $($eventTypeSummary.Files)`n" -Level Standard
		}
		
		catch {
			Write-LogFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Level Minimal -Color "Red"
			if ($isDebugEnabled) {
                Write-LogFile -Message "[DEBUG] Event type processing error:" -Level Debug
                Write-LogFile -Message "[DEBUG]   Exception type: $($_.Exception.GetType().Name)" -Level Debug
                Write-LogFile -Message "[DEBUG]   Full error: $($_.Exception.ToString())" -Level Debug
                Write-LogFile -Message "[DEBUG]   Stack trace: $($_.ScriptStackTrace)" -Level Debug
            }
			throw
		}
	}

	$summary.ProcessingTime = (Get-Date) - $summary.StartTime

	$summaryData = [ordered]@{
		"Collection Results" = [ordered]@{
			"Total Records" = $summary.TotalRecords
			"Files Created" = $summary.TotalFiles
		}
	}

	Write-Summary -Summary $summaryData -Title "Sign-in Log Collection Summary"
	Write-LogFile -Message "`nNote: Files organized by event type in: $OutputDir" -Level Standard
}

function Get-GraphEntraAuditLogs {
	<#
	.SYNOPSIS
	Get directory audit logs.

	.DESCRIPTION
	The Get-GraphEntraAuditLogs GraphAPI cmdlet to collect the contents of the Entra ID Audit logs.

	.PARAMETER startDate
	The startDate parameter specifies the date from which all logs need to be collected.

	.PARAMETER endDate
    The Before parameter specifies the date endDate which all logs need to be collected.

	.PARAMETER OutputDir
	outputDir is the parameter specifying the output directory.
	Default: The output will be written to: "Output\EntraID\{date_AuditLogs}\Auditlogs.json

	.PARAMETER UserIds
	UserIds is the UserIds parameter filtering the log entries by the account of the user who performed the actions.

	.PARAMETER All
    When specified along with UserIds, this parameter filters the results to include events where the provided UserIds match any user principal name found in either the userPrincipalNames or targetResources fields.

	.PARAMETER Encoding
	Encoding is the parameter specifying the encoding of the JSON output file.
	Default: UTF8

	.PARAMETER MergeOutput
	MergeOutput is the parameter specifying if you wish to merge outputs to a single file
	Default: No

	.PARAMETER Output
    Output is the parameter specifying the JSON or SOF-ELK output type. The SOF-ELK output can be imported into the platform of the same name.
	Default: JSON

	.EXAMPLE
	Get-GraphEntraAuditLogs
	Get directory audit logs.

	.EXAMPLE
	Get-GraphEntraAuditLogs -Application
	Get directory audit logs via application authentication.

	.PARAMETER LogLevel
    Specifies the level of logging:
    None: No logging
    Minimal: Critical errors only
    Standard: Normal operational logging
    Default: Standard

	.EXAMPLE
    Get-GraphEntraAuditLogs -UserIds 'user@example.com' -All
    Get sign-in logs for 'user@example.com', including both userPrincipalName and targetResources in the filter.

	.EXAMPLE
	Get-GraphEntraAuditLogs -Before 2025-04-12
	Get directory audit logs before 2025-04-12.

	.EXAMPLE
	Get-GraphEntraAuditLogs -After 2025-04-12
	Get directory audit logs after 2025-04-12.
	#>
	[CmdletBinding()]
	param(
		[string]$startDate,
		[string]$endDate,
		[string]$OutputDir,
		[ValidateSet("JSON", "SOF-ELK")] 
		[string]$Output = "JSON",
		[string]$Encoding = "UTF8",
		[switch]$MergeOutput,
		[string[]]$UserIds,
        [switch]$All,
        [ValidateSet('None', 'Minimal', 'Standard', 'Debug')]
        [string]$LogLevel = 'Standard'
	)

	Init-Logging
    Init-OutputDir -Component "EntraID" -SubComponent "AuditLogs" -FilePostfix "AuditLogs" -CustomOutputDir $OutputDir
    $summary = @{
        TotalRecords = 0
        StartTime = Get-Date
        ProcessingTime = $null
        TotalFiles = 0
    }

    Write-LogFile -Message "=== Starting Audit Log Collection ===" -Color "Cyan" -Level Standard
    $requiredScopes = @("AuditLog.Read.All", "Directory.Read.All")
    $graphAuth = Get-GraphAuthType -RequiredScopes $RequiredScopes
	$OutputDir = Split-Path $script:outputFile -Parent

	StartDateAz -Quiet
    EndDate -Quiet

	$StartDate = $script:StartDate.ToString("yyyy-MM-ddTHH:mm:ss'Z'", [System.Globalization.CultureInfo]::InvariantCulture)
	$EndDate = $script:EndDate.ToString("yyyy-MM-ddTHH:mm:ss'Z'", [System.Globalization.CultureInfo]::InvariantCulture)

	Write-LogFile -Message "Start Date: $StartDate" -Level Standard
    Write-LogFile -Message "End Date: $EndDate" -Level Standard
    Write-LogFile -Message "Output Format: $Output" -Level Standard
    if ($UserIds) {
        Write-LogFile -Message "Filtering for User: $UserIds" -Level Standard
    }
    Write-LogFile -Message "----------------------------------------`n" -Level Standard

	$filterQuery = "activityDateTime ge $StartDate and activityDateTime le $EndDate"
	if ($UserIds -and $UserIds.Count -gt 0) {
		$userFilters = $UserIds | ForEach-Object { "startsWith(initiatedBy/user/userPrincipalName, '$_')" }
		$filterQuery += " and (" + ($userFilters -join " or ") + ")"
		
		if ($All.IsPresent) {
			$targetFilters = $UserIds | ForEach-Object { "targetResources/any(tr: tr/userPrincipalName eq '$_')" }
			$filterQuery = "($filterQuery) or (" + ($targetFilters -join " or ") + ")"
		}
	}
	else {
        if ($All.IsPresent) {
            Write-LogFile -Message "[WARNING] '-All' switch has no effect without specifying UserIds"
        }
    }

	$encodedFilterQuery = [System.Web.HttpUtility]::UrlEncode($filterQuery)
	$apiUrl = "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?`$filter=$encodedFilterQuery"

	if ($isDebugEnabled) {
        Write-LogFile -Message "[DEBUG] API configuration:" -Level Debug
        Write-LogFile -Message "[DEBUG]   Base URL: https://graph.microsoft.com/v1.0/auditLogs/directoryAudits" -Level Debug
        Write-LogFile -Message "[DEBUG]   Filter query (decoded): $filterQuery" -Level Debug
        Write-LogFile -Message "[DEBUG]   Full API URL: $apiUrl" -Level Debug
    }

	try {
		Do {
			$retryCount = 0
            $maxRetries = 3
            $success = $false

			while (-not $success -and $retryCount -lt $maxRetries) {
				try { 
					$response = Invoke-MgGraphRequest -Uri $apiUrl -Method Get -ContentType "application/json; odata.metadata=minimal; odata.streaming=true;" -OutputType Json
					$responseJson = $response | ConvertFrom-Json 
					$success = $true
				}
				catch {
					$retryCount++
					if ($retryCount -lt $maxRetries) {
						Write-LogFile -Message "[WARNING] Failed to acquire logs. Retrying... Attempt $retryCount of $maxRetries" -Level Standard -Color "Yellow"
						if ($isDebugEnabled) {
                            Write-LogFile -Message "[DEBUG] API call error details:" -Level Debug
                            Write-LogFile -Message "[DEBUG]   Exception type: $($_.Exception.GetType().Name)" -Level Debug
                            Write-LogFile -Message "[DEBUG]   Full error: $($_.Exception.ToString())" -Level Debug
                            Write-LogFile -Message "[DEBUG]   Stack trace: $($_.ScriptStackTrace)" -Level Debug
                        }
						Start-Sleep -Seconds 15
					}
					else {
						Write-LogFile -Message "[ERROR] Failed to acquire logs after $maxRetries attempts. Error: $($_.Exception.Message)" -Level Minimal -Color "Red"
						throw
					}
				}
			}

			if ($responseJson.value) {
				$date = [datetime]::Now.ToString('yyyyMMddHHmmss') 
				$filePath = Join-Path -Path $OutputDir -ChildPath "$($date)-AuditLogs.json"

				if ($isDebugEnabled) {
                    Write-LogFile -Message "[DEBUG] Processing response data:" -Level Debug
                    Write-LogFile -Message "[DEBUG]   Records in batch: $($responseJson.value.Count)" -Level Debug
                    Write-LogFile -Message "[DEBUG]   Output file: $filePath" -Level Debug
                }

				if ($Output -eq "JSON") {
                    $responseJson.value | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath -Append -Encoding $Encoding
                }
                elseif ($Output -eq "SOF-ELK") {
                    # UTF8 is fixed, as it is required by SOF-ELK
                    foreach ($item in $responseJson.value) {
                        $item | ConvertTo-Json -Depth 100 -Compress | Out-File -FilePath $filePath -Append -Encoding UTF8
                    }
                }

				$currentBatchCount = ($responseJson.value | Measure-Object).Count
                $summary.TotalRecords += $currentBatchCount
                $summary.TotalFiles++
				
				$dates = $responseJson.value | ForEach-Object {
					[DateTime]::Parse($_.activityDateTime, [System.Globalization.CultureInfo]::InvariantCulture)
				} | Sort-Object

                $from =  $dates | Select-Object -First 1
                $fromstr =  $from.ToString('yyyy-MM-ddTHH:mmZ')
                $to = ($dates | Select-Object -Last 1).ToString('yyyy-MM-ddTHH:mmZ')
				Write-LogFile -Message "[INFO] Retrieved $currentBatchCount records between $fromstr and $to" -Level Standard -Color "Green"
			}
			$apiUrl = $responseJson.'@odata.nextLink'
		} While ($apiUrl)

		if ($Output -eq "JSON" -and ($MergeOutput.IsPresent)) {
			Merge-OutputFiles -OutputDir $OutputDir -OutputType "JSON" -MergedFileName "AuditLogs-Combined.json"
		}
		elseif ($Output -eq "SOF-ELK" -and ($MergeOutput.IsPresent)) {
			Merge-OutputFiles -OutputDir $OutputDir -OutputType "SOF-ELK" -MergedFileName "AuditLogs-Combined.json"
		}

		$summary.ProcessingTime = (Get-Date) - $summary.StartTime

		$summaryData = [ordered]@{
			"Collection Results" = [ordered]@{
				"Total Records" = $summary.TotalRecords
				"Files Created" = $summary.TotalFiles
			}
		}

		Write-Summary -Summary $summaryData -Title "Audit Log Collection Summary"
		Write-LogFile -Message "`nNote: Output files saved to: $OutputDir" -Level Standard
    }
	catch {
		Write-logFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Color "Red" -Level Minimal
		if ($isDebugEnabled) {
            Write-LogFile -Message "[DEBUG] Fatal error details:" -Level Debug
            Write-LogFile -Message "[DEBUG]   Exception type: $($_.Exception.GetType().Name)" -Level Debug
            Write-LogFile -Message "[DEBUG]   Full error: $($_.Exception.ToString())" -Level Debug
            Write-LogFile -Message "[DEBUG]   Stack trace: $($_.ScriptStackTrace)" -Level Debug
            Write-LogFile -Message "[DEBUG]   Records collected before error: $($summary.TotalRecords)" -Level Debug
        }
		throw
    }
}
	
