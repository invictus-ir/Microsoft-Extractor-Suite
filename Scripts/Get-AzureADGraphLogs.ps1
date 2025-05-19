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
    Get-GraphEntraSignInLogs -endDate 2024-04-12
    Get audit logs before 2024-04-12.

    .EXAMPLE
    Get-GraphEntraSignInLogs -startDate 2024-04-12
    Get audit logs after 2024-04-12.

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
        [string]$UserIds,
		[switch]$MergeOutput,
        [string]$Encoding = "UTF8",
        [ValidateSet('None', 'Minimal', 'Standard', 'Debug')]
        [string]$LogLevel = 'Standard',
		[Parameter()]
		[ValidateSet('All', 'interactiveUser', 'nonInteractiveUser', 'servicePrincipal', 'managedIdentity')]
		[string[]]$EventTypes = @('All')
	)

	Set-LogLevel -Level ([LogLevel]::$LogLevel)
    $summary = @{
        TotalRecords = 0
        StartTime = Get-Date
        ProcessingTime = $null
        TotalFiles = 0
    }

	Write-LogFile -Message "=== Starting Sign-in Log Collection ===" -Color "Cyan" -Level Minimal
	$requiredScopes = @("AuditLog.Read.All", "Directory.Read.All")
    $graphAuth = Get-GraphAuthType -RequiredScopes $RequiredScopes

	$date = [datetime]::Now.ToString('yyyyMMdd') 
	if ($OutputDir -eq "" ){
		$OutputDir = "Output\EntraID\$($date)-SignInLogs"
		if (!(test-path $OutputDir)) {
			New-Item -ItemType Directory -Force -path $OutputDir > $null
		}
	}
	else {
        if (!(Test-Path -Path $OutputDir)) {
            Write-LogFile -Message "[Error] Custom directory invalid: $OutputDir" -Level Minimal -Color "Red"
            return
        }
    }

	StartDateAz -Quiet
    EndDate -Quiet

	$StartDate = $script:StartDate.ToString('yyyy-MM-ddTHH:mm:ssZ')
    $EndDate = $script:EndDate.ToString('yyyy-MM-ddTHH:mm:ssZ')

	Write-LogFile -Message "Start Date: $StartDate" -Level Standard
    Write-LogFile -Message "End Date: $EndDate" -Level Standard
    Write-LogFile -Message "Output Format: $Output" -Level Standard
    Write-LogFile -Message "Output Directory: $OutputDir" -Level Standard
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
		'combinedUser' = @{
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
		$eventTypesToProcess = @('combinedUser', 'servicePrincipal', 'managedIdentity')
    } elseif ($EventTypes -contains 'interactiveUser' -and $EventTypes -contains 'nonInteractiveUser') {
		$remainingTypes = $EventTypes | Where-Object { $_ -ne 'interactiveUser' -and $_ -ne 'nonInteractiveUser' }
		$eventTypesToProcess = @('combinedUser') + $remainingTypes
	}
	else {
		$eventTypesToProcess = $EventTypes
	}

	foreach ($eventType in $eventTypesToProcess) {
		$currentEventType = $eventTypeMapping[$eventType]
		Write-LogFile -Message "[INFO] Acquiring the $($currentEventType.displayName) sign-in logs" -Level Standard -Color "Cyan"

		$eventTypeDir = Join-Path -Path $OutputDir -ChildPath $currentEventType.displayName
		if (!(Test-Path $eventTypeDir)) {
			New-Item -ItemType Directory -Force -Path $eventTypeDir > $null
		}
        
        $filterQuery = "createdDateTime ge $StartDate and createdDateTime le $EndDate"
        if ($UserIds) {
            $filterQuery += " and startsWith(userPrincipalName, '$UserIds')"
        }
        
		$filterQuery += " and $($currentEventType.filterQuery)"
        $encodedFilterQuery = [System.Web.HttpUtility]::UrlEncode($filterQuery)
        $apiUrl = "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=$encodedFilterQuery"
        
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
							
							# Re-authenticate to refresh the token
							$graphAuth = Get-GraphAuthType -RequiredScopes $RequiredScopes -Force
							Start-Sleep -Seconds 20
							continue
						}
						
						$retryCount++
						if ($retryCount -lt $maxRetries) {
							Write-LogFile -Message "[WARNING] Failed to acquire logs. Retrying... Attempt $retryCount of $maxRetries" -Level Standard -Color "Yellow"
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
					$filePath = Join-Path -Path $eventTypeDir -ChildPath "$($date)-$($currentEventType.filename)-SignInLogs.json"

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
					Merge-OutputFiles -OutputDir $eventTypeDir -OutputType "SOF-ELK" -MergedFileName "SignInLogs-$eventType-Combined.json"
				}
			}

			Write-LogFile -Message "`nSummary for $($currentEventType.displayName):" -Color "Cyan" -Level Standard
            Write-LogFile -Message "  Records: $($eventTypeSummary.RecordCount)" -Level Standard
            Write-LogFile -Message "  Files: $($eventTypeSummary.Files)`n" -Level Standard
		}
		
		catch {
			Write-LogFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Level Minimal -Color "Red"
			throw
		}
	}

	$summary.ProcessingTime = (Get-Date) - $summary.StartTime
    Write-LogFile -Message "`nOverall Collection Summary:" -Color "Cyan" -Level Standard
    Write-LogFile -Message "  Total Records: $($summary.TotalRecords)" -Level Standard
    Write-LogFile -Message "  Files Created: $($summary.TotalFiles)" -Level Standard
    Write-LogFile -Message "  Output Directory: $OutputDir" -Level Standard
    Write-LogFile -Message "  Processing Time: $($summary.ProcessingTime.ToString('mm\:ss'))" -Level Standard -Color "Green"
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
	Get-GraphEntraAuditLogs -Before 2024-04-12
	Get directory audit logs before 2024-04-12.

	.EXAMPLE
	Get-GraphEntraAuditLogs -After 2024-04-12
	Get directory audit logs after 2024-04-12.
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
		[string]$UserIds,
        [switch]$All,
        [ValidateSet('None', 'Minimal', 'Standard', 'Debug')]
        [string]$LogLevel = 'Standard'
	)

	Set-LogLevel -Level ([LogLevel]::$LogLevel)
    $summary = @{
        TotalRecords = 0
        StartTime = Get-Date
        ProcessingTime = $null
        TotalFiles = 0
    }

    Write-LogFile -Message "=== Starting Sign-in Log Collection ===" -Color "Cyan" -Level Minimal
    $requiredScopes = @("AuditLog.Read.All", "Directory.Read.All")
    $graphAuth = Get-GraphAuthType -RequiredScopes $RequiredScopes
	
	$date = [datetime]::Now.ToString('yyyyMMdd') 
	if ($OutputDir -eq "" ){
		$OutputDir = "Output\EntraID\$($date)-Auditlogs"
		if (!(test-path $OutputDir)) {
			New-Item -ItemType Directory -Force -Path $OutputDir > $null
			write-logFile -Message "[INFO] Creating the following directory: $OutputDir"
		}
	}
	else {
        if (!(Test-Path -Path $OutputDir)) {
            Write-LogFile -Message "[Error] Custom directory invalid: $OutputDir" -Level Minimal -Color "Red"
            return
        }
    }

	StartDateAz -Quiet
    EndDate -Quiet

	$StartDate = $script:StartDate.ToString('yyyy-MM-ddTHH:mm:ssZ')
	$EndDate = $script:EndDate.ToString('yyyy-MM-ddTHH:mm:ssZ')

	Write-LogFile -Message "Start Date: $StartDate" -Level Standard
    Write-LogFile -Message "End Date: $EndDate" -Level Standard
    Write-LogFile -Message "Output Format: $Output" -Level Standard
    Write-LogFile -Message "Output Directory: $OutputDir" -Level Standard
    if ($UserIds) {
        Write-LogFile -Message "Filtering for User: $UserIds" -Level Standard
    }
    Write-LogFile -Message "----------------------------------------`n" -Level Standard

	$filterQuery = "activityDateTime ge $StartDate and activityDateTime le $EndDate"
	if ($UserIds) {
		$filterQuery += " and startsWith(initiatedBy/user/userPrincipalName, '$UserIds')"

		if ($All.IsPresent) {
            $filterQuery = "($filterQuery) or (targetResources/any(tr: tr/userPrincipalName eq '$UserIds'))"
        }
	}
	else {
        if ($All.IsPresent) {
            Write-LogFile -Message "[WARNING] '-All' switch has no effect without specifying UserIds"
        }
    }

	$encodedFilterQuery = [System.Web.HttpUtility]::UrlEncode($filterQuery)
	$apiUrl = "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?`$filter=$encodedFilterQuery"

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
        Write-LogFile -Message "`nCollection Summary:" -Color "Cyan" -Level Standard
        Write-LogFile -Message "  Total Records: $($summary.TotalRecords)" -Level Standard
        Write-LogFile -Message "  Files Created: $($summary.TotalFiles)" -Level Standard
        Write-LogFile -Message "  Output Directory: $OutputDir" -Level Standard
        Write-LogFile -Message "  Processing Time: $($summary.ProcessingTime.ToString('mm\:ss'))" -Level Standard -Color "Green"
    }
	catch {
		Write-logFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Color "Red" -Level Minimal
		throw
    }
}
	
