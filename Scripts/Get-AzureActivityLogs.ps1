function Get-ActivityLogs {
	<#
    .SYNOPSIS
    Retrieves the Activity logs.

    .DESCRIPTION
    The Get-ActivityLogs cmdlet collects the Azure Activity logs.
	The output will be written to: Output\ActivityLogs\$date\$iD-ActivityLog.json

	.PARAMETER StartDate
    startDate is the parameter specifying the start date of the date range.
	Default: Today -89 days

	.PARAMETER EndDate
    endDate is the parameter specifying the end date of the date range.
	Default: Now
	
	.PARAMETER SubscriptionID
    SubscriptionID is the parameter specifies the subscription ID for which the collection of Activity logs is required.
    Default: All subscriptions

	.PARAMETER OutputDir
    OutputDir is the parameter specifying the output directory.
	Default: Output\ActivityLogs

	.PARAMETER Encoding
    Encoding is the parameter specifying the encoding of the JSON output file.
	Default: UTF8

	.PARAMETER LogLevel
    Specifies the level of logging:
    None: No logging
    Minimal: Critical errors only
    Standard: Normal operational logging
	Debug: Verbose logging for debugging purposes
    Default: Standard
	
    .EXAMPLE
    Get-ActivityLogs
	Get all the activity logs for all subscriptions connected to the logged-in user account for the last 89 days.

	.EXAMPLE
    Get-ActivityLogs -EndDate 2025-04-12
	Get all the activity logs before 2025-04-12.

	.EXAMPLE
    Get-ActivityLogs -StartDate 2025-04-12
	Get all the activity logs after 2025-04-12.
	
	.EXAMPLE
    Get-ActivityLogs -SubscriptionID "4947f939-cf12-4329-960d-4dg68a3eb66f"
	Get all the activity logs for the subscription 4947f939-cf12-4329-960d-4dg68a3eb66f
#>
	[CmdletBinding()]
	param(
		[string]$StartDate,
		[string]$EndDate,
		[string]$SubscriptionID,
		[string]$OutputDir,
		[string]$Encoding = "UTF8",
        [ValidateSet('None', 'Minimal', 'Standard', 'Debug')]
        [string]$LogLevel = 'Standard'		
	)

	Init-Logging
    Init-OutputDir -Component "Activity Logs" -FilePostfix "ActivityLogs" -CustomOutputDir $OutputDir

    $summary = @{
        TotalRecords = 0
        TotalFiles = 0
        SubscriptionsProcessed = 0
        SubscriptionsWithData = 0
        EmptySubscriptions = 0
        StartTime = Get-Date
        ProcessingTime = $null
    }

	Write-LogFile -Message "=== Starting Azure Activity Log Collection ===" -Color "Cyan" -Level Standard

	StartDate -Quiet
    EndDate -Quiet

	Write-LogFile -Message "Start Date: $($script:StartDate.ToString('yyyy-MM-dd HH:mm:ss'))" -Level Standard
	Write-LogFile -Message "End Date: $($script:EndDate.ToString('yyyy-MM-dd HH:mm:ss'))" -Level Standard

	$originalWarningPreference = $WarningPreference
	$WarningPreference = 'SilentlyContinue'

	if ($isDebugEnabled) {
        Write-LogFile -Message "[DEBUG] Warning preference changed from '$originalWarningPreference' to 'SilentlyContinue'" -Level Debug
    }

	try {
		$encryptedToken  = (Get-AzAccessToken -ResourceUrl "https://management.azure.com" -AsSecureString).token
		$accessToken = [PSCredential]::new("token", $encryptedToken)

		if ($isDebugEnabled) {
            Write-LogFile -Message "[DEBUG] Access token retrieved successfully:" -Level Debug
            try {
                $azContext = Get-AzContext
                if ($azContext) {
                    Write-LogFile -Message "[DEBUG] Azure context information:" -Level Debug
                    Write-LogFile -Message "[DEBUG]   Account: $($azContext.Account.Id)" -Level Debug
                    Write-LogFile -Message "[DEBUG]   Environment: $($azContext.Environment.Name)" -Level Debug
                    Write-LogFile -Message "[DEBUG]   Tenant: $($azContext.Tenant.Id)" -Level Debug
                    if ($azContext.Subscription) {
                        Write-LogFile -Message "[DEBUG]   Current subscription: $($azContext.Subscription.Id) ($($azContext.Subscription.Name))" -Level Debug
                    }
                }
            }
            catch {
                Write-LogFile -Message "[DEBUG] Could not retrieve Azure context details" -Level Debug
            }
        }
	}
	catch {
		write-logFile -Message "[INFO] Ensure you are connected to Azure by running the Connect-AzureAz command before executing this script" -Color "Yellow" -Level Minimal
		Write-logFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Color "Red" -Level Minimal

		if ($isDebugEnabled) {
            Write-LogFile -Message "[DEBUG] Azure token retrieval failed:" -Level Debug
            Write-LogFile -Message "[DEBUG]   Exception type: $($_.Exception.GetType().Name)" -Level Debug
            Write-LogFile -Message "[DEBUG]   Exception message: $($_.Exception.Message)" -Level Debug
            Write-LogFile -Message "[DEBUG]   Stack trace: $($_.ScriptStackTrace)" -Level Debug
        }
		throw
	}

	if ($SubscriptionID -eq "") {
		Write-LogFile -Message "[INFO] Retrieving all available subscriptions..." -Level Standard

		try {
			$subscriptionsUri = "https://management.azure.com/subscriptions?api-version=2020-01-01"
			$headers = @{
				Authorization = "Bearer $($accessToken.GetNetworkCredential().Password)"
				'Content-Type' = 'application/json'
			}

			if ($isDebugEnabled) {
                Write-LogFile -Message "[DEBUG] Subscription API call:" -Level Debug
                Write-LogFile -Message "[DEBUG]   URI: $subscriptionsUri" -Level Debug
                Write-LogFile -Message "[DEBUG]   Headers: Authorization (Bearer token), Content-Type (application/json)" -Level Debug
            }

			$subscriptionsResponse = Invoke-RestMethod -Uri $subscriptionsUri -Headers $headers -Method Get
			$subScription = $subscriptionsResponse.value
		}
		catch {
			write-logFile -Message "[INFO] Ensure you are connected to Azure by running the Connect-AzureAz command before executing this script" -Color "Yellow" -Level Minimal
			Write-logFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Color "Red" -Level Minimal

			if ($isDebugEnabled) {
                Write-LogFile -Message "[DEBUG] Subscription retrieval failed:" -Level Debug
                Write-LogFile -Message "[DEBUG]   Exception: $($_.Exception.Message)" -Level Debug
                Write-LogFile -Message "[DEBUG]   URI attempted: $subscriptionsUri" -Level Debug
                Write-LogFile -Message "[DEBUG]   Stack trace: $($_.ScriptStackTrace)" -Level Debug
            }
			throw
		}

		Write-LogFile -Message "[INFO] Found $($subscription.Count) subscriptions" -Level Standard
		if ($isDebugEnabled) {
            Write-LogFile -Message "[DEBUG] Detailed subscription list:" -Level Debug
        }

        foreach ($sub in $subscription) {
            Write-LogFile -Message "  - $($sub.subscriptionId) ($($sub.displayName))" -Level Standard
			if ($isDebugEnabled) {
                Write-LogFile -Message "[DEBUG]   Subscription details:" -Level Debug
                Write-LogFile -Message "[DEBUG]     ID: $($sub.subscriptionId)" -Level Debug
                Write-LogFile -Message "[DEBUG]     Name: $($sub.displayName)" -Level Debug
                Write-LogFile -Message "[DEBUG]     State: $($sub.state)" -Level Debug
                if ($sub.tenantId) {
                    Write-LogFile -Message "[DEBUG]     Tenant: $($sub.tenantId)" -Level Debug
                }
            }
        }
		Write-LogFile -Message " " -Level Standard
	}
	else {
		try {
			Write-LogFile -Message "[INFO] Processing single subscription: $SubscriptionID" -Level Standard
			$subScription = Get-AzSubscription -SubscriptionId $SubscriptionID

			if ($isDebugEnabled) {
                $singleSubRetrievalTime = (Get-Date) - $singleSubRetrievalStart
                Write-LogFile -Message "[DEBUG] Single subscription retrieval completed:" -Level Debug
                Write-LogFile -Message "[DEBUG]   Retrieval time: $($singleSubRetrievalTime.TotalSeconds) seconds" -Level Debug
                Write-LogFile -Message "[DEBUG]   Subscription name: $($subScription.Name)" -Level Debug
                Write-LogFile -Message "[DEBUG]   Subscription state: $($subScription.State)" -Level Debug
                Write-LogFile -Message "[DEBUG]   Tenant ID: $($subScription.TenantId)" -Level Debug
            }
		}
		catch {
			write-logFile -Message "[INFO] Ensure you are connected to Azure by running the Connect-AzureAz command before executing this script" -Color "Yellow" -Level Minimal
			Write-logFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Color "Red" -Level Minimal

			if ($isDebugEnabled) {
                Write-LogFile -Message "[DEBUG] Single subscription retrieval failed:" -Level Debug
                Write-LogFile -Message "[DEBUG]   Requested subscription ID: $SubscriptionID" -Level Debug
                Write-LogFile -Message "[DEBUG]   Exception: $($_.Exception.Message)" -Level Debug
                Write-LogFile -Message "[DEBUG]   Stack trace: $($_.ScriptStackTrace)" -Level Debug
            }
			throw
		}
	}

	foreach ($sub in $subScription) {
		$summary.SubscriptionsProcessed++
		$subId = $sub.subscriptionId
		write-logFile -Message "[INFO] Retrieving all Activity Logs for $subId" -Color "Green" -Level Standard
        
        $apiCallCount = 0
        $totalApiTime = 0

		if ($isDebugEnabled) {
            Write-LogFile -Message "[DEBUG] === Processing subscription $($summary.SubscriptionsProcessed) of $($subScription.Count) ===" -Level Debug
            Write-LogFile -Message "[DEBUG] Subscription ID: $subId" -Level Debug
            Write-LogFile -Message "[DEBUG] Subscription name: $($sub.displayName)" -Level Debug
            $subscriptionProcessingStart = Get-Date
        }

		$date = [datetime]::Now.ToString('yyyyMMddHHmmss') 
        $filePath = "$(Split-Path $script:outputFile -Parent)\$($date)-$subId-ActivityLog.json"

		$uriBase = "https://management.azure.com/subscriptions/$subId/providers/Microsoft.Insights/eventtypes/management/values?api-version=2015-04-01&`$filter=eventTimestamp ge '$script:StartDate' and eventTimestamp le '$script:endDate'"
		$events = @()

		if ($isDebugEnabled) {
            Write-LogFile -Message "[DEBUG] Activity Log API configuration:" -Level Debug
            Write-LogFile -Message "[DEBUG]   Base URI: $uriBase" -Level Debug
            Write-LogFile -Message "[DEBUG]   API version: 2015-04-01" -Level Debug
            Write-LogFile -Message "[DEBUG]   Filter: eventTimestamp ge '$script:StartDate' and eventTimestamp le '$script:endDate'" -Level Debug
        }

		do {
            $apiCallStart = Get-Date
            $apiCallCount++
			$listOperations = @{
				Uri     = $uriBase
				Headers = @{
					Authorization  = "Bearer $($accessToken.GetNetworkCredential().Password)"
					'Content-Type' = 'application/json'
				}
				Method  = 'GET'
			}

			$response = Invoke-RestMethod @listOperations
			$events += $response.value
			$uriBase = $response.nextLink

			if ($isDebugEnabled) {
                $apiCallTime = (Get-Date) - $apiCallStart
                $totalApiTime += $apiCallTime.TotalSeconds
                Write-LogFile -Message "[DEBUG] API call #$apiCallCount completed:" -Level Debug
                Write-LogFile -Message "[DEBUG]   Call duration: $($apiCallTime.TotalSeconds) seconds" -Level Debug
                Write-LogFile -Message "[DEBUG]   Events in this batch: $($response.value.Count)" -Level Debug
                Write-LogFile -Message "[DEBUG]   Total events so far: $($events.Count)" -Level Debug
                Write-LogFile -Message "[DEBUG]   Has next link: $(if ($response.nextLink) { 'Yes' } else { 'No' })" -Level Debug
                if ($response.nextLink) {
                    Write-LogFile -Message "[DEBUG]   Next link: $($response.nextLink)" -Level Debug
                }
            }
		} while ($null -ne $uriBase)

		if ($isDebugEnabled) {
            $subscriptionProcessingTime = (Get-Date) - $subscriptionProcessingStart
            Write-LogFile -Message "[DEBUG] Subscription processing completed:" -Level Debug
            Write-LogFile -Message "[DEBUG]   Total API calls: $apiCallCount" -Level Debug
            Write-LogFile -Message "[DEBUG]   Total API time: $([Math]::Round($totalApiTime, 2)) seconds" -Level Debug
            if ($apiCallCount -gt 0) { Write-LogFile -Message "[DEBUG]   Average API call time: $([Math]::Round($totalApiTime / $apiCallCount, 2)) seconds" -Level Debug } else { Write-LogFile -Message "[DEBUG]   Average API call time: N/A" -Level Debug }
            Write-LogFile -Message "[DEBUG]   Total processing time: $($subscriptionProcessingTime.TotalSeconds) seconds" -Level Debug
            Write-LogFile -Message "[DEBUG]   Events retrieved: $($events.Count)" -Level Debug
        }

		if ($events.Count -eq 0) {
			Write-LogFile -Message "[WARNING] No Activity logs in subscription: $($subId), or an error occurred." -Color Yellow -Level Minimal
			$summary.EmptySubscriptions++

			if ($isDebugEnabled) {
                Write-LogFile -Message "[DEBUG] Empty subscription analysis:" -Level Debug
                Write-LogFile -Message "[DEBUG]   Subscription ID: $subId" -Level Debug
                Write-LogFile -Message "[DEBUG]   API calls made: $apiCallCount" -Level Debug
                Write-LogFile -Message "[DEBUG]   Total API time: $([Math]::Round($totalApiTime, 2)) seconds" -Level Debug
                Write-LogFile -Message "[DEBUG]   Possible reasons: No activity in date range, insufficient permissions, subscription inactive" -Level Debug
            }
		}
		else{
			$summary.TotalRecords += $events.Count
            $summary.TotalFiles++
            $summary.SubscriptionsWithData++

			Write-LogFile -Message "[INFO] Found $($events.Count) activity logs in subscription: $subId" -Level Standard
			$events | ConvertTo-Json -Depth 100 | Set-Content -Path $filePath  -encoding $Encoding

			if ($isDebugEnabled) {
                $fileInfo = Get-Item $filePath
                Write-LogFile -Message "[DEBUG] File write completed:" -Level Debug
                Write-LogFile -Message "[DEBUG]   File size: $([Math]::Round($fileInfo.Length / 1KB, 2)) KB" -Level Debug
                Write-LogFile -Message "[DEBUG]   File created: $($fileInfo.CreationTime)" -Level Debug
            }
		}
	}
	$summary.ProcessingTime = (Get-Date) - $summary.StartTime
    $summaryData = [ordered]@{
        "Collection Results" = [ordered]@{
            "Total Records" = $summary.TotalRecords
            "Files Created" = $summary.TotalFiles
        }
        "Subscriptions" = [ordered]@{
            "Total Processed" = $summary.SubscriptionsProcessed
            "With Data" = $summary.SubscriptionsWithData
            "Empty" = $summary.EmptySubscriptions
        }
    }

    Write-Summary -Summary $summaryData -Title "Activity Log Collection Summary"
    Write-LogFile -Message "`nNote: Output files saved to: $(Split-Path $script:outputFile -Parent)" -Level Standard
}
