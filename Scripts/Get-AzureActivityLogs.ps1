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
    Default: Standard
	
    .EXAMPLE
    Get-ActivityLogs
	Get all the activity logs for all subscriptions connected to the logged-in user account for the last 89 days.

	.EXAMPLE
    Get-ActivityLogs -EndDate 2024-04-12
	Get all the activity logs before 2024-04-12.

	.EXAMPLE
    Get-ActivityLogs -StartDate 2024-04-12
	Get all the activity logs after 2024-04-12.
	
	.EXAMPLE
    Get-ActivityLogs -SubscriptionID "4947f939-cf12-4329-960d-4dg68a3eb66f"
	Get all the activity logs for the subscription 4947f939-cf12-4329-960d-4dg68a3eb66f
#>
	[CmdletBinding()]
	param(
		[string]$StartDate,
		[string]$EndDate,
		[string]$SubscriptionID,
		[string]$OutputDir = "Output\ActivityLogs",
		[string]$Encoding = "UTF8",
        [ValidateSet('None', 'Minimal', 'Standard')]
        [string]$LogLevel = 'Standard'		
	)

	Set-LogLevel -Level ([LogLevel]::$LogLevel)
    $summary = @{
        TotalRecords = 0
        TotalFiles = 0
        SubscriptionsProcessed = 0
        SubscriptionsWithData = 0
        EmptySubscriptions = 0
        StartTime = Get-Date
        ProcessingTime = $null
    }

	Write-LogFile -Message "=== Starting Azure Activity Log Collection ===" -Color "Cyan" -Level Minimal

	StartDate -Quiet
    EndDate -Quiet

	Write-LogFile -Message "Start Date: $($script:StartDate.ToString('yyyy-MM-dd HH:mm:ss'))" -Level Standard
	Write-LogFile -Message "End Date: $($script:EndDate.ToString('yyyy-MM-dd HH:mm:ss'))" -Level Standard
    Write-LogFile -Message "Output Directory: $OutputDir" -Level Standard
    Write-LogFile -Message "----------------------------------------`n" -Level Standard

	if (!(test-path $OutputDir)) {
		New-Item -ItemType Directory -Force -Path $OutputDir > $null
	} else {
        if (!(Test-Path -Path $OutputDir)) {
            Write-LogFile -Message "[Error] Custom directory invalid: $OutputDir" -Level Minimal -Color "Red"
            return
        }
    }

	$originalWarningPreference = $WarningPreference
	$WarningPreference = 'SilentlyContinue'

	try {
		$encryptedToken  = (Get-AzAccessToken -ResourceUrl "https://management.azure.com" -AsSecureString).token
		$accessToken = [PSCredential]::new("token", $encryptedToken)
	}
	catch {
		write-logFile -Message "[INFO] Ensure you are connected to Azure by running the Connect-AzureAz command before executing this script" -Color "Yellow" -Level Minimal
		Write-logFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Color "Red" -Level Minimal
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

			$subscriptionsResponse = Invoke-RestMethod -Uri $subscriptionsUri -Headers $headers -Method Get
			$subScription = $subscriptionsResponse.value
		}
		catch {
			write-logFile -Message "[INFO] Ensure you are connected to Azure by running the Connect-AzureAz command before executing this script" -Color "Yellow" -Level Minimal
			Write-logFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Color "Red" -Level Minimal
			throw
		}

		Write-LogFile -Message "[INFO] Found $($subscription.Count) subscriptions" -Level Standard
        foreach ($sub in $subscription) {
            Write-LogFile -Message "  - $($sub.subscriptionId) ($($sub.displayName))" -Level Standard
        }
		Write-LogFile -Message " " -Level Standard
	}
	else {
		try {
			Write-LogFile -Message "[INFO] Processing single subscription: $SubscriptionID" -Level Standard
			$subScription = Get-AzSubscription -SubscriptionId $SubscriptionID
		}
		catch {
			write-logFile -Message "[INFO] Ensure you are connected to Azure by running the Connect-AzureAz command before executing this script" -Color "Yellow" -Level Minimal
			Write-logFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Color "Red" -Level Minimal
			throw
		}
	}

	foreach ($sub in $subScription) {
		$summary.SubscriptionsProcessed++
		$subId = $sub.subscriptionId
		write-logFile -Message "[INFO] Retrieving all Activity Logs for $subId" -Color "Green" -Level Standard

		$date = [datetime]::Now.ToString('yyyyMMddHHmmss') 
		$filePath = "$OutputDir\$($date)-$subId-ActivityLog.json"

		$uriBase = "https://management.azure.com/subscriptions/$subId/providers/Microsoft.Insights/eventtypes/management/values?api-version=2015-04-01&`$filter=eventTimestamp ge '$script:StartDate' and eventTimestamp le '$script:endDate'"
		$events = @()

		do {
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
		} while ($null -ne $uriBase)

		if ($events.Count -eq 0) {
			Write-LogFile -Message "[WARNING] No Activity logs in subscription: $($subId), or an error occurred." -Color Yellow -Level Minimal
			$summary.EmptySubscriptions++
		}
		else{
			$summary.TotalRecords += $events.Count
            $summary.TotalFiles++
            $summary.SubscriptionsWithData++

			Write-LogFile -Message "[INFO] Found $($events.Count) activity logs in subscription: $subId" -Level Standard
			$events | ConvertTo-Json -Depth 100 | Set-Content -Path $filePath  -encoding $Encoding
		}
	}
	$summary.ProcessingTime = (Get-Date) - $summary.StartTime
    Write-LogFile -Message "`n=== Activity Log Collection Summary ===" -Color "Cyan" -Level Standard
    Write-LogFile -Message "  Total Records: $($summary.TotalRecords)" -Level Standard
    Write-LogFile -Message "  Files Created: $($summary.TotalFiles)" -Level Standard
    Write-LogFile -Message "  Subscriptions:" -Level Standard
    Write-LogFile -Message "    - Total Processed: $($summary.SubscriptionsProcessed)" -Level Standard
    Write-LogFile -Message "    - With Data: $($summary.SubscriptionsWithData)" -Level Standard
    Write-LogFile -Message "    - Empty: $($summary.EmptySubscriptions)" -Level Standard
    Write-LogFile -Message "`nOutput Details:" -Level Standard
    Write-LogFile -Message "  Directory: $OutputDir" -Level Standard
    Write-LogFile -Message "  Processing Time: $($summary.ProcessingTime.ToString('mm\:ss'))" -Color "Green" -Level Standard
    Write-LogFile -Message "===================================" -Color "Cyan" -Level Standard
}
