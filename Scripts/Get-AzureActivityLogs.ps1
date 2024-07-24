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
		[string]$Encoding = "UTF8"		
	)
	
	StartDate
	EndDate

	if (!(test-path $OutputDir)) {
		New-Item -ItemType Directory -Force -Name $OutputDir > $null
		write-logFile -Message "[INFO] Creating the following directory: $OutputDir"
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

	$currentContext = Get-AzContext
	$azureRmProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
	$profileClient = [Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient]::new($azureRmProfile)
	$token = $profileClient.AcquireAccessToken($currentContext.Tenant.Id)

	if ($SubscriptionID -eq "") {
		write-logFile -Message "[INFO] Retrieving all subscriptions linked to the logged-in user account" -Color "Green"

		try {
			$subscriptionsUri = "https://management.azure.com/subscriptions?api-version=2020-01-01"
			$headers = @{
				Authorization = "Bearer $($token.AccessToken)"
				'Content-Type' = 'application/json'
			}

			$subscriptionsResponse = Invoke-RestMethod -Uri $subscriptionsUri -Headers $headers -Method Get
			$subScription = $subscriptionsResponse.value
		}
		catch {
			write-logFile -Message "[INFO] Ensure you are connected to Azure by running the Connect-AzureAz command before executing this script" -Color "Yellow"
			Write-logFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Color "Red"
			throw
		}
		
		foreach ($i in $subScription) {
			$subId = $i.subscriptionId
			write-logFile -Message "[INFO] Identified Subscription: $subId"
		}
	}
	else {
		try {
			$subScription = Get-AzSubscription -SubscriptionId $SubscriptionID
		}
		catch {
			write-logFile -Message "[INFO] Ensure you are connected to Azure by running the Connect-AzureAz command before executing this script" -Color "Yellow"
			Write-logFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Color "Red"
			throw
		}
	}

	foreach ($sub in $subScription) {
		$subId = $sub.subscriptionId
		write-logFile -Message "[INFO] Retrieving all Activity Logs for $subId" -Color "Green"	

		$date = [datetime]::Now.ToString('yyyyMMddHHmmss') 
		$filePath = "$OutputDir\$($date)-$subId-ActivityLog.json"

		$uriBase = "https://management.azure.com/subscriptions/$subId/providers/Microsoft.Insights/eventtypes/management/values?api-version=2015-04-01&`$filter=eventTimestamp ge '$script:StartDate' and eventTimestamp le '$script:endDate'"
		$events = @()

		do {
			$listOperations = @{
				Uri     = $uriBase
				Headers = @{
					Authorization  = "Bearer $($token.AccessToken)"
					'Content-Type' = 'application/json'
				}
				Method  = 'GET'
			}

			$response = Invoke-RestMethod @listOperations
			$events += $response.value
			$uriBase = $response.nextLink
		} while ($null -ne $uriBase)

		if ($events.Count -eq 0) {
			Write-LogFile -Message "[WARNING] No Activity logs in subscription: $($subId), or an error occurred." -ForegroundColor Yellow
		}
		else{
			$eventCount = $events.Count
			Write-LogFile -Message "[INFO] $eventCount Activity logs found in subscription: $subId" -ForegroundColor Green
			$events | ConvertTo-Json -Depth 100 | Set-Content -Path $filePath  -encoding $Encoding
		}
	}
	Write-LogFile -Message "[INFO] Done all Activity Logs are collected" -Color "Green"
}
