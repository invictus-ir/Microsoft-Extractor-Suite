Function StartDateAzure
{
	if (($startDate -eq "") -Or ($null -eq $startDate)) {
		$startDate = [datetime]::Now.ToUniversalTime().AddDays(-89)
		$startDate = Get-Date $startDate -Format "yyyy-MM-dd HH:mm:ss"
		write-host "[INFO] No start date provived by user setting the start date to: $startDate"
		
		$script:StartDate = Get-Date $startDate -Format "yyyy-MM-dd HH:mm:ss"
	}
	
	else {
		$script:startDate = $startDate -as [datetime]
		if (!$script:startDate ) { 
		write-host  "[WARNING] Not A valid start date and time, make sure to use YYYY-MM-DD" 
		} 
	}
}

function EndDateAzure
{
	if (($endDate -eq "") -Or ($null -eq $endDate)) {
		$endDate = [datetime]::Now.ToUniversalTime()
		$endDate = Get-Date $endDate -Format "yyyy-MM-dd HH:mm:ss"
		write-host  "[INFO] No end date provived by user setting the end date to: $endDate"
		
		$script:endDate = Get-Date $endDate -Format "yyyy-MM-dd HH:mm:ss"
	}

	else {
		$script:endDate = $endDate -as [datetime]
		if (!$endDate) { 
			write-host "[WARNING] Not A valid end date and time, make sure to use YYYY-MM-DD"
		} 
	}
}

function Get-ActivityLogs {
	<#
    .SYNOPSIS
    Retrieves the Activity logs.

    .DESCRIPTION
    The Get-ActivityLogs cmdlet collects the Azure Activity logs.
	The output will be written to: Output\AzureAD\$date\$iD-ActivityLog.json

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
	Default: Output\AzureActivityLogs

	.PARAMETER Encoding
    Encoding is the parameter specifying the encoding of the JSON output file.
	Default: UTF8
	
    .EXAMPLE
    Get-ActivityLogs
	Get all the activity logs for all subscriptions connected to the logged-in user account for the last 89 days.

	.EXAMPLE
    Get-ActivityLogs -EndDate 2023-04-12
	Get all the activity logs before 2023-04-12.

	.EXAMPLE
    Get-ActivityLogs -StartDate 2023-04-12
	Get all the activity logs after 2023-04-12.
	
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
		[string]$Encoding		
	)

	try {
		$areYouConnected = Get-AzActivityLog -ErrorAction stop -WarningAction silentlyContinue
	}
	catch {
		write-logFile -Message "[WARNING] You must call Connect-AzureAZ before running this script" -Color "Red"
		break
	}
	
	StartDateAzure
	EndDateAzure
	
	$date = [datetime]::Now.ToString('yyyyMMddHHmmss')

	if ($Encoding -eq "" ){
		$Encoding = "UTF8"
	}

	if ($OutputDir -eq "" ){
		$OutputDir = "Output\AzureActivityLogs\$date\"
		if (!(test-path $OutputDir)) {
			write-logFile -Message "[INFO] Creating the following directory: $OutputDir"
			New-Item -ItemType Directory -Force -Name $OutputDir | Out-Null
		}
	}

	else{
		write-logFile -Message "[INFO] Output directory set to: $OutputDir" -Color "Green"
	}

	if ($SubscriptionID -eq "") {
		write-logFile -Message "[INFO] Retrieving all subscriptions linked to the logged-in user account" -Color "Green"
		$subScription = Get-AzSubscription
		
		foreach ($i in $subScription) {
			write-logFile -Message "[INFO] Identified Subscription: $i"
		}
	}
	
	else {
		
		$subScription = Get-AzSubscription -SubscriptionId $SubscriptionID
	}
	
	foreach ($sub in $Subscription) {	
		$name = $sub.Name
		$iD = $sub.Id
		
		write-logFile -Message "[INFO] Retrieving all Activity Logs for $sub" -Color "Green"	
		Set-AzContext -Subscription $iD | Out-Null
		
		write-logFile -Message "[INFO] Connected to $iD" -Color "Green"	
		$filePath = "$OutputDir\$iD-ActivityLog.json"
				
		[DateTime]$currentStart = $script:StartDate
		[DateTime]$currentEnd = $script:EndDate		
		
		$totalDays = ($currentEnd - $currentStart).TotalDays

		for ($i = 0; $i -lt $totalDays; $i++) {
			$dagCounter = $currentStart.AddDays($i)
			$formattedDate = $dagCounter.ToString("yyyy-MM-dd")
			
			[DateTime]$start = (Get-Date $formattedDate).Date  
			[DateTime]$end = (Get-Date $formattedDate).Date.AddDays(1).AddSeconds(-1)
			
			$currentStartnew = $start
			$currentEnd = $end
			
			$amountResults = Get-AzActivityLog -StartTime $start -EndTime $end -MaxRecord 1000 -WarningAction SilentlyContinue	
			if ($amountResults.count -gt 0) {
				if ($amountResults.count -gt 1000) {
					while ($currentStartnew -lt $currentEnd) {				
						Write-LogFile -Message "[WARNING] $formattedDate - We have exceeded the maximum allowable number of 100 logs, lowering the time interval.." -Color "Red"
						Write-LogFile -Message "[INFO] $formattedDate - Temporary lowering time interval.." -Color "Yellow"
						
						$tempInterval = 24
						$tempStartDate = $start
						$amountResults = Get-AzActivityLog -StartTime $tempStartDate -EndTime $currentEnd -MaxRecord 1000 -WarningAction SilentlyContinue

						while ($($amountResults.count) -gt 1000) {
							$timeLeft = ($currentEnd - $tempStartDate).TotalHours
							$tempInterval = $timeLeft / 2
							
							$backup = $tempInterval
							$tempStartDate = $tempStartDate.AddHours($tempInterval)
							$amountResults = Get-AzActivityLog -StartTime $tempStartDate -EndTime $currentEnd -MaxRecord 1000 -WarningAction SilentlyContinue
						}
						
						$amountResults = Get-AzActivityLog -StartTime $tempStartDate -EndTime $currentEnd -MaxRecord 1000 -WarningAction SilentlyContinue
						Write-LogFile -Message "[INFO] Successfully retrieved $($amountResults.count) Activity logs between $tempStartDate and $currentEnd" -Color "Green"

						$amountResults | Out-File -FilePath $filePath -Append -Encoding $Encoding
						
						if ($tempStartDate -eq $currentEnd) {
							$timeLeft = ($currentEnd - $start).TotalHours							
							$tempStartDate = $start			
						}
						
						$currentEnd = $tempStartDate
					}
				}
				
				else {
					Write-LogFile -Message "[INFO] Successfully retrieved $($amountResults.count) Activity logs for $formattedDate. Moving on!" -Color "Green"
					Get-AzActivityLog -StartTime $start -EndTime $end -MaxRecord 1000 -WarningAction silentlyContinue | Out-File -FilePath $filePath -Append -Encoding $Encoding
				}					
			}
			
			else {
				Write-LogFile -Message "[INFO] No Activity Logs found on $formattedDate. Moving on!"
			}
		}
		
		Write-LogFile -Message "[INFO] Done all logs are collected for $name" -Color "Green"
	}
}