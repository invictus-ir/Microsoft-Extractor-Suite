# This contains a function to collect the Message Trace logging.
Function StartDateMTL
{
	if (($startDate -eq "") -Or ($null -eq $startDate))
	{
		$startDate = [datetime]::Now.ToUniversalTime().AddDays(-10)
		$startDate = Get-Date $startDate -Format "yyyy-MM-dd HH:mm:ss"
		write-LogFile -Message "[INFO] No start date provived by user setting the start date to: $startDate" -Color "Yellow"
		
		$script:startDate = Get-Date $startDate -Format "yyyy-MM-dd HH:mm:ss"
	}
	else
	{
		$script:startDate = $startDate -as [datetime]
		if (!$startDate) { write-LogFile -Message "[WARNING] Not A valid start date and time, make sure to use YYYY-MM-DD" -Color "Red"} 
	}
}

function EndDateMTL
{
	if (($endDate -eq "") -Or ($null -eq $endDate))
	{
		$endDate = [datetime]::Now.ToUniversalTime()
		$endDate = Get-Date $endDate -Format "yyyy-MM-dd HH:mm:ss"
		write-LogFile -Message "[INFO] No end date provived by user setting the end date to: $endDate" -Color "Yellow"
		
		$script:endDate = Get-Date $endDate -Format "yyyy-MM-dd HH:mm:ss"
	}
	else
	{
		$script:endDate = $endDate -as [datetime]
		if (!$endDate) {write-LogFile -Message "[WARNING] Not A valid end date and time, make sure to use YYYY-MM-DD" -Color "Red"} 
	}
}

function Get-MessageTraceLog
{
<#
    .SYNOPSIS
	Collects the trace messages as they pass through the cloud-based organization.

    .DESCRIPTION
    Collects the trace messages as they pass through the cloud-based organization.
	Only 10 days of history is available. Output is saved in: Output\MessageTrace\
	
	.PARAMETER UserIds
    UserIds is the Identity parameter specifies the Inbox rule that you want to view.

	.PARAMETER StartDate
    startDate is the parameter specifying the start date of the date range.
	Default: Today 10 days

	.PARAMETER EndDate
    endDate is the parameter specifying the end date of the date range.
	Default: Now

	.EXAMPLE
    Get-MessageTraceLog
	Collects the trace messages for all users.
    
    .EXAMPLE
    Get-MessageTraceLog -UserIds HR@invictus-ir.com
	Collects the trace messages for the user HR@invictus-ir.com.

	.EXAMPLE
    Get-MessageTraceLog -UserIds "Test@invictus-ir.com,HR@invictus-ir.com"
	Collects the trace messages for the users Test@invictus-ir.com and HR@invictus-ir.com.

	.EXAMPLE
	Get-MessageTraceLog -UserIds "*@invictus-ir.com"
	Collects the trace messages for the full @invictus-ir.com domain.

	.EXAMPLE
	Get-MessageTraceLog -UserIds Test@invictus-ir.com -StartDate 1/4/2023 -EndDate 5/4/2023
	Gets the trace messages for the user Test@invictus-ir.com between 1/4/2023 and 5/4/2023.
#>
	[CmdletBinding()]
	param(
		[string]$UserIds,
		[string]$StartDate,
		[string]$EndDate
	)

	try {
		$areYouConnected = Get-MessageTrace -ErrorAction stop
	}
	catch {
		write-logFile -Message "[WARNING] You must call Connect-M365 before running this script" -Color "Red"
		break
	}
		
	write-logFile -Message "[INFO] Running Get-MessageTraceLog" -Color "Green"

	StartDateMTL
	EndDateMTL
	
	$date = Get-Date -Format "yyyyMMddHHmm"
	$outputDir = "Output\MessageTrace\"	
	if (!(test-path $outputDir)) {
		write-logFile -Message "[INFO] Creating the following directory: $outputDir"
		New-Item -ItemType Directory -Force -Name $outputDir | Out-Null
	}
	
	if (($null -eq $UserIds) -Or ($UserIds -eq ""))  {
		write-logFile -Message "[INFO] No users provided.. Getting the Message Trace Log for all users" -Color "Yellow"
		Get-mailbox -resultsize unlimited  |
		ForEach-Object {
			$outputFile = "Output\MessageTrace\"+$($_.PrimarySmtpAddress)+"-MTL.csv"

			$ResultsRecipient = Get-MessageTrace -RecipientAddress $_.PrimarySmtpAddress -StartDate $script:startDate -EndDate $script:endDate -PageSize 5000
			$ResultsSender = Get-MessageTrace -SenderAddress $_.PrimarySmtpAddress -StartDate $script:startDate -EndDate $script:endDate -PageSize 5000
			
			$results = $resultsSender + $resultsRecipient
			if ($results){
				write-logFile -Message "[INFO] Collecting the Message Trace Log for $($_.PrimarySmtpAddress)"
				$results | Export-Csv $outputFile -ErrorAction SilentlyContinue
				write-logFile -Message "[INFO] Output is written to: $outputFile" -Color "Green"
			}
			else {
				write-logFile -Message "[INFO] No message Trace logging found for $($_.PrimarySmtpAddress)" -Color "Yellow"
			}
		}
	}

	elseif ($UserIds -match ",") {			
		$UserIds.Split(",") | foreach {
			$user = $_
			
			write-logFile -Message "[INFO] Collecting the Message Trace Log for $user"
			$outputFile = "Output\MessageTrace\"+$user+"-MTL.csv"

			$ResultsRecipient = Get-MessageTrace -RecipientAddress $user -StartDate $script:startDate -EndDate $script:endDate -PageSize 5000
			$ResultsSender = Get-MessageTrace -SenderAddress $user -StartDate $script:startDate -EndDate $script:endDate -PageSize 5000

			$results = $resultsSender + $resultsRecipient
			$results | Export-Csv $outputFile -ErrorAction SilentlyContinue
			write-logFile -Message "[INFO] Output is written to: $outputFile" -Color "Green"
		}
	}
	
	else {
		$outputFile = "Output\MessageTrace\"+$UserIds+"-MTL.csv"
		write-logFile -Message "[INFO] Collecting the Message Trace Log for $UserIds"

		$resultsRecipient = Get-MessageTrace -RecipientAddress $UserIds -StartDate $script:startDate -EndDate $script:endDate -PageSize 5000
		$resultsSender = Get-MessageTrace -SenderAddress $UserIds -StartDate $script:startDate -EndDate $script:endDate -PageSize 5000

		$results = $resultsSender + $resultsRecipient
		$results | Export-Csv $outputFile -ErrorAction SilentlyContinue
		write-logFile -Message "[INFO] Output is written to: $outputFile" -Color "Green"
	}	
}