# This contains a function to collect the Message Trace logging.
Function StartDateMTL
{
	if (($startDate -eq "") -Or ($null -eq $startDate))
	{
		$script:StartDate = [datetime]::Now.ToUniversalTime().AddDays(-10)
		write-LogFile -Message "[INFO] No start date provided by user setting the start date to: $($script:StartDate.ToString("yyyy-MM-ddTHH:mm:ssK"))" -Color "Yellow"
	}
	else
	{
		$script:StartDate = $startDate -as [datetime]
		if (!$startDate) { write-LogFile -Message "[WARNING] Not A valid start date and time, make sure to use YYYY-MM-DD" -Color "Red"} 
	}
}

function EndDateMTL
{
	if (($endDate -eq "") -Or ($null -eq $endDate))
	{
		$script:EndDate = [datetime]::Now.ToUniversalTime()
		write-LogFile -Message "[INFO] No end date provided by user setting the end date to: $($script:EndDate.ToString("yyyy-MM-ddTHH:mm:ssK"))" -Color "Yellow"
	}
	else
	{
		$script:EndDate = $endDate -as [datetime]
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
    UserIds is the UserIds parameter filtering the log entries by the account of the user who performed the actions.

	.PARAMETER StartDate
    startDate is the parameter specifying the start date of the date range.
	Default: Today 10 days

	.PARAMETER EndDate
    endDate is the parameter specifying the end date of the date range.
	Default: Now

	.PARAMETER OutputDir
    outputDir is the parameter specifying the output directory.
	Default: Output\MessageTrace

	.PARAMETER Encoding
    Encoding is the parameter specifying the encoding of the CSV output file.
	Default: UTF8

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
		[string]$EndDate,
		[string]$OutputDir = "Output\MessageTrace",
		[string]$Encoding = "UTF8"
	)

	try {
		$areYouConnected = Get-MessageTrace -ErrorAction stop
	}
	catch {
		write-logFile -Message "[INFO] Ensure you are connected to M365 by running the Connect-M365 command before executing this script" -Color "Yellow"
		Write-logFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Color "Red"
		break
	}
		
	write-logFile -Message "[INFO] Running Get-MessageTraceLog" -Color "Green"

	StartDateMTL
	EndDateMTL
	
	$date = Get-Date -Format "yyyyMMddHHmm"

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

	if (($null -eq $UserIds) -Or ($UserIds -eq ""))  {
		write-logFile -Message "[INFO] No users provided. Getting the Message Trace Log for all users between $($script:StartDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK")) and $($script:EndDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK"))" -Color "Yellow"
		Get-mailbox -resultsize unlimited |
		ForEach-Object {
			$outputFile = "$OutputDir\"+$($_.PrimarySmtpAddress)+"-MTL.csv"

			$ResultsRecipient = Get-MessageTrace -RecipientAddress $_.PrimarySmtpAddress -StartDate $script:startDate -EndDate $script:endDate -PageSize 5000
			$ResultsSender = Get-MessageTrace -SenderAddress $_.PrimarySmtpAddress -StartDate $script:startDate -EndDate $script:endDate -PageSize 5000
			
			$results = $resultsSender + $resultsRecipient
			if ($results){
				write-logFile -Message "[INFO] Collecting the Message Trace Log for $($_.PrimarySmtpAddress)"
				$results | Export-Csv $outputFile -ErrorAction SilentlyContinue -NoTypeInformation
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
			
			write-logFile -Message "[INFO] Collecting the Message Trace Log for $user between $($script:StartDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK")) and $($script:EndDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK"))"
			$outputFile = "$OutputDir\"+$user+"-MTL.csv"

			$ResultsRecipient = Get-MessageTrace -RecipientAddress $user -StartDate $script:startDate -EndDate $script:endDate -PageSize 5000
			$ResultsSender = Get-MessageTrace -SenderAddress $user -StartDate $script:startDate -EndDate $script:endDate -PageSize 5000

			$results = $resultsSender + $resultsRecipient
			$results | Export-Csv $outputFile -ErrorAction SilentlyContinue -NoTypeInformation -Encoding $Encoding
			write-logFile -Message "[INFO] Output is written to: $outputFile" -Color "Green"
		}
	}

	elseif ($UserIds -match "\*") {	
		write-logFile -Message "[INFO] An entire domain has been provided, retrieving all messages between $($script:StartDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK")) and $($script:EndDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK"))" -Color "Yellow"
		write-logFile -Message "[WARNING] Please be aware that the output is restricted to a maximum of 5000 received and 5000 sent emails in the results" -Color "Red"

		$Domain = $UserIds.Replace("*@","")
		$outputFile = "$OutputDir\$Domain-MTL.csv"
		
		$ResultsRecipient = Get-MessageTrace -RecipientAddress $UserIds -StartDate $script:startDate -EndDate $script:endDate -PageSize 5000
		$ResultsSender = Get-MessageTrace -SenderAddress $UserIds -StartDate $script:startDate -EndDate $script:endDate -PageSize 5000
		
		$results = $resultsSender + $resultsRecipient

		$results | Export-Csv $outputFile -ErrorAction SilentlyContinue -NoTypeInformation -Encoding $Encoding
		write-logFile -Message "[INFO] Output is written to: $outputFile" -Color "Green"

	}
	
	else {
		$outputFile = "$OutputDir\"+$UserIds+"-MTL.csv"
		write-logFile -Message "[INFO] Collecting the Message Trace Log for $UserIds"

		$resultsRecipient = Get-MessageTrace -RecipientAddress $UserIds -StartDate $script:startDate -EndDate $script:endDate -PageSize 5000
		$resultsSender = Get-MessageTrace -SenderAddress $UserIds -StartDate $script:startDate -EndDate $script:endDate -PageSize 5000

		$results = $resultsSender + $resultsRecipient
		$results | Export-Csv $outputFile -ErrorAction SilentlyContinue -NoTypeInformation -Encoding $Encoding
		write-logFile -Message "[INFO] Output is written to: $outputFile" -Color "Green"
	}	
}