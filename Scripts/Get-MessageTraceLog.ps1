# This contains a function to collect the Message Trace logging.
Function StartDateMTL {
	param([switch]$Quiet)

	if (($startDate -eq "") -Or ($null -eq $startDate))
	{
		$script:StartDate = [datetime]::Now.ToUniversalTime().AddDays(-90)
		if (-not $Quiet) {
			write-LogFile -Message "[INFO] No start date provided by user setting the start date to: $($script:StartDate.ToString("yyyy-MM-ddTHH:mm:ssK"))" -Color "Yellow"
		}
	}
	else {
		$script:StartDate = $startDate -as [datetime]
		if (!$startDate -and -not $Quiet) {
			write-LogFile -Message "[WARNING] Not A valid start date and time, make sure to use YYYY-MM-DD" -Color "Red"
		} 
	}
}

function EndDateMTL {
	param([switch]$Quiet)

	if (($endDate -eq "") -Or ($null -eq $endDate))
	{
		$script:EndDate = [datetime]::Now.ToUniversalTime()
		if (-not $Quiet) {
			write-LogFile -Message "[INFO] No end date provided by user setting the end date to: $($script:EndDate.ToString("yyyy-MM-ddTHH:mm:ssK"))" -Color "Yellow"
		}
	}
	else {
		$script:EndDate = $endDate -as [datetime]
		if (!$endDate -and -not $Quiet) {
			write-LogFile -Message "[WARNING] Not A valid end date and time, make sure to use YYYY-MM-DD" -Color "Red"} 
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

	.PARAMETER LogLevel
    Specifies the level of logging:
    None: No logging
    Minimal: Critical errors only
    Standard: Normal operational logging
	Debug: Verbose logging for debugging purposes
    Default: Standard

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
		[string[]]$UserIds,
		[string]$StartDate,
		[string]$EndDate,
		[string]$OutputDir,
		[string]$Encoding = "UTF8",
        [ValidateSet('None', 'Minimal', 'Standard', 'Debug')]
        [string]$LogLevel = 'Standard'
	)
	
	Init-Logging
	Write-LogFile -Message "=== Starting Message Trace Log Collection ===" -Color "Cyan" -Level Standard
	StartDateMTL -Quiet
	EndDateMTL -Quiet

	$filePostfix = "MessageTrace"
	if ($UserIds) {
		$userString = ($UserIds -join ",").Replace("*@","").Replace("@","-")
		$filePostfix = "MessageTrace-$userString"
	}

    Init-OutputDir -Component "MessageTrace" -FilePostfix $filePostfix -CustomOutputDir $OutputDir
	$OutputDir = Split-Path $script:outputFile -Parent
	
    $summary = @{
        StartTime = Get-Date
        ProcessingTime = $null
    }

	
	if ($isDebugEnabled) {
		Write-LogFile -Message "[DEBUG] Date processing complete:" -Level Debug
		Write-LogFile -Message "[DEBUG]   Processed StartDate: $($script:StartDate)" -Level Debug
		Write-LogFile -Message "[DEBUG]   Processed EndDate: $($script:EndDate)" -Level Debug
		Write-LogFile -Message "[DEBUG]   Date range span: $(($script:EndDate - $script:StartDate).TotalDays) days" -Level Debug
	}	

	if (($null -eq $UserIds) -Or ($UserIds -eq "")) {
        Write-LogFile -Message "[INFO] No users provided. Getting the Message Trace Log for all users between $($script:StartDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK")) and $($script:EndDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK"))" -Color "Yellow" -Level Standard
        Retrieve-MessageTrace -StartDate $script:StartDate -endDate $script:EndDate -OutputFile $script:outputFile 
    } else {
        if($UserIds -match "\*"){
            Write-LogFile -Message "[INFO] An entire domain has been provided, retrieving all messages between $($script:StartDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK")) and $($script:EndDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK"))" -Color "Yellow" -Level Standard
        }
        $users = $UserIds.Split(",")

        $users | foreach {
            $user = $_

			if ($isDebugEnabled) {
                Write-LogFile -Message "[DEBUG] Processing user: '$user'" -Level Debug
                Write-LogFile -Message "[DEBUG] Output file path: '$outputFile'" -Level Debug
            }

            write-logFile -Message "[INFO] Collecting the Message Trace Log for $user between $($script:StartDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK")) and $($script:EndDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK"))" -Level Standard
            $outputFile = "$OutputDir\$($user.Replace('*@',''))-MTL.csv"
            Remove-Item $outputFile -ErrorAction SilentlyContinue

            Retrieve-MessageTrace -StartDate $script:StartDate -endDate $script:EndDate -OutputFile $outputFile -searchParams @{"RecipientAddress" = $user}
            Retrieve-MessageTrace -StartDate $script:StartDate -endDate $script:EndDate -OutputFile $outputFile -searchParams @{"SenderAddress" = $user}

            if (test-path $outputFile) {
                Write-LogFile -Message "[INFO] Output is written to: $outputFile" -Color "Green" -Level Standard
            } else {
                Write-LogFile -Message "[INFO] No message Trace logging found for $($user)" -Color "Yellow" -Level Standard
            }
        }
    }

	$summary.ProcessingTime = (Get-Date) - $summary.StartTime
    $summaryData = [ordered]@{
        "Collection Details" = [ordered]@{
            "Analysis Period" = "$($script:StartDate) to $($script:EndDate)"
            "Users Processed" = if ($UserIds) { ($UserIds -split ",").Count } else { "All Users" }
            "Output Directory" = $OutputDir
        }
    }

    Write-Summary -Summary $summaryData -Title "Message Trace Analysis Summary"
}

function Retrieve-MessageTrace {
# Handle the pagination of the MessageTraceV2 API
    param(
		[DateTime]$startDate,
		[DateTime]$endDate,
		$searchParams = @{},
		[string]$OutputFile
	)

	if ($isDebugEnabled) {
        Write-LogFile -Message "[DEBUG] Retrieve-MessageTrace function called" -Level Debug
        Write-LogFile -Message "[DEBUG]   StartDate: $startDate" -Level Debug
        Write-LogFile -Message "[DEBUG]   EndDate: $endDate" -Level Debug
        Write-LogFile -Message "[DEBUG]   OutputFile: '$OutputFile'" -Level Debug
        Write-LogFile -Message "[DEBUG]   SearchParams: $($searchParams | ConvertTo-Json -Compress)" -Level Debug
    }

	$localSummary = @{
        MessageCount = 0
        SentCount = 0
        ReceivedCount = 0
        StatusCounts = @{}
    }

	$currentEnd = $endDate
    while($currentEnd -gt $startDate){
        $currentStart = $currentEnd.addDays(-10)
        if($currentStart -lt $StartDate) {
            $currentStart = $StartDate
        }

		if ($isDebugEnabled) {
            Write-LogFile -Message "[DEBUG] Processing date chunk:" -Level Debug
            Write-LogFile -Message "[DEBUG]   Current start: $currentStart" -Level Debug
            Write-LogFile -Message "[DEBUG]   Current end: $currentEnd" -Level Debug
            Write-LogFile -Message "[DEBUG]   Chunk span: $(($currentEnd - $currentStart).TotalDays) days" -Level Debug
        }

        $searchParams.ResultSize = 5000
        $searchParams.StartDate = $currentStart
        $searchParams.EndDate = $currentEnd
        $resultCount = 5000
		
        while($resultCount -ge 5000) {
            $results = Get-MessageTraceV2 @searchParams
            $resultCount = $results.Count

            if($results){
                $results | Export-Csv $outputFile -ErrorAction SilentlyContinue -NoTypeInformation -Encoding $Encoding -Append
                Write-LogFile -Message "[INFO] Found $resultCount records between $($results[-1].Received) and $($results[0].Received)"  -Level Standard

                $searchParams.EndDate = $results[-1].Received.ToString("O")
                $searchParams.StartingRecipientAddress = $results[-1].RecipientAddress
            }
        }

        $currentEnd=$currentStart
    }
}