function Get-DirectoryActivityLogs {
	<#
    .SYNOPSIS
    Retrieves the Directory Activity logs.

    .DESCRIPTION
    The Get-DirectoryActivityLogs cmdlet collects the Azure Directory Activity logs.
	The output will be written to: Output\EntraID\$date\$iD-ActivityLog.json

	.PARAMETER StartDate
    startDate is the parameter specifying the start date of the date range.
	Default: Today -90 days

	.PARAMETER EndDate
    endDate is the parameter specifying the end date of the date range.
	Default: Now

	.PARAMETER OutputDir
    OutputDir is the parameter specifying the output directory.
	Default: Output\DirectoryActivityLogs

	.PARAMETER Encoding
    Encoding is the parameter specifying the encoding of the JSON output file.
	Default: UTF8

    .PARAMETER Output
    Output is the parameter specifying the CSV or JSON output type.
	Default: CSV

    .PARAMETER LogLevel
    Specifies the level of logging:
    None: No logging
    Minimal: Critical errors only
    Standard: Normal operational logging
    Default: Standard
	
    .EXAMPLE
    Get-DirectoryActivityLogs
	Get all the Directory Activity logs for the last 90 days.

	.EXAMPLE
    Get-DirectoryActivityLogs -EndDate 2024-04-12
	Get all the Directory Activity before 2024-04-12.

	.EXAMPLE
    Get-DirectoryActivityLogs -StartDate 2024-04-12
	Get all the Directory Activity after 2024-04-12.
#>
	[CmdletBinding()]
	param(
		[string]$StartDate,
		[string]$endDate,
		[string]$output = "CSV",
		[string]$outputDir = "Output\DirectoryActivityLogs",
		[string]$encoding = "UTF8",
        [ValidateSet('None', 'Minimal', 'Standard')]
        [string]$LogLevel = 'Standard'	
	)

    Write-LogFile -Message "=== Starting Directory Activity Log Analysis ===" -Color "Cyan" -Level Minimal
	
	StartDate -Quiet
    EndDate -Quiet

    Write-LogFile -Message "Start Date: $($summary.DateRange)$($script:StartDate.ToString('yyyy-MM-dd HH:mm:ss'))" -Level Standard
    Write-LogFile -Message "End Date: $($script:EndDate.ToString('yyyy-MM-dd HH:mm:ss'))" -Level Standard
    Write-LogFile -Message "Output Directory: $OutputDir" -Level Standard
    Write-LogFile -Message "----------------------------------------`n" -Level Standard

	if (!(test-path $outputDir)) {
		New-Item -ItemType Directory -Force -Name $outputDir > $null
	}
	else {
        if (!(Test-Path -Path $OutputDir)) {
            Write-LogFile -Message "[Error] Custom directory invalid: $OutputDir" -Level Minimal -Color "Red"
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

    Write-LogFile -Message "[INFO] Retrieving Directory Activity logs..." -Level Standard
    $uriBase = "https://management.azure.com/providers/microsoft.insights/eventtypes/management/values?api-version=2015-04-01&`$filter=eventTimestamp ge '$script:StartDate' and eventTimestamp le '$script:endDate'"
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

    $processedEvents = $events | ForEach-Object {
        $eventProps = @{}
        foreach ($prop in $_.PSObject.Properties) {
            $eventProps[$prop.Name] = $prop.Value
        }
        [PSCustomObject]$eventProps
    }

    $date = [datetime]::Now.ToString('yyyyMMddHHmmss')
    if ($output -eq "JSON") {
        $processedEvents | ConvertTo-Json -Depth 100 | Set-Content -Path "$OutputDir/$($date)-DirectoryActivityLogs.JSON"   
    }

    elseif ($output -eq "CSV") {
        $processedEvents | Export-Csv -Path "$OutputDir/$($date)-DirectoryActivityLogs.csv" -NoTypeInformation
    }

    Write-LogFile -Message "[INFO] Done all Directory Activity Logs are collected" -Color "Green" -Level Standard
}

