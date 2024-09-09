function Get-DirectoryActivityLogs {
	<#
    .SYNOPSIS
    Retrieves the Directory Activity logs.

    .DESCRIPTION
    The Get-DirectoryActivityLogs cmdlet collects the Azure Directory Activity logs.
	The output will be written to: Output\AzureAD\$date\$iD-ActivityLog.json

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
	
    .EXAMPLE
    Get-DirectoryActivityLogs
	Get all the Directory Activity logs for the last 90 days.

	.EXAMPLE
    Get-DirectoryActivityLogs -EndDate 2023-04-12
	Get all the Directory Activity before 2023-04-12.

	.EXAMPLE
    Get-DirectoryActivityLogs -StartDate 2023-04-12
	Get all the Directory Activity after 2023-04-12.
#>
	[CmdletBinding()]
	param(
		[string]$StartDate,
		[string]$endDate,
		[string]$output = "CSV",
		[string]$outputDir = "Output\DirectoryActivityLogs",
		[string]$encoding = "UTF8"	
	)
	
	StartDate
	EndDate

	if (!(test-path $outputDir)) {
		New-Item -ItemType Directory -Force -Name $outputDir > $null
		write-logFile -Message "[INFO] Creating the following directory: $outputDir"
	}
	else {
		if (Test-Path -Path $outputDir) {
			write-LogFile -Message "[INFO] Custom directory set to: $outputDir"
		}
	
		else {
			write-Error "[Error] Custom directory invalid: $outputDir exiting script" -ErrorAction Stop
			write-LogFile -Message "[Error] Custom directory invalid: $outputDir exiting script"
		}
	}

    try {
        $currentContext = Get-AzContext
        $azureRmProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
        $profileClient = [Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient]::new($azureRmProfile)
        $token = $profileClient.AcquireAccessToken($currentContext.Tenant.Id)
    }
    catch {
		write-logFile -Message "[INFO] Ensure you are connected to Azure by running the Connect-AzureAz command before executing this script" -Color "Yellow"
		Write-logFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Color "Red"
		throw
	}

    $uriBase = "https://management.azure.com/providers/microsoft.insights/eventtypes/management/values?api-version=2015-04-01&`$filter=eventTimestamp ge '$script:StartDate' and eventTimestamp le '$script:endDate'"
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

    Write-LogFile -Message "[INFO] Done all Directory Activity Logs are collected" -Color "Green"
}

