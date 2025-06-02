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
    Debug: Verbose logging for debugging purposes
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
        [ValidateSet('None', 'Minimal', 'Standard', 'Debug')]
        [string]$LogLevel = 'Standard'	
	)

    Set-LogLevel -Level ([LogLevel]::$LogLevel)
    $isDebugEnabled = $script:LogLevel -eq [LogLevel]::Debug

    Write-LogFile -Message "=== Starting Directory Activity Log Analysis ===" -Color "Cyan" -Level Minimal

    if ($isDebugEnabled) {
        Write-LogFile -Message "[DEBUG] PowerShell Version: $($PSVersionTable.PSVersion)" -Level Debug
        Write-LogFile -Message "[DEBUG] Input parameters:" -Level Debug
        Write-LogFile -Message "[DEBUG]   StartDate: $StartDate" -Level Debug
        Write-LogFile -Message "[DEBUG]   EndDate: $endDate" -Level Debug
        Write-LogFile -Message "[DEBUG]   Output: $output" -Level Debug
        Write-LogFile -Message "[DEBUG]   OutputDir: $outputDir" -Level Debug
        Write-LogFile -Message "[DEBUG]   Encoding: $encoding" -Level Debug
        Write-LogFile -Message "[DEBUG]   LogLevel: $LogLevel" -Level Debug
        
        $azModule = Get-Module -Name Az* -ErrorAction SilentlyContinue
        if ($azModule) {
            Write-LogFile -Message "[DEBUG] Azure Modules loaded:" -Level Debug
            foreach ($module in $azModule) {
                Write-LogFile -Message "[DEBUG]   - $($module.Name) v$($module.Version)" -Level Debug
            }
        } else {
            Write-LogFile -Message "[DEBUG] No Azure modules loaded" -Level Debug
        }
    }
	
	StartDate -Quiet
    EndDate -Quiet

    Write-LogFile -Message "Start Date: $($summary.DateRange)$($script:StartDate.ToString('yyyy-MM-dd HH:mm:ss'))" -Level Standard
    Write-LogFile -Message "End Date: $($script:EndDate.ToString('yyyy-MM-dd HH:mm:ss'))" -Level Standard
    Write-LogFile -Message "Output Directory: $OutputDir" -Level Standard
    Write-LogFile -Message "----------------------------------------`n" -Level Standard

	if (!(test-path $outputDir)) {
        New-Item -ItemType Directory -Force -Path $outputDir > $null
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

        if ($isDebugEnabled) {
            Write-LogFile -Message "[DEBUG] Azure access token acquired successfully" -Level Debug
            
            try {
                $azContext = Get-AzContext
                if ($azContext) {
                    Write-LogFile -Message "[DEBUG] Azure context information:" -Level Debug
                    Write-LogFile -Message "[DEBUG]   Account: $($azContext.Account.Id)" -Level Debug
                    Write-LogFile -Message "[DEBUG]   Environment: $($azContext.Environment.Name)" -Level Debug
                    Write-LogFile -Message "[DEBUG]   Tenant: $($azContext.Tenant.Id)" -Level Debug
                    Write-LogFile -Message "[DEBUG]   Subscription: $($azContext.Subscription.Name)" -Level Debug
                }
            } catch {
                Write-LogFile -Message "[DEBUG] Could not retrieve Azure context details" -Level Debug
            }
        }
	}
	catch {
		write-logFile -Message "[INFO] Ensure you are connected to Azure by running the Connect-AzureAz command before executing this script" -Color "Yellow" -Level Minimal
		Write-logFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Color "Red" -Level Minimal
        if ($isDebugEnabled) {
            Write-LogFile -Message "[DEBUG] Token acquisition error details:" -Level Debug
            Write-LogFile -Message "[DEBUG]   Exception type: $($_.Exception.GetType().Name)" -Level Debug
            Write-LogFile -Message "[DEBUG]   Full error: $($_.Exception.ToString())" -Level Debug
            Write-LogFile -Message "[DEBUG]   Stack trace: $($_.ScriptStackTrace)" -Level Debug
        }
		throw
	}

    Write-LogFile -Message "[INFO] Retrieving Directory Activity logs..." -Level Standard
    $uriBase = "https://management.azure.com/providers/microsoft.insights/eventtypes/management/values?api-version=2015-04-01&`$filter=eventTimestamp ge '$script:StartDate' and eventTimestamp le '$script:endDate'"
    $events = @()

    if ($isDebugEnabled) {
        Write-LogFile -Message "[DEBUG] API configuration:" -Level Debug
        Write-LogFile -Message "[DEBUG]   Base URL: https://management.azure.com/providers/microsoft.insights/eventtypes/management/values" -Level Debug
        Write-LogFile -Message "[DEBUG]   API Version: 2015-04-01" -Level Debug
        Write-LogFile -Message "[DEBUG]   Filter: eventTimestamp ge '$script:StartDate' and eventTimestamp le '$script:endDate'" -Level Debug
        Write-LogFile -Message "[DEBUG]   Full URI: $uriBase" -Level Debug
    }

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
        $processedEvents | Export-Csv -Path "$OutputDir/$($date)-DirectoryActivityLogs.csv" -NoTypeInformation -Encoding $Encoding
    }

    Write-LogFile -Message "[INFO] Done all Directory Activity Logs are collected" -Color "Green" -Level Standard
}

