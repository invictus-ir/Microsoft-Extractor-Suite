Function Get-UALGraph {
<#
    .SYNOPSIS
    Gets all the unified audit log entries.

    .DESCRIPTION
    Makes it possible to extract all unified audit data out of a Microsoft 365 environment. 
	The output will be written to: Output\UnifiedAuditLog\

	.PARAMETER UserIds
    UserIds is the UserIds parameter filtering the log entries by the account of the user who performed the actions.

	.PARAMETER StartDate
    startDate is the parameter specifying the start date of the date range.
	Default: Today -90 days

	.PARAMETER EndDate
    endDate is the parameter specifying the end date of the date range.
	Default: Now

	.PARAMETER OutputDir
	OutputDir is the parameter specifying the output directory.
	Default: Output\UnifiedAuditLog

	.PARAMETER Encoding
    Encoding is the parameter specifying the encoding of the CSV/JSON output file.
	Default: UTF8

    .PARAMETER RecordType
    The RecordType parameter filters the log entries by record type.
	Options are: ExchangeItem, ExchangeAdmin, etc. A total of 236 RecordTypes are supported.

    .PARAMETER Keyword
    The Keyword parameter allows you to filter the Unified Audit Log for specific keywords.

    .PARAMETER Service
    The Service parameter filters the Unified Audit Log based on the specific services.
    Options are: Exchange,Skype,Sharepoint etc.

    .PARAMETER Operations
    The Operations parameter filters the log entries by operation or activity type. Usage: -Operations UserLoggedIn,MailItemsAccessed
	Options are: New-MailboxRule, MailItemsAccessed, etc.

    .PARAMETER IPAddress
    The IP address parameter is used to filter the logs by specifying the desired IP address.
	
	.PARAMETER SearchName
    Specifies the name of the search query. This parameter is required.
    
    .EXAMPLE
    Get-UALGraph -searchName Test 
	Gets all the unified audit log entries.
	
	.EXAMPLE
	Get-UALGraph -searchName Test -UserIds Test@invictus-ir.com
	Gets all the unified audit log entries for the user Test@invictus-ir.com.
	
	.EXAMPLE
	Get-UALGraph -searchName Test -startDate "2024-03-10T09:28:56Z" -endDate "2024-03-20T09:28:56Z" -Service Exchange
    Retrieves audit log data for the specified time range March 10, 2024 to March 20, 2024 and filters the results to include only events related to the Exchange service.
	
	.EXAMPLE
	Get-UALGraph -searchName Test -startDate "2024-03-01" -endDate "2024-03-10" -IPAddress 182.74.242.26
	Retrieve audit log data for the specified time range March 1, 2024 to March 10, 2024 and filter the results to include only entries associated with the IP address 182.74.242.26.

#>
    [CmdletBinding()]
    param(
		[Parameter(Mandatory=$true)]$searchName,
        [string]$OutputDir = "Output\UnifiedAuditLog\",
        [string]$Encoding = "UTF8",
        [string]$startDate,
		[string]$endDate,
        [string[]]$RecordType = @(),
        [string]$Keyword = "",
        [string]$Service = "",
        [string[]]$Operations = @(),
        [string[]]$UserIds = @(),
        [string[]]$IPAddress = @()
    )

    $authType = Get-GraphAuthType
    if ($authType -eq "Delegated") {
        Connect-MgGraph -Scopes AuditLogsQuery.Read.All > $null
    }

	if (!(test-path $OutputDir)) {
		write-logFile -Message "[INFO] Creating the following directory: $OutputDir"
		New-Item -ItemType Directory -Force -Name $OutputDir > $null
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

    $script:startTime = Get-Date

    StartDate
	EndDate

    write-logFile -Message "[INFO] Running Get-UALGraph" -Color "Green"

	$body = @{
        "@odata.type" = "#microsoft.graph.security.auditLogQuery"
        displayName = $searchName
        filterStartDateTime = $script:startDate
        filterEndDateTime = $script:endDate
        recordTypeFilters = $RecordType
        keywordFilter = $Keyword
        serviceFilter = $Service
        operationFilters = $Operations
        userPrincipalNameFilters = $UserIds
        ipAddressFilters = $IPAddress
        objectIdFilters = @()
        administrativeUnitIdFilters = @()
        status = ""
    } | ConvertTo-Json

    try {
        $response = Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/beta/security/auditLog/queries" -Body $body -ContentType "application/json"
        $scanId = $response.id
        write-logFile -Message "[INFO] A new Unified Audit Log search has started with the name: $searchName and ID: $scanId." -Color "Green"    

        Start-Sleep -Seconds 10
        $apiUrl = "https://graph.microsoft.com/beta/security/auditLog/queries/$scanId"

        write-logFile -Message "[INFO] Waiting for the scan to start..."
        $lastStatus = ""
        do {
            $response = Invoke-MgGraphRequest -Method Get -Uri $apiUrl -ContentType 'application/json'
            $status = $response.status
            if ($status -ne $lastStatus) {
                $lastStatus = $status
            }
            Start-Sleep -Seconds 5
        } while ($status -ne "succeeded" -and $status -ne "running")
        if ($status -eq "running") {
            write-logFile -Message "[INFO] Unified Audit Log search has started... This can take a while..."
            do {
                $response = Invoke-MgGraphRequest -Method Get -Uri $apiUrl -ContentType 'application/json'
                $status = $response.status
                if ($status -ne $lastStatus) {
                    write-logFile -Message "[INFO] Unified Audit Log search is still running. Waiting..."
                    $lastStatus = $status
                }
                Start-Sleep -Seconds 5
            } while ($status -ne "succeeded")
        }
       write-logFile -Message "[INFO] Unified Audit Log search complete."
    }
    catch {
        write-logFile -Message "[INFO] Ensure you are connected to Microsoft Graph by running the Connect-MgGraph -Scopes 'AuditLogsQuery.Read.All' command before executing this script" -Color "Yellow"
        Write-logFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Color "Red"
        break
    }

    try {
    	write-logFile -Message "[INFO] Collecting scan results from api (this may take a while)"
        $date = [datetime]::Now.ToString('yyyyMMddHHmmss')
        $inc = 1 
        $apiUrl = "https://graph.microsoft.com/beta/security/auditLog/queries/$scanId/records"
        $ProgressPreference = 'SilentlyContinue'
        
        Do {
            $outputFilePath = "$($date)-$searchName-UnifiedAuditLog-$($inc).json"
            $filePath = Join-Path -Path $OutputDir -ChildPath $outputFilePath
            $response = invoke-MgGraphRequest -Method Get -Uri $apiUrl -ContentType 'application/json' -OutputFilePath $filepath -PassThru
            $apiUrl = $response.'@odata.nextLink'
            $inc ++
        } While ($apiUrl)
        
        write-logFile -Message "[INFO] Audit log records have been saved to $outputFilePath" -Color "Green"
        $endTime = Get-Date
        $runtime = $endTime - $script:startTime
        write-logFile -Message "[INFO] Total runtime (HH:MM:SS): $($runtime.Hours):$($runtime.Minutes):$($runtime.Seconds)" -Color "Green"
    }
    catch {
        Write-logFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Color "Red"
        break
    }
}



