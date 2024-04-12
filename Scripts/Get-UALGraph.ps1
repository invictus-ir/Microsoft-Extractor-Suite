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

    .PARAMETER Application
    Application is the parameter specifying App-only access (access without a user) for authentication and authorization.
    Default: Delegated access (access on behalf a user)

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
    Get-UALGraph -SearchName Test 
	Gets all the unified audit log entries.
	
	.EXAMPLE
	Get-UALGraph -SearchName Test -UserIds Test@invictus-ir.com
	Gets all the unified audit log entries for the user Test@invictus-ir.com.
	
	.EXAMPLE
	Get-UALGraph -SearchName Scan1GraphAPI -startDate "2024-03-10T09:28:56Z" -endDate "2024-03-20T09:28:56Z" -Service Exchange
    Retrieves audit log data for the specified time range March 10, 2024 to March 20, 2024 and filters the results to include only events related to the Exchange service.
	
	.EXAMPLE
	Get-UALGraph -searchName scan1 -startDate "2024-03-01" -endDate "2024-03-10" -IPAddress 182.74.242.26
	Retrieve audit log data for the specified time range March 1, 2024 to March 10, 2024 and filter the results to include only entries associated with the IP address 182.74.242.26.

#>
    [CmdletBinding()]
    param(
		[Parameter(Mandatory=$true)]$searchName,
        [switch]$Application,
        [string]$OutputDir,
        [string]$Encoding,
        [string]$startDate,
		[string]$endDate,
        [string[]]$RecordType = @(),
        [string]$Keyword = "",
        [string]$Service = "",
        [string[]]$Operations = @(),
        [string[]]$UserIds = @(),
        [string[]]$IPAddress = @()
    )

    if (!($Application.IsPresent)) {
        Connect-MgGraph -Scopes AuditLogsQuery.Read.All -NoWelcome
    }

    try {
        $areYouConnected = Get-MgBetaSecurityAuditLogQuery -ErrorAction stop 
    }
    catch {
        Write-logFile -Message "[WARNING] You must call Connect-MgGraph -Scopes 'AuditLogsQuery.Read.All' before running this script" -Color "Red"
        break
    }

    if ($OutputDir -eq "" ){
		$OutputDir = "Output\UnifiedAuditLog\"
		if (!(test-path $OutputDir)) {
			write-logFile -Message "[INFO] Creating the following directory: $OutputDir"
			New-Item -ItemType Directory -Force -Name $OutputDir | Out-Null
		}
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

    if ($Encoding -eq "" ){
		$Encoding = "UTF8"
	}

	$params =
	@{
        "@odata.type" = "#microsoft.graph.security.auditLogQuery"
        displayName = $searchName
        filterStartDateTime = $script:StartDate
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
	}

	$startScan = New-MgBetaSecurityAuditLogQuery -BodyParameter $params
    write-logFile -Message "[INFO] New Unfied Audit Log Search started with the name: $searchName and Id: $($startScan.Id)" -Color "Green"    
	Start-Sleep -Seconds 10

	do {
		$auditLogQuery = Get-MgBetaSecurityAuditLogQuery -AuditLogQueryId $startScan.Id
        $scanId = $startScan.Id
		
		if ($auditLogQuery.Status -eq "running") {
            write-logFile -Message "[INFO] Unified Audit Log search is stil running. Waiting..."
			Start-Sleep -Seconds 10
		}
		elseif ($auditLogQuery.Status -eq "failed") {
            write-logFile -Message "[INFO] Unified Audit Log search failed." -Color "Red"
			exit 1 
		} 
		elseif ($auditLogQuery.Status -eq "succeeded") {
            write-logFile -Message "[INFO] Unified Audit Log search succeeded." -Color "Green"
            DownloadUAL $scanId $searchName $Encoding $OutputDir
		}
		else {
			write-logFile -Message "[INFO] Unified Audit Log search is stil running. Waiting..."
			Start-Sleep -Seconds 10
		}
	} until ($auditLogQuery.Status -eq "succeeded")	
}

Function DownloadUAL($scanId, $searchName, $Encoding, $OutputDir) {
    $date = Get-Date -Format "yyyyMMddHHmm"
    $outputFilePath = "$($date)-$searchName-UnifiedAuditLog.json"
    $customObjects = @()

    Get-MgBetaSecurityAuditLogQueryRecord -AuditLogQueryId $scanId -All |
        ForEach-Object {	
            $customObject = New-Object PSObject -Property @{
                AdministrativeUnits = $_.AdministrativeUnits
                AuditData = $_ | Select-Object -ExpandProperty AuditData
                AuditLogRecordType = $_.AuditLogRecordType
                ClientIP = $_.ClientIP
                CreatedDateTime = $_.CreatedDateTime
                Id = $_.Id
                ObjectId = $_.ObjectId
                Operation = $_.Operation
                OrganizationId = $_.OrganizationId
                Service = $_.Service
                UserId = $_.UserId
                UserPrincipalName = $_.UserPrincipalName
                UserType = $_.UserType
                AdditionalProperties = $_.AdditionalProperties
            }
            
            $customObjects += $customObject
        } 

        $customObjects | ConvertTo-Json -Depth 100 | Out-File -Append "$OutputDir/$($date)-$searchName-UnifiedAuditLog.json" -Encoding $Encoding

    write-logFile -Message "[INFO] Audit log records have been saved to $outputFilePath" -Color "Green"
    $endTime = Get-Date
    $runtime = $endTime - $script:startTime
    write-logFile -Message "[INFO] Total runtime (HH:MM:SS): $($runtime.Hours):$($runtime.Minutes):$($runtime.Seconds)" -Color "Green"
}



