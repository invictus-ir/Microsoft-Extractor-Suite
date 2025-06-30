function Get-MailboxAuditLog
{
<#
    .SYNOPSIS
    Get mailbox audit log entries.

    .DESCRIPTION
    Get mailbox audit log entries for all or a specific user account. 
	The output will be written to: Output\MailboxAuditLog\

	.PARAMETER UserIds
    UserIds is the Identity parameter specifying a single mailbox or multiple mailboxes to retrieve mailbox audit log entries from.

	.PARAMETER StartDate
    startDate is the parameter specifying the start date of the date range.

	.PARAMETER EndDate
    endDate is the parameter specifying the end date of the date range.

	.PARAMETER OutputDir
    outputDir is the parameter specifying the output directory.
	Default: Output\MailboxAuditLog

	.PARAMETER Encoding
    Encoding is the parameter specifying the encoding of the CSV output file.
	Default: UTF8

    .PARAMETER MergeOutput
    MergeOutput is the parameter specifying if you wish to merge CSV outputs to a single file.

    .PARAMETER Output
    Output is the parameter specifying the CSV, JSON, or SOF-ELK output type. The SOF-ELK output can be imported into the platform of the same name.
	Default: CSV

	.PARAMETER LogLevel
    Specifies the level of logging:
    None: No logging
    Minimal: Critical errors only
    Standard: Normal operational logging
    Default: Standard
    
	.EXAMPLE
    Get-MailboxAuditLog
	Get all available mailbox audit log entries for all user accounts

    .EXAMPLE
    Get-MailboxAuditLog -UserIds Test@invictus-ir.com
	Get mailbox audit log entries for the user Test@invictus-ir.com

	.EXAMPLE
    Get-MailboxAuditLog -UserIds "Test@invictus-ir.com,HR@invictus-ir.com"
	Get mailbox audit log entries for the users Test@invictus-ir.com and HR@invictus-ir.com.

	.EXAMPLE
	Get-MailboxAuditLog -UserIds Test@invictus-ir.com -StartDate 1/4/2024 -EndDate 5/4/2024
	Get mailbox audit log entries for the user Test@invictus-ir.com between 1/4/2024 and 5/4/2024.
#>
    [CmdletBinding()]
    param(
        [string]$UserIds = "*",
        [string]$StartDate,
        [string]$EndDate,
        [decimal]$Interval,
        [string]$OutputDir = "Output\MailboxAuditLog",
        [ValidateSet("CSV", "JSON", "SOF-ELK")]
        [string]$Output = "CSV",
        [switch]$MergeOutput,
        [string]$Encoding = "UTF8",
        [ValidateSet('None', 'Minimal', 'Standard', 'Debug')]
        [string]$LogLevel = 'Standard'
    )

    Set-LogLevel -Level ([LogLevel]::$LogLevel)
    $isDebugEnabled = $script:LogLevel -eq [LogLevel]::Debug

    Write-LogFile -Message "== Starting the Mailbox Audit Log Collection (utilizing Get-UAL) ==" -Level Standard

    $date = [datetime]::Now.ToString('yyyyMMddHHmmss')
    if ($OutputDir -eq "Output\MailboxAuditLog") {
        $OutputDir = "Output\MailboxAuditLog\$date"
    }

    if (!(Test-Path -Path $OutputDir)) {
        try {
            New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
        }
        catch {
            Write-LogFile -Message "[Error] Failed to create directory: $OutputDir" -Level Minimal -Color "Red"
            Write-Error "[Error] Failed to create directory: $OutputDir"
            return
        }
    }

    $params = @{
        RecordType = "ExchangeItem"
        UserIds = $UserIds
        Output = $Output
        OutputDir = $OutputDir
        LogLevel = $LogLevel
        Encoding = $Encoding
    }

    if ($PSBoundParameters.ContainsKey('Interval')) {
        $params['Interval'] = $Interval
    }

    if ($PSBoundParameters.ContainsKey('StartDate')) {
        $params['StartDate'] = $StartDate
    }
    if ($PSBoundParameters.ContainsKey('EndDate')) {
        $params['EndDate'] = $EndDate
    }
    if ($MergeOutput.IsPresent) {
        $params['MergeOutput'] = $MergeOutput
    }

    # Call Get-UAL with the constructed parameters
    Get-UAL @params
}

function Get-MailboxAuditLogLegacy
{
<#
    .SYNOPSIS
    Get mailbox audit log entries using the legacy Search-MailboxAuditlog method.

    .DESCRIPTION
    Get mailbox audit log entries for specific a user account. 
	The output will be written to: Output\MailboxAuditLog\

	.PARAMETER UserIds
    UserIds is the Identity parameter specifying a single mailbox to retrieve mailbox audit log entries from.

	.PARAMETER StartDate
    startDate is the parameter specifying the start date of the date range.

	.PARAMETER EndDate
    endDate is the parameter specifying the end date of the date range.

	.PARAMETER OutputDir
    outputDir is the parameter specifying the output directory.
	Default: Output\MailboxAuditLog

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
    Get-MailboxAuditLogLegacy
	Get all available mailbox audit log entries for all user accounts

    .EXAMPLE
    Get-MailboxAuditLogLegacy -UserIds Test@invictus-ir.com
	Get mailbox audit log entries for the user Test@invictus-ir.com

	.EXAMPLE
    Get-MailboxAuditLogLegacy -UserIds "Test@invictus-ir.com,HR@invictus-ir.com"
	Get mailbox audit log entries for the users Test@invictus-ir.com and HR@invictus-ir.com.

	.EXAMPLE
	Get-MailboxAuditLogLegacy -UserIds Test@invictus-ir.com -StartDate 1/4/2023 -EndDate 5/4/2023
	Get mailbox audit log entries for the user Test@invictus-ir.com between 1/4/2023 and 5/4/2023.
#>
	[CmdletBinding()]
	param(
		[string]$UserIds,
		[string]$StartDate,
		[string]$EndDate,
		[string]$OutputDir = "Output\MailboxAuditLog",
		[string]$Encoding = "UTF8",
        [ValidateSet('None', 'Minimal', 'Standard', 'Debug')]
        [string]$LogLevel = 'Standard'
	)

    Set-LogLevel -Level ([LogLevel]::$LogLevel)
    $isDebugEnabled = $script:LogLevel -eq [LogLevel]::Debug

	try {
        $areYouConnected = Search-MailboxAuditlog -ErrorAction stop
    }
    catch {
        Write-LogFile -Message "[INFO] Ensure you are connected to M365 by running the Connect-M365 command before executing this script" -Level Minimal -Color "Yellow"
        Write-LogFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Level Minimal -Color "Red"
        throw
    }

    if ($isDebugEnabled) {
        Write-LogFile -Message "[DEBUG] PowerShell Version: $($PSVersionTable.PSVersion)" -Level Debug
        Write-LogFile -Message "[DEBUG] Input parameters:" -Level Debug
        Write-LogFile -Message "[DEBUG]   UserIds: $UserIds" -Level Debug
        Write-LogFile -Message "[DEBUG]   StartDate: $StartDate" -Level Debug
        Write-LogFile -Message "[DEBUG]   EndDate: $EndDate" -Level Debug
        Write-LogFile -Message "[DEBUG]   OutputDir: $OutputDir" -Level Debug
        Write-LogFile -Message "[DEBUG]   Encoding: $Encoding" -Level Debug
        Write-LogFile -Message "[DEBUG]   LogLevel: $LogLevel" -Level Debug
        
        $exchangeModule = Get-Module -Name ExchangeOnlineManagement -ErrorAction SilentlyContinue
        if ($exchangeModule) {
            Write-LogFile -Message "[DEBUG] ExchangeOnlineManagement Module Version: $($exchangeModule.Version)" -Level Debug
        } else {
            Write-LogFile -Message "[DEBUG] ExchangeOnlineManagement Module not loaded" -Level Debug
        }

        try {
            $connectionInfo = Get-ConnectionInformation -ErrorAction SilentlyContinue
            if ($connectionInfo) {
                Write-LogFile -Message "[DEBUG] Connection Status: $($connectionInfo.State)" -Level Debug
                Write-LogFile -Message "[DEBUG] Connection Type: $($connectionInfo.TokenStatus)" -Level Debug
                Write-LogFile -Message "[DEBUG] Connected Account: $($connectionInfo.UserPrincipalName)" -Level Debug
            } else {
                Write-LogFile -Message "[DEBUG] No active Exchange Online connection found" -Level Debug
            }
        } catch {
            Write-LogFile -Message "[DEBUG] Unable to retrieve connection information" -Level Debug
        }
    }

    Write-LogFile -Message "[INFO] Running Get-MailboxAuditLogLegacy" -Level Minimal -Color "Green"

	If (!(Test-Path $OutputDir)){
        New-Item -ItemType Directory -Force -Path $OutputDir > $null
        Write-LogFile -Message "[INFO] Creating the following directory: $OutputDir" -Level Standard
    }
    else {
        if (Test-Path -Path $OutputDir) {
            Write-LogFile -Message "[INFO] Custom directory set to: $OutputDir" -Level Standard
        }
        else {
            Write-Error "[Error] Custom directory invalid: $OutputDir exiting script" -ErrorAction Stop
            Write-LogFile -Message "[Error] Custom directory invalid: $OutputDir exiting script" -Level Minimal
        }
    }
	
	StartDate
	EndDate

	if (($null -eq $UserIds) -Or ($UserIds -eq ""))  {
        Write-LogFile -Message "[INFO] No users provided.. Getting the MailboxAuditLog for all users" -Level Standard -Color "Yellow"
		Get-mailbox -resultsize unlimited |
		ForEach-Object {
			$date = Get-Date -Format "yyyyMMddHHmm"
			$outputFile = "$OutputDir\$($date)-mailboxAuditLog-$($_.UserPrincipalName).csv"

            Write-LogFile -Message "[INFO] Collecting the MailboxAuditLog for $($_.UserPrincipalName)" -Level Standard
			$result = Search-MailboxAuditlog -Identity $_.UserPrincipalName -LogonTypes Delegate,Admin,Owner -StartDate $script:StartDate -EndDate $script:EndDate -ShowDetails -ResultSize 250000 
			$result | export-csv -NoTypeInformation -Path $outputFile -Encoding $Encoding
			
            Write-LogFile -Message "[INFO] Output is written to: $outputFile" -Level Standard -Color "Green"
		}
	}

	elseif ($UserIds -match ",") {
		$UserIds.Split(",") | Foreach {
			$user = $_
			$date = Get-Date -Format "yyyyMMddHHmm"
			$outputFile = "$OutputDir\$($date)-mailboxAuditLog-$($user).csv"

            Write-LogFile -Message "[INFO] Collecting the MailboxAuditLog for $user" -Level Standard
			$result = Search-MailboxAuditlog -Identity $user -LogonTypes Delegate,Admin,Owner -StartDate $script:StartDate -EndDate $script:EndDate -ShowDetails -ResultSize 250000 
			$result | export-csv -NoTypeInformation -Path $outputFile -Encoding $Encoding
			
            Write-LogFile -Message "[INFO] Output is written to: $outputFile" -Level Standard -Color "Green"
		}
	}

	else {		
		$date = Get-Date -Format "yyyyMMddHHmm"
		$outputFile = "$OutputDir\$($date)-mailboxAuditLog-$($UserIds).csv"

        Write-LogFile -Message "[INFO] Collecting the MailboxAuditLog for $UserIds" -Level Standard
		$result = Search-MailboxAuditlog -Identity $UserIds -LogonTypes Delegate,Admin,Owner -StartDate $script:StartDate -EndDate $script:EndDate -ShowDetails -ResultSize 250000 
		$result | export-csv -NoTypeInformation -Path $outputFile -Encoding $Encoding
		
        Write-LogFile -Message "[INFO] Output is written to: $outputFile" -Level Standard -Color "Green"
	} 
}
