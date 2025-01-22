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
        [ValidateSet('None', 'Minimal', 'Standard')]
        [string]$LogLevel = 'Standard'
    )

    Write-LogFile -Message "== Starting the Mailbox Audit Log Collection (utilizing Get-UAL) ==" -Level Minimal

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