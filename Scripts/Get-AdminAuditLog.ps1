function Get-AdminAuditLog {
<#
    .SYNOPSIS
    Search the contents of the administrator audit log.

    .DESCRIPTION
    Administrator audit logging records when a user or administrator makes a change in your organization (in the Exchange admin center or by using cmdlets).
    The output will be written to: Output\AdminAuditLog\

    .PARAMETER StartDate
    startDate is the parameter specifying the start date of the date range.

    .PARAMETER EndDate
    endDate is the parameter specifying the end date of the date range.

    .PARAMETER Interval
    Interval is the parameter specifying the interval in which the logs are being gathered.

	.PARAMETER Output
    Output is the parameter specifying the CSV, JSON, JSONL or SOF-ELK output type. The SOF-ELK output can be imported into the platform of the same name.
    Default: CSV

    .PARAMETER MergeOutput
    MergeOutput is the parameter specifying if you wish to merge CSV outputs to a single file.

    .PARAMETER OutputDir
    OutputDir is the parameter specifying the output directory.
    Default: Output\AdminAuditLog

    .PARAMETER LogLevel
    Specifies the level of logging:
    None: No logging
    Minimal: Critical errors only
    Standard: Normal operational logging
    Default: Standard

    .PARAMETER Encoding
    Encoding is the parameter specifying the encoding of the CSV/JSON output file.
    Default: UTF8

    .PARAMETER UserIds
    UserIds is the UserIds parameter filtering the log entries by the account of the user who performed the actions.
    
    .EXAMPLE
    Get-AdminAuditLog
    Displays the total number of logs within the admin audit log.

    .EXAMPLE
    Get-AdminAuditLog -StartDate 2025-04-01 -EndDate 2025-04-05
    Collects the admin audit log between 2025-04-01 and 2025-04-05
#>
    [CmdletBinding()]
    param(
        [string]$UserIds = "*",
        [string]$StartDate,
        [string]$EndDate,
        [decimal]$Interval,
        [string]$OutputDir = "Output\AdminAuditLog",
        [ValidateSet("CSV", "JSON", "SOF-ELK", "JSONL")]
        [string]$Output = "CSV",
        [switch]$MergeOutput,
        [string]$Encoding = "UTF8",
        [ValidateSet('None', 'Minimal', 'Standard', 'Debug')]
        [string]$LogLevel = 'Standard'
    )

    $params = @{
        RecordType = "ExchangeAdmin"
        UserIds = $UserIds
        Output = $Output
        OutputDir = $OutputDir
        LogLevel = $LogLevel
        Encoding = $Encoding
    }

    if ($PSBoundParameters.ContainsKey('StartDate')) {
        $params['StartDate'] = $StartDate
    }
    if ($PSBoundParameters.ContainsKey('EndDate')) {
        $params['EndDate'] = $EndDate
    }
    if ($PSBoundParameters.ContainsKey('Interval')) {
        $params['Interval'] = $Interval
    }
    if ($MergeOutput.IsPresent) {
        $params['MergeOutput'] = $true
    }

    $date = [datetime]::Now.ToString('yyyyMMddHHmmss')
    if ($OutputDir -eq "Output\AdminAuditLog") {
        $OutputDir = "Output\AdminAuditLog\$date"
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

    Write-LogFile -Message "== Starting the Admin Audit Log Collection (utilizing Get-UAL) ==" -Level Minimal

    # Call Get-UAL with the constructed parameters
    Get-UAL @params
}
    