function Get-MailboxAuditStatus {
<#
    .SYNOPSIS
    Retrieves audit status and settings for all mailboxes in Microsoft 365.

    .DESCRIPTION
    Retrieves detailed information about mailbox audit settings, including audit status, bypass settings,
    and configured audit actions for owners, delegates, and administrators.

    .PARAMETER OutputDir
    Specifies the output directory for the audit status report.
    Default: Output\Audit Status

    .PARAMETER Encoding
    Specifies the encoding of the CSV output file.
    Default: UTF8

    .PARAMETER UserIds
    UserIds is the UserIds parameter filtering the log entries by the account of the user who performed the actions.

    .PARAMETER LogLevel
    Specifies the level of logging:
    None: No logging
    Minimal: Critical errors only
    Standard: Normal operational logging
    Default: Standard
    
    .EXAMPLE
    Get-MailboxAuditStatus
    Retrieves audit status for all mailboxes and exports to a CSV file in the default directory.
		
    .EXAMPLE
    Get-MailboxAuditStatus -OutputDir C:\Temp -Encoding UTF32
    Retrieves audit status and saves the output to C:\Temp with UTF-32 encoding.
#>
    [CmdletBinding()]
    param (
        [string]$OutputDir = "Output\Audit Status",
        [string]$Encoding = "UTF8",
        [ValidateSet('None', 'Minimal', 'Standard', 'Debug')]
        [string]$LogLevel = 'Standard',
        [string]$UserIds
    )

    Set-LogLevel -Level ([LogLevel]::$LogLevel)
    $summary = @{
        TotalMailboxes = 0
        AuditEnabled = 0
        AuditDisabled = 0
        AuditBypass = 0
        OwnerActionsConfigured = 0
        DelegateActionsConfigured = 0
        AdminActionsConfigured = 0
        ProcessedMailboxes = 0
        StartTime = Get-Date
        ProcessingTime = $null
        OrgWideAuditingEnabled = $false
    }

    Write-LogFile -Message "=== Starting Mailbox Audit Status Collection ===" -Color "Cyan" -Level Minimal

    if (!(Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Force -Path $OutputDir > $null
    } else {
        if (!(Test-Path -Path $OutputDir)) {
            Write-LogFile -Message "[ERROR] Custom directory invalid: $OutputDir" -Level Minimal -Color "Red"
            return
        }
    }

    $date = Get-Date -Format "yyyyMMddHHmm"
    $outputFile = "$date-MailboxAuditStatus.csv"
    $outputDirectory = Join-Path $OutputDir $outputFile

    try {
        $orgConfig = Get-OrganizationConfig | Select-Object -ExpandProperty AuditDisabled
        $summary.OrgWideAuditingEnabled = -not $orgConfig
        
        if ($orgConfig) {
            Write-LogFile -Message "[WARNING] Organization-wide auditing is disabled!" -Level Minimal -Color "Red"
        } else {
            Write-LogFile -Message "[INFO] Organization-wide auditing is enabled - This overrides individual mailbox settings" -Level Standard -Color "Green"
        }
    }
    catch {
        Write-LogFile -Message "[INFO] Ensure you are connected to M365 by running the Connect-ExchangeOnline or Connect-M365 command before executing this script" -Level Minimal -Color "Yellow"
        Write-LogFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Level Minimal -Color "Red"
        throw
    }

    Write-LogFile -Message "[INFO] Retrieving mailbox list..." -Level Standard
    $mailboxes = Get-EXOMailbox -ResultSize unlimited -PropertySets All
    $summary.TotalMailboxes = $mailboxes.Count
    Write-LogFile -Message "[INFO] Found $($mailboxes.Count) mailboxes to process" -Level Standard

    Write-LogFile -Message "[INFO] Retrieving audit bypass associations..." -Level Standard
    $bypassLookup = @{}

    foreach ($mailbox in $mailboxes) {
        $bypassLookup[$mailbox.UserPrincipalName] = $false
    }

    try {
        Write-LogFile -Message "[INFO] Attempting bulk retrieval of audit bypass associations..." -Level Standard
        $bypassAssociations = Get-MailboxAuditBypassAssociation -ResultSize Unlimited -WarningAction SilentlyContinue | 
            Select-Object Identity, AuditBypassEnabled | 
            Where-Object { $_.AuditBypassEnabled -eq $true }
        
        foreach ($bypass in $bypassAssociations) {
            if ($null -ne $bypass.Identity) {
                $bypassLookup[$bypass.Identity] = $True
            }
        }
    }
    catch {
        Write-LogFile -Message "[WARNING] Bulk retrieval failed, likely due to too many mailboxes. This will timeout the cmdlet. Processing mailboxes individually..." -Level Standard -Color "Yellow"
        Write-LogFile -Message "[WARNING] This may take some time..." -Level Standard -Color "Yellow"

        $batchSize = 10
        for ($i = 0; $i -lt $mailboxes.Count; $i += $batchSize) {
            $batch = $mailboxes | Select-Object -Skip $i -First $batchSize
            
            foreach ($mbx in $batch) {
                try {
                    $bypass = Get-MailboxAuditBypassAssociation -Identity $mbx.UserPrincipalName -WarningAction SilentlyContinue | Select-Object Identity, AuditBypassEnabled
                    if ($bypass -and $bypass.Identity) {
                        $bypassLookup[$bypass.Identity] = [bool]$bypass.AuditBypassEnabled 
                    }
                    else {
                        $bypassLookup[$mbx.UserPrincipalName] = $false
                    }
                }
                catch {
                    $bypassLookup[$mbx.UserPrincipalName] = $false
                    continue
                }
            }
            
            $processed = [Math]::Min($i + $batchSize, $mailboxes.Count)
            $percentage = [math]::Round(($processed / $mailboxes.Count) * 100, 2)
            Write-LogFile -Message "[INFO] Processed bypass status: $processed/$($mailboxes.Count) mailboxes ($percentage%)" -Level Standard
            Start-Sleep -Seconds 5 # Otherwise it might still timeout.
        }
    }

    $results = @()

    foreach ($mailbox in $mailboxes) {
        $summary.ProcessedMailboxes++
        $bypassStatus = $bypassLookup[$mailbox.UserPrincipalName]

        if ($mailbox.AuditEnabled) { $summary.AuditEnabled++ }
        else { $summary.AuditDisabled++ }
        if ($bypassStatus) { $summary.AuditBypass++ }
        if ($mailbox.AuditOwner) { $summary.OwnerActionsConfigured++ }
        if ($mailbox.AuditDelegate) { $summary.DelegateActionsConfigured++ }
        if ($mailbox.AuditAdmin) { $summary.AdminActionsConfigured++ }

         # Sort the audit actions for each category
         $ownerActions = if ($mailbox.AuditOwner) { 
            ($mailbox.AuditOwner | Sort-Object) -join ', ' 
        } else { 
            '' 
        }
        
        $delegateActions = if ($mailbox.AuditDelegate) { 
            ($mailbox.AuditDelegate | Sort-Object) -join ', ' 
        } else { 
            '' 
        }
        
        $adminActions = if ($mailbox.AuditAdmin) { 
            ($mailbox.AuditAdmin | Sort-Object) -join ', ' 
        } else { 
            '' 
        }

        $defaultAuditSet = if ($mailbox.DefaultAuditSet) {
            ($mailbox.DefaultAuditSet | Sort-Object) -join ', '
        } else {
            ''
        }

        $results += [PSCustomObject]@{
            UserPrincipalName = $mailbox.UserPrincipalName
            DisplayName = $mailbox.DisplayName
            RecipientTypeDetails = $mailbox.RecipientTypeDetails
            AuditEnabled = $mailbox.AuditEnabled
            AuditBypassEnabled = $bypassStatus
            DefaultAuditSet = $defaultAuditSet
            OwnerAuditActions = $ownerActions
            OwnerAuditActionsCount = if ($mailbox.AuditOwner) { $mailbox.AuditOwner.Count } else { 0 }
            DelegateAuditActions = $delegateActions
            DelegateAuditActionsCount = if ($mailbox.AuditDelegate) { $mailbox.AuditDelegate.Count } else { 0 }
            AdminAuditActions = $adminActions
            AdminAuditActionsCount = if ($mailbox.AuditAdmin) { $mailbox.AuditAdmin.Count } else { 0 }
            EffectiveAuditState = if ($summary.OrgWideAuditingEnabled -and -not $bypassStatus) { 
                "Enabled (Organization Policy)" 
            } elseif ($bypassStatus) {
                "Bypassed"
            } else {
                "Disabled"
            }
        }
    }

    $results | Export-Csv -Path $outputDirectory -NoTypeInformation -Encoding $Encoding
    $summary.ProcessingTime = (Get-Date) - $summary.StartTime
    
    Write-LogFile -Message "`nOrganization Configuration:" -Level Standard -Color "Cyan"
    Write-LogFile -Message "  Organization-wide Auditing: $(if ($summary.OrgWideAuditingEnabled) { 'Enabled' } else { 'Disabled' })" -Level Standard
    if ($summary.OrgWideAuditingEnabled) {
        Write-LogFile -Message "  [!] Organization-wide auditing overrides individual mailbox settings" -Level Standard
        Write-LogFile -Message "  [!] Default actions are automatically logged for all non-bypassed mailboxes" -Level Standard
    }
    Write-LogFile -Message "`nMailbox Statistics:" -Level Standard -Color "Cyan"
    Write-LogFile -Message "  Total Mailboxes: $($summary.TotalMailboxes)" -Level Standard
    Write-LogFile -Message "  Audit Enabled: $($summary.AuditEnabled)" -Level Standard
    Write-LogFile -Message "  Audit Disabled: $($summary.AuditDisabled)" -Level Standard
    Write-LogFile -Message "  Audit Bypass Enabled: $($summary.AuditBypass)" -Level Standard
    
    Write-LogFile -Message "`nAudit Actions Configured:" -Level Standard -Color "Cyan"
    Write-LogFile -Message "  Owner Actions: $($summary.OwnerActionsConfigured)" -Level Standard
    Write-LogFile -Message "  Delegate Actions: $($summary.DelegateActionsConfigured)" -Level Standard
    Write-LogFile -Message "  Admin Actions: $($summary.AdminActionsConfigured)" -Level Standard
    
    Write-LogFile -Message "`nOutput Details:" -Level Standard -Color "Cyan"
    Write-LogFile -Message "  Output File: $outputDirectory" -Level Standard
    Write-LogFile -Message "  Processing Time: $($summary.ProcessingTime.ToString('mm\:ss'))" -Level Standard
    Write-LogFile -Message "===================================" -Color "Cyan" -Level Standard
}
