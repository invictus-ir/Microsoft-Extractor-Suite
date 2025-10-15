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
    Debug: Verbose logging for debugging purposes
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
        [string]$OutputDir,
        [string]$Encoding = "UTF8",
        [ValidateSet('None', 'Minimal', 'Standard', 'Debug')]
        [string]$LogLevel = 'Standard',
        [string[]]$UserIds
    )

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

    Init-Logging
    Init-OutputDir -Component "Audit Status" -FilePostfix "MailboxAuditStatus" -CustomOutputDir $OutputDir

    Write-LogFile -Message "=== Starting Mailbox Audit Status Collection ===" -Color "Cyan" -Level Standard

    try {
        $orgConfig = Get-OrganizationConfig | Select-Object -ExpandProperty AuditDisabled
        $summary.OrgWideAuditingEnabled = -not $orgConfig

        if ($isDebugEnabled) {
            Write-LogFile -Message "[DEBUG] Organization audit configuration:" -Level Debug
            Write-LogFile -Message "[DEBUG]   AuditDisabled property: $orgConfig" -Level Debug
            Write-LogFile -Message "[DEBUG]   Organization-wide auditing enabled: $($summary.OrgWideAuditingEnabled)" -Level Debug
        }
        
        if ($orgConfig) {
            Write-LogFile -Message "[WARNING] Organization-wide auditing is disabled!" -Level Minimal -Color "Red"
        } else {
            Write-LogFile -Message "[INFO] Organization-wide auditing is enabled - This overrides individual mailbox settings" -Level Standard -Color "Green"
        }
    }
    catch {
        Write-LogFile -Message "[INFO] Ensure you are connected to M365 by running the Connect-ExchangeOnline or Connect-M365 command before executing this script" -Level Minimal -Color "Yellow"
        Write-LogFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Level Minimal -Color "Red"

        if ($isDebugEnabled) {
            Write-LogFile -Message "[DEBUG] Organization config retrieval failed:" -Level Debug
            Write-LogFile -Message "[DEBUG]   Exception type: $($_.Exception.GetType().Name)" -Level Debug
            Write-LogFile -Message "[DEBUG]   Exception message: $($_.Exception.Message)" -Level Debug
            Write-LogFile -Message "[DEBUG]   Stack trace: $($_.ScriptStackTrace)" -Level Debug
        }
        throw
    }

    Write-LogFile -Message "[INFO] Retrieving mailbox list..." -Level Standard

    if ($isDebugEnabled) {
        Write-LogFile -Message "[DEBUG] Executing Get-EXOMailbox command..." -Level Debug
        Write-LogFile -Message "[DEBUG]   Parameters: -ResultSize unlimited -PropertySets All" -Level Debug
        $mailboxRetrievalStart = Get-Date
    }

    try {
        $mailboxes = Get-EXOMailbox -ResultSize unlimited -PropertySets All
        $summary.TotalMailboxes = $mailboxes.Count
        Write-LogFile -Message "[INFO] Found $($mailboxes.Count) mailboxes to process" -Level Standard

        if ($isDebugEnabled) {
            $mailboxRetrievalTime = (Get-Date) - $mailboxRetrievalStart
            Write-LogFile -Message "[DEBUG] Mailbox retrieval completed:" -Level Debug
            Write-LogFile -Message "[DEBUG]   Total mailboxes: $($mailboxes.Count)" -Level Debug
            Write-LogFile -Message "[DEBUG]   Retrieval time: $($mailboxRetrievalTime.TotalSeconds) seconds" -Level Debug
        }
    }
    catch {
        Write-LogFile -Message "[ERROR] Failed to retrieve mailboxes: $($_.Exception.Message)" -Level Minimal -Color "Red"
        if ($isDebugEnabled) {
            Write-LogFile -Message "[DEBUG] Mailbox retrieval error:" -Level Debug
            Write-LogFile -Message "[DEBUG]   Exception: $($_.Exception.Message)" -Level Debug
            Write-LogFile -Message "[DEBUG]   Stack trace: $($_.ScriptStackTrace)" -Level Debug
        }
        throw
    }


    Write-LogFile -Message "[INFO] Retrieving audit bypass associations..." -Level Standard
    $bypassLookup = @{}

    foreach ($mailbox in $mailboxes) {
        $bypassLookup[$mailbox.UserPrincipalName] = $false
    }

    if ($isDebugEnabled) {
        Write-LogFile -Message "[DEBUG] Bypass lookup initialized with $($bypassLookup.Count) entries (all set to false)" -Level Debug
    }

    try {
        Write-LogFile -Message "[INFO] Attempting bulk retrieval of audit bypass associations..." -Level Standard
        $bypassAssociations = Get-MailboxAuditBypassAssociation -ResultSize Unlimited -WarningAction SilentlyContinue | 
            Select-Object Identity, AuditBypassEnabled | 
            Where-Object { $_.AuditBypassEnabled -eq $true }
        
        if ($isDebugEnabled) {
            Write-LogFile -Message "[DEBUG] Bulk bypass retrieval completed:" -Level Debug
            Write-LogFile -Message "[DEBUG]   Bypass associations found: $($bypassAssociations.Count)" -Level Debug
        }
        
        foreach ($bypass in $bypassAssociations) {
            if ($null -ne $bypass.Identity) {
                $bypassLookup[$bypass.Identity] = $True
                if ($isDebugEnabled) {
                    Write-LogFile -Message "[DEBUG]   Set bypass = true for: $($bypass.Identity)" -Level Debug
                }
            }
        }
        if ($isDebugEnabled) {
            $bypassCount = ($bypassLookup.Values | Where-Object { $_ -eq $true }).Count
            Write-LogFile -Message "[DEBUG] Bypass lookup updated: $bypassCount mailboxes with bypass enabled" -Level Debug
        }
    }
    catch {
        Write-LogFile -Message "[WARNING] Bulk retrieval failed, likely due to too many mailboxes. This will timeout the cmdlet. Processing mailboxes individually..." -Level Standard -Color "Yellow"
        Write-LogFile -Message "[WARNING] This may take some time..." -Level Standard -Color "Yellow"

        if ($isDebugEnabled) {
            Write-LogFile -Message "[DEBUG] Bulk bypass retrieval failed, switching to individual processing:" -Level Debug
            Write-LogFile -Message "[DEBUG]   Exception: $($_.Exception.Message)" -Level Debug
        }

        $batchSize = 10
        for ($i = 0; $i -lt $mailboxes.Count; $i += $batchSize) {
            $batch = $mailboxes | Select-Object -Skip $i -First $batchSize

            if ($isDebugEnabled) {
                $batchNumber = [Math]::Floor($i / $batchSize) + 1
                Write-LogFile -Message "[DEBUG] Processing batch $batchNumber (mailboxes $($i + 1) to $([Math]::Min($i + $batchSize, $mailboxes.Count)))" -Level Debug
            }
            foreach ($mbx in $batch) {
                try {
                    $bypass = Get-MailboxAuditBypassAssociation -Identity $mbx.UserPrincipalName -WarningAction SilentlyContinue | Select-Object Identity, AuditBypassEnabled
                    if ($bypass -and $bypass.Identity) {
                        $bypassLookup[$bypass.Identity] = [bool]$bypass.AuditBypassEnabled 
                    }
                    if ($isDebugEnabled -and $bypass.AuditBypassEnabled) {
                            Write-LogFile -Message "[DEBUG]     Individual bypass found: $($mbx.UserPrincipalName)" -Level Debug
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

        if ($isDebugEnabled -and ($summary.ProcessedMailboxes % 100 -eq 0 -or $summary.ProcessedMailboxes -le 10)) {
            Write-LogFile -Message "[DEBUG] Processing mailbox $($summary.ProcessedMailboxes)/$($summary.TotalMailboxes): $($mailbox.UserPrincipalName)" -Level Debug
            Write-LogFile -Message "[DEBUG]   AuditEnabled: $($mailbox.AuditEnabled), Bypass: $bypassStatus" -Level Debug
            Write-LogFile -Message "[DEBUG]   Owner actions: $($mailbox.AuditOwner.Count), Delegate: $($mailbox.AuditDelegate.Count), Admin: $($mailbox.AuditAdmin.Count)" -Level Debug
        }

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

    $results | Export-Csv -Path $script:outputFile -NoTypeInformation -Encoding $Encoding

    $summaryData = [ordered]@{
        "Organization Configuration" = [ordered]@{
            "Organization-wide Auditing" = if ($summary.OrgWideAuditingEnabled) { 'Enabled' } else { 'Disabled' }
        }
        "Mailbox Statistics" = [ordered]@{
            "Total Mailboxes" = $summary.TotalMailboxes
            "Audit Enabled" = $summary.AuditEnabled
            "Audit Disabled" = $summary.AuditDisabled
            "Audit Bypass Enabled" = $summary.AuditBypass
        }
        "Audit Actions Configured" = [ordered]@{
            "Owner Actions" = $summary.OwnerActionsConfigured
            "Delegate Actions" = $summary.DelegateActionsConfigured
            "Admin Actions" = $summary.AdminActionsConfigured
        }
    }

    $summary.ProcessingTime = (Get-Date) - $summary.StartTime
    
    if ($summary.OrgWideAuditingEnabled) {
        Write-LogFile -Message "  [!] Organization-wide auditing overrides individual mailbox settings" -Level Standard
        Write-LogFile -Message "  [!] Default actions are automatically logged for all non-bypassed mailboxes" -Level Standard
    }

    Write-Summary -Summary $summaryData -Title "Mailbox Audit Status Summary"
}
    