function Get-MailboxPermissions {
<#
    .SYNOPSIS
    Retrieves delegated permissions for all mailboxes in Microsoft 365.

    .DESCRIPTION
    Retrieves detailed information about mailbox delegated permissions, including Full Access, Send As, 
    Send on Behalf, Calendar permissions, and Inbox permissions for all mailboxes.

    .PARAMETER OutputDir
    Specifies the output directory for the delegated permissions report.
    Default: Output\Mailbox Permissions

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
    Get-MailboxPermissions
    Retrieves delegated permissions for all mailboxes and exports to a CSV file in the default directory.
        
    .EXAMPLE
    Get-MailboxPermissions -OutputDir C:\Temp -Encoding UTF32
    Retrieves delegated permissions and saves the output to C:\Temp with UTF-32 encoding.

    .EXAMPLE
    Get-MailboxPermissions -OutputDir "Reports" -Encoding UTF8
    Retrieves delegated permissions and saves the report in the Reports folder with UTF-8 encoding.
#>
    [CmdletBinding()]
    param (
        [string]$OutputDir,
        [string]$Encoding = "UTF8",
        [ValidateSet('None', 'Minimal', 'Standard', 'Debug')]
        [string]$LogLevel = 'Standard',
        [string[]]$UserIds
        )

    Init-Logging
    Init-OutputDir -Component "Mailbox Permissions" -FilePostfix "MailboxPermissions" -CustomOutputDir $OutputDir

    $summary = @{
        TotalMailboxes = 0
        MailboxesProcessed = 0
        MailboxesWithPermissions = 0
        PermissionStats = @{
            FullAccess = 0
            SendAs = 0
            SendOnBehalf = 0
            Calendar = 0
            Inbox = 0
        }
        StartTime = Get-Date
        ProcessingTime = $null
    }

    Write-LogFile -Message "=== Starting Mailbox Permissions Collection ===" -Color "Cyan" -Level Standard
    try {
        Get-EXOMailbox -ResultSize 1 > $null
    }
    catch {
        write-logFile -Message "[INFO] Ensure you are connected to M365 by running the Connect-M365 command before executing this script" -Color "Yellow" -Level Minimal
        Write-logFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Color "Red" -Level Minimal
        if ($isDebugEnabled) {
            Write-LogFile -Message "[DEBUG] Connection error details:" -Level Debug
            Write-LogFile -Message "[DEBUG]   Exception type: $($_.Exception.GetType().Name)" -Level Debug
            Write-LogFile -Message "[DEBUG]   Full error: $($_.Exception.ToString())" -Level Debug
            Write-LogFile -Message "[DEBUG]   Stack trace: $($_.ScriptStackTrace)" -Level Debug
        }
        throw
    }

    $results = [System.Collections.Generic.List[object]]::new()
    $recipientCache = @{}
    Write-LogFile -Message "[INFO] Retrieving mailbox list..." -Level Standard

    if ($UserIds) {
        $userIdList = $UserIds -split ','
        Write-LogFile -Message "[INFO] Filtering mailboxes for users: $UserIds" -Level Standard
        $mailboxes = Get-EXOMailbox -ResultSize unlimited -Properties UserPrincipalName, DisplayName, GrantSendOnBehalfTo, RecipientTypeDetails | 
            Where-Object { $userIdList -contains $_.UserPrincipalName }
    } else {
        $mailboxes = Get-EXOMailbox -ResultSize unlimited -Properties UserPrincipalName, DisplayName, GrantSendOnBehalfTo, RecipientTypeDetails
    }
    
    $totalMailboxes = $mailboxes.Count
    $summary.TotalMailboxes = $mailboxes.Count
    Write-LogFile -Message "[INFO] Found $($summary.TotalMailboxes) mailboxes to process" -Level Standard
    $current = 0

    foreach ($mailbox in $mailboxes) {
        $summary.MailboxesProcessed++
        $current++
        if ($LogLevel -eq 'Standard') {
            Write-Progress -Activity "Checking delegated permissions" -Status "Processing $($mailbox.DisplayName)" -PercentComplete (($current / $totalMailboxes) * 100)
        }

        if ($isDebugEnabled) {
            Write-LogFile -Message "[DEBUG] Mailbox details:" -Level Debug
            Write-LogFile -Message "[DEBUG]   Display Name: $($mailbox.DisplayName)" -Level Debug
            Write-LogFile -Message "[DEBUG]   UPN: $($mailbox.UserPrincipalName)" -Level Debug
            Write-LogFile -Message "[DEBUG]   Type: $($mailbox.RecipientTypeDetails)" -Level Debug
        }

        # Get Full Access permissions
        $fullAccessDetails = Get-MailboxPermission -Identity $mailbox.UserPrincipalName | 
            Where-Object {
                $_.IsInherited -eq $false -and 
                $_.User -notlike "NT AUTHORITY\SELF" -and 
                $_.User -notlike "DiscoverySearchMailbox" -and 
                $_.User -notlike "S-1-5*"
            }

        if ($isDebugEnabled) {
            Write-LogFile -Message "[DEBUG]   Found $(@($fullAccessDetails).Count) Full Access permissions" -Level Debug
        }

        # Get Send As permissions
        $sendAsDetails = @()
        try {
            $sendAsDetails = Get-RecipientPermission -Identity $mailbox.UserPrincipalName -ErrorAction Stop |
                Where-Object {
                    $_.IsInherited -eq $false -and
                    $_.Trustee -notlike "NT AUTHORITY\SELF" -and
                    $_.Trustee -notlike "DiscoverySearchMailbox*" -and
                    $_.Trustee -notlike "S-1-5*"
                }
            if ($isDebugEnabled) {
                Write-LogFile -Message "[DEBUG]   Found $(@($sendAsDetails).Count) Send As permissions" -Level Debug
            }
        }
        catch [System.Management.Automation.CommandNotFoundException] {
            if ($LogLevel -eq 'Standard') {
                Write-LogFile -Message "[WARNING] Get-RecipientPermission cmdlet not available. Skipping Send As permissions check for $($mailbox.UserPrincipalName)." -Color "Yellow" -Level Standard
            }
        }
        catch {
            if ($_.Exception.Message -match "couldn't be found|ManagementObjectNotFoundException") {
                Write-LogFile -Message "[DEBUG] Skipping Send As for $($mailbox.UserPrincipalName): mailbox not found on server" -Level Debug
            } else {
                Write-LogFile -Message "[WARNING] Error getting Send As permissions for $($mailbox.UserPrincipalName): $($_.Exception.Message)" -Color "Yellow" -Level Standard
                if ($isDebugEnabled) {
                    Write-LogFile -Message "[DEBUG] Mailbox retrieval error details:" -Level Debug
                    Write-LogFile -Message "[DEBUG]   Exception type: $($_.Exception.GetType().Name)" -Level Debug
                    Write-LogFile -Message "[DEBUG]   Full error: $($_.Exception.ToString())" -Level Debug
                    Write-LogFile -Message "[DEBUG]   Stack trace: $($_.ScriptStackTrace)" -Level Debug
                }
            }
        }

        # Get Send on Behalf permissions
        $sendOnBehalfUsers = $mailbox.GrantSendOnBehalfTo | Where-Object {$_ -ne $null}

        if ($isDebugEnabled) {
            Write-LogFile -Message "[DEBUG]   Found $(@($sendOnBehalfUsers).Count) Send on Behalf permissions" -Level Debug
        }
        
        # Get Calendar Folder Permissions
        $calendarPermissions = @()
        try {
            $calendarPermissions = Get-MailboxFolderPermission -Identity "$($mailbox.UserPrincipalName):\Calendar" -ErrorAction Stop | 
                Where-Object {
                    $_.User.DisplayName -notlike "Default" -and 
                    $_.User.DisplayName -notlike "Anonymous" -and 
                    $_.User.DisplayName -notlike "NT AUTHORITY\SELF"
                }

            if ($isDebugEnabled) {
                Write-LogFile -Message "[DEBUG]   Found $(@($calendarPermissions).Count) Calendar permissions" -Level Debug
            }
        }
        catch {
        }

         # Get Inbox Folder Permissions
        $inboxPermissions = @()
        try {
            $inboxPermissions = Get-MailboxFolderPermission -Identity "$($mailbox.UserPrincipalName):\Inbox" -ErrorAction Stop | 
                Where-Object {
                    $_.User.DisplayName -notlike "Default" -and 
                    $_.User.DisplayName -notlike "Anonymous" -and 
                    $_.User.DisplayName -notlike "NT AUTHORITY\SELF"
                }

            if ($isDebugEnabled) {
                Write-LogFile -Message "[DEBUG]   Found $(@($inboxPermissions).Count) Inbox permissions" -Level Debug
            }
        }
        catch {
        }

        $fullAccessCount    = @($fullAccessDetails).Count
        $sendAsCount        = @($sendAsDetails).Count
        $sendOnBehalfCount  = @($sendOnBehalfUsers).Count
        $calendarCount      = @($calendarPermissions).Count
        $inboxCount         = @($inboxPermissions).Count

        $summary.PermissionStats.FullAccess    += $fullAccessCount
        $summary.PermissionStats.SendAs        += $sendAsCount
        $summary.PermissionStats.SendOnBehalf  += $sendOnBehalfCount
        $summary.PermissionStats.Calendar      += $calendarCount
        $summary.PermissionStats.Inbox         += $inboxCount

        # Pre-resolve all unique recipient identities for this mailbox into cache
        $identitiesToResolve = [System.Collections.Generic.List[object]]::new()
        if ($fullAccessDetails) { foreach ($e in $fullAccessDetails) { $identitiesToResolve.Add($e.User) } }
        if ($sendAsDetails)     { foreach ($e in $sendAsDetails)     { $identitiesToResolve.Add($e.Trustee) } }
        if ($sendOnBehalfUsers) { foreach ($e in $sendOnBehalfUsers) { $identitiesToResolve.Add($e) } }
        foreach ($id in ($identitiesToResolve | Select-Object -Unique)) {
            if (-not $recipientCache.ContainsKey($id)) {
                $recipientCache[$id] = Get-EXORecipient $id -ErrorAction SilentlyContinue
            }
        }

        $permissionEntry = [PSCustomObject]@{
            UserPrincipalName = $mailbox.UserPrincipalName
            DisplayName = $mailbox.DisplayName
            RecipientTypeDetails = $mailbox.RecipientTypeDetails

            # Full Access Details
            FullAccessUsers = ($fullAccessDetails | ForEach-Object {
                $r = $recipientCache[$_.User]
                if ($r) { "$($r.DisplayName) ($($r.PrimarySmtpAddress))" } else { $_.User }
            }) -join '; '
            FullAccessPermissions = ($fullAccessDetails | ForEach-Object {
                $r = $recipientCache[$_.User]
                $userName = if ($r) { "$($r.DisplayName) ($($r.PrimarySmtpAddress))" } else { $_.User }
                "$userName - Rights: $($_.AccessRights -join ','), Deny: $($_.Deny), Inheritance: $($_.InheritanceType)"
            }) -join ' | '

            # Send As Details
            SendAsUsers = ($sendAsDetails | ForEach-Object {
                $r = $recipientCache[$_.Trustee]
                if ($r) { "$($r.DisplayName) ($($r.PrimarySmtpAddress))" } else { $_.Trustee }
            }) -join '; '
            SendAsPermissions = ($sendAsDetails | ForEach-Object {
                $r = $recipientCache[$_.Trustee]
                $userName = if ($r) { "$($r.DisplayName) ($($r.PrimarySmtpAddress))" } else { $_.Trustee }
                "$userName - Type: $($_.AccessControlType), Rights: $($_.AccessRights), Inheritance: $($_.InheritanceType)"
            }) -join ' | '

            # Send on Behalf Details
            SendOnBehalfUsers = ($sendOnBehalfUsers | ForEach-Object {
                $r = $recipientCache[$_]
                if ($r) { "$($r.DisplayName) ($($r.PrimarySmtpAddress))" } else { $_ }
            }) -join '; '

            # Calendar Permissions
            CalendarUsers = ($calendarPermissions | ForEach-Object {
                "$($_.User.DisplayName) ($($_.User.ADRecipient.PrimarySmtpAddress)) - $($_.AccessRights)"
            }) -join '; '
            CalendarPermissions = ($calendarPermissions | ForEach-Object {
                "$($_.User.DisplayName): $($_.AccessRights)"
            }) -join ' | '

            # Inbox Permissions
            InboxUsers = ($inboxPermissions | ForEach-Object {
                "$($_.User.DisplayName) ($($_.User.ADRecipient.PrimarySmtpAddress)) - $($_.AccessRights)"
            }) -join '; '
            InboxPermissions = ($inboxPermissions | ForEach-Object {
                "$($_.User.DisplayName): $($_.AccessRights)"
            }) -join ' | '

            # Permission Counts
            FullAccessCount           = $fullAccessCount
            SendAsCount               = $sendAsCount
            SendOnBehalfCount         = $sendOnBehalfCount
            CalendarPermissionCount   = $calendarCount
            InboxPermissionCount      = $inboxCount
        }            

        if ($permissionEntry.FullAccessCount -gt 0 -or 
            $permissionEntry.SendAsCount -gt 0 -or 
            $permissionEntry.SendOnBehalfCount -gt 0 -or
            $permissionEntry.CalendarPermissionCount -gt 0 -or
            $permissionEntry.InboxPermissionCount -gt 0) {
            $summary.MailboxesWithPermissions++
        }

        $results.Add($permissionEntry)
    }

    $results | Export-Csv -Path $script:outputFile -NoTypeInformation -Encoding $Encoding
    Write-Progress -Activity "Checking delegated permissions" -Completed

    $summary.ProcessingTime = (Get-Date) - $summary.StartTime

    $summaryData = [ordered]@{
        "Processing Statistics" = [ordered]@{
            "Total Mailboxes" = $summary.TotalMailboxes
            "Mailboxes Processed" = $summary.MailboxesProcessed
            "Mailboxes with Permissions" = $summary.MailboxesWithPermissions
        }
        "Permission Counts" = [ordered]@{
            "Full Access" = $summary.PermissionStats.FullAccess
            "Send As" = $summary.PermissionStats.SendAs
            "Send on Behalf" = $summary.PermissionStats.SendOnBehalf
            "Calendar" = $summary.PermissionStats.Calendar
            "Inbox" = $summary.PermissionStats.Inbox
        }
    }

    Write-Summary -Summary $summaryData -Title "Mailbox Permissions Analysis Summary"
}