@{
    Name = "UAL Operations - Full Collection of Mail Operations"
    Description = "Collecte exhaustive of UAL concerning Mail Operations via Get-UAL. Bypass the limitation of 5000 events of Get-QuickUALOperations."

    Tasks = @(
        @{
            Task = "UALOperationsFull"
            Operations = @(
                # ===== EMAIL RULES & CONFIGURATION =====
                'New-InboxRule'
                'Set-InboxRule'
                'Enable-InboxRule'
                'Disable-InboxRule'
                'Remove-InboxRule'
                'New-TransportRule'
                'Set-TransportRule'
                'Enable-TransportRule'
                'Disable-TransportRule'

                # ===== EMAIL ACTIVITIES =====
                'MailboxLogin'
                'MailItemsAccessed'
                'Send'
                'SendAs'
                'SendOnBehalf'
                'HardDelete'
                'SoftDelete'
                'MoveToDeletedItems'
                'Update'
                'Move'
                'Copy'

                # ===== PERMISSIONS & ACCESS =====
                'Add-MailboxPermission'
                'Remove-MailboxPermission'
                'Add-RecipientPermission'
                'Add-MailboxFolderPermission'
                'Set-MailboxFolderPermission'
            )
        }
    )
}
