@{
    Name = "Default Security Investigation"
    Description = "Balanced acquisition covering key data sources needed for an investigation. Note: Execution time varies significantly, moderate with specific users, extended when analyzing all users."

    # Enable/Disable tasks by commenting/uncommenting lines with #
    # To enable a task: Remove the # at the beginning of the line
    # To disable a task: Add # at the beginning of the line
    
    Tasks = @(
        # ===== Tasks (ENABLED BY DEFAULT) =====
        "Get-RiskyUsers"                 # Get risky users from Entra ID
        "Get-RiskyDetections"            # Get risk detection events  
        "Get-MFA"                        # Collect MFA status for users
        "Get-MailboxRules"               # Export mailbox rules
        "Get-OAuthPermissionsGraph"      # Collect OAuth application permissions via Graph API

        # ===== Sign-In & Audit Logging (ENABLED FOR DEFAULT) =====
        "Get-GraphEntraSignInLogs"       # Collect sign-in logs
        "Get-GraphEntraAuditLogs"        # Collect audit logs

        # ===== Unified Audit Log (ENABLED FOR DEFAULT) =====
        # "Get-UAL"                      # Collect all Unified Audit Logs (NOT RECOMMENDED FOR ALL USERS)
        # "Get-UALStatistics"            # Displays the total number of logs within the Unified Audit Logs per Record Type
        # "Get-MailboxAuditLog"          # Collect Mailbox Audit Logs

        # ===== Message Tracking (UNCOMMENT TO ENABLE) =====
        "Get-MessageTraceLog"            # Collect message tracking logs

        # ===== Activity Logging (UNCOMMENT TO ENABLE) =====
        # "Get-ActivityLogs"             # Collect activity logs

        # ===== User Related (ENABLED FOR DEFAULT) =====
        "Get-Users"                      # Collect user information
        "Get-AdminUsers"                 # Collect users with administrative privileges

        # ===== Device Management (UNCOMMENT TO ENABLE) =====
        "Get-Devices"                    # Collect device registration information

        # ===== Permissions and Audit Settings (ENABLED FOR DEFAULT) =====
        "Get-MailboxAuditStatus"         # Collect the mailbox audit configurations
        "Get-MailboxPermissions"         # Collect delegated mailbox permissions

        # ===== TENANT-WIDE / ALL USERS ONLY (UNCOMMENT TO ENABLE) =====
        # NOTE: These tasks only work when no specific users are targeted (all users mode)
        "Get-SecurityAlerts"              # Retrieve security alerts
        "Get-TransportRules"              # Export transport rules
        "Get-ConditionalAccessPolicies"   # Collect conditional access policies
        "Get-Licenses"                    # Collect all licenses in the tenant with retention times
        # "Get-LicenseCompatibility"      # Check presence of E5, P2, P1, and E3 licenses
        # "Get-EntraSecurityDefaults"     # Check status of Entra ID security defaults
        # "Get-LicensesByUser"            # Collect license assignments for all users
        # "Get-Groups"                    # Collect all groups in the organization
        # "Get-GroupMembers"              # Collect all members of each group
        # "Get-DynamicGroups"             # Collect all dynamic groups and membership rules
        # "Get-DirectoryActivityLogs"     # Collect directory activity logs
        # "Get-PIMAssignments"            # Generate report of all Entra ID PIM role assignments
        # "Get-AllRoleActivity"           # Export all directory role memberships with last login info
                
        # ===== UNIFIED AUDIT LOG (ENABLED BY DEFAULT) =====
        @{
            Task = "UALOperations"
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
                'UpdateInboxRules'
                
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
                
                # ===== AUTHENTICATION & IDENTITY =====
                'UserLoggedIn'
                'UserLoginFailed'
                'UserStrongAuthClientAuthNRequired'
                'UserStrongAuthClientAuthNRequiredInterrupt'
                'UserPasswordChanged'
                
                # ===== APPLICATIONS & CONSENT =====
                'ApplicationConsent'
                'Consent to application'
                'Add OAuth2PermissionGrant'
                'Add app role assignment grant to user'
                'Add delegated permission grant'
                'Add application'
                'Add service principal'
                'Add owner to application'
                
                # ===== FILE & SHAREPOINT ACTIVITIES =====
                'FileAccessed'
                'FileDownloaded'
                'FileUploaded'
                'FileCopied'
                'FileDeleted'
                'SharingSet'
                'SharingRevoked'
                'AddedToSecureLink'
                'RemovedFromSecureLink'
                
                # ===== SEARCH & EDISCOVERY =====
                'SearchQueryInitiated'
                'SearchQueryPerformed'
                'New-ComplianceSearch'
                'SearchExportDownloaded'
                'ViewedSearchExported'
                
                # ===== ADMINISTRATIVE ACTIVITIES =====
                'Add user'
                'Delete user'
                'Update user'
                'Add member to group'
                'Remove member from group'
                'Added member to role'
                'Remove member from role'
                'Set-AdminAuditLogConfig'
                
                # ===== SECURITY & COMPLIANCE =====
                'AlertTriggered'
                'AlertEntityGenerated'
                'CaseAdded'
                'ThreatIntelligenceAtpFile'
                
                # ===== POWER AUTOMATE =====
                'CreateFlow'
                'PutConnection'
                'HygieneTenantEvents'
            )
        }
    )
}