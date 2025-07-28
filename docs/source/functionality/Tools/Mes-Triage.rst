Start-MESTriage
=======

The Start-MESTriage function performs a quick security triage for specific users across Azure, Entra ID and Microsoft 365 environments. It executes multiple data collection tasks based on customizable templates, making it ideal for incident response and security investigations.

.. note::

  **Important** : Regarding the UserIds filter:

- If you do not specify one or more user IDs, the script may take a long time to run.
- It’s strongly recommended to always filter by specific users.
- If you need to collect the full dataset, consider running each function individually—especially Get-UAL.
- Long-running executions may lead to timeouts and script errors due to dropped connections.

Why use Start-MESTriage?
^^^^^^^^^^^
Start-MESTriage automates the collection of critical security data across multiple Azure, Entra ID and Microsoft 365 services in a single operation. Instead of running individual functions separately, Start-MESTriage uses predefined templates to execute multiple tasks efficiently, providing a comprehensive security overview for specific users or the entire environment.

The function automatically discovers available templates and allows easy customization by commenting/uncommenting tasks in template files. This makes it flexible for different investigation scenarios while maintaining consistency in data collection.

Available Templates
^^^^^^^^^^^
Start-MESTriage includes three built-in templates:

**Quick Template**
- Fastest execution, essential data only
- Focuses on high-priority security indicators
- Ideal for initial threat assessment

**Standard Template** (Default)
- Balanced approach between speed and comprehensiveness
- Covers most common investigation requirements
- Recommended for typical security incidents

**Comprehensive Template**
- Extensive data collection across all available functions
- Includes nearly everything available in the toolkit
- Best for thorough investigations

**Custom Templates**
- Users can create custom templates by adding .psd1 files to the Templates folder
- Templates can be easily customized by commenting/uncommenting specific tasks
- Allows organizations to create standardized investigation procedures

Execute Start-MESTriage
^^^^^^^^^^^

Usage
""""""""""""""""""""""""""
Running the script with minimal parameters performs a standard triage for a specific user:
::

    Start-MESTriage -Template Standard -TriageName "Investigation001" -UserIds "user@domain.com"

Perform a quick triage for multiple users:
::

    Start-MESTriage -Template Quick -TriageName "QuickCheck" -UserIds "user1@domain.com,user2@domain.com"

Execute a comprehensive triage with custom date range:
::

    Start-MESTriage -Template Comprehensive -TriageName "FullInvestigation" -UserIds "user@domain.com" -StartDate "2025-06-01" -EndDate "2025-06-30"

Run triage for all users in the environment:
::

    Start-MESTriage -Template Standard -TriageName "OrgWide" -StartDate "2025-06-01" -EndDate "2025-06-30"

Custom output directory and format:
::

    Start-MESTriage -Template Standard -TriageName "Investigation" -UserIds "user@domain.com" -OutputDir "C:\Investigations" -Output JSON

Parameters
""""""""""""""""""""""""""
-Template (optional)
    - Template to use for the triage operation.
    - Available templates are automatically discovered from the Templates folder.
    - Built-in options: Quick, Standard, Comprehensive
    - Custom templates: Any .psd1 file in the Templates folder
    - Default: Standard

-TriageName (mandatory)
    - TriageName is the mandatory parameter specifying the name of the triage project.
    - This will be used as the folder name for outputs.
    - Creates organized output structure for investigation tracking.

-UserIds (optional)
    - UserIds parameter specifying the target users for the triage.
    - You can enter multiple email addresses separated by commas.
    - If not specified, applies to all users (where applicable for each task).

-StartDate (optional)
    - StartDate parameter specifying the start date for time-based queries.
    - Default: Today -90 days

-EndDate (optional)
    - EndDate parameter specifying the end date for time-based queries.
    - Default: Now

-Output (optional)
    - Output format for the generated files.
    - Options: CSV, JSON, JSONL and SOF-ELK
    - Note: Some tasks automatically use JSON format regardless of this setting.
    - Default: CSV

-OutputDir (optional)
    - OutputDir parameter specifying the output directory.
    - If not specified, creates Output\[TriageName]
    - Default: Output\[TriageName]

-Encoding (optional)
    - Encoding parameter specifying the encoding of the output files.
    - Default: UTF8

-LogLevel (optional)
    - Specifies the level of logging for the triage operation.
    - None: No logging
    - Minimal: Critical errors only
    - Standard: Normal operational logging
    - Debug: Verbose logging for debugging purposes
    - Default: Minimal

.. note::

  **Important note** regarding the StartDate and EndDate variables.

- When you do not specify a timestamp, the script will automatically default to midnight (00:00) of that day.
- If you provide a timestamp, it will be converted to the corresponding UTC time. For example, if your local timezone is UTC+2, a timestamp like 2025-01-01 08:15:00 will be converted to 2025-01-01 06:15:00 in UTC.
- To specify a date and time without conversion, please use the ISO 8601 format with UTC time (e.g., 2025-01-01T08:15:00Z).

Output
""""""""""""""""""""""""""
The output will be saved to the specified OutputDir, organized by task type. Each triage creates:
- Individual task outputs in their respective subdirectories

Available Tasks in Templates
""""""""""""""""""""""""""
Start-MESTriage can execute the following tasks based on template configuration:

**User related**
- Get-Users: User creation dates and password changes
- Get-AdminUsers: Administrator directory roles and assignments
- Get-MFA: Multi-factor authentication status for all users
- Get-RiskyUsers: Users flagged by Entra ID Identity Protection
- Get-RiskyDetections: Risk detections from Identity Protection

**Sign-in, Audit, Unified Audit Log and Activity Logs**
- Get-UAL: Unified Audit Logs from Microsoft 365
- Get-UALStatistics: Statistics on available audit log data
- Get-GraphEntraSignInLogs: Sign-in logs via Graph API
- Get-GraphEntraAuditLogs: Audit logs via Graph API
- Get-MailboxAuditLog: Exchange mailbox audit logs
- Get-ActivityLogs: Azure activity logs
- Get-DirectoryActivityLogs: Directory service activity logs

**Email related**
- Get-MailboxRules: Mailbox rules that could indicate compromise
- Get-MailboxAuditStatus: Audit configuration for mailboxes
- Get-MailboxPermissions: Mailbox delegation and permissions
- Get-MessageTraceLog: Email message trace logs
- Get-TransportRules: Exchange transport rule configurations

**Applications and Permissions**
- Get-OAuthPermissionsGraph: OAuth application permissions
- Get-ConditionalAccessPolicies: Conditional access policy configurations

**Device and Groups**
- Get-Devices: Device registration and compliance information
- Get-Groups: Group configurations and memberships
- Get-GroupMembers: Detailed group membership information
- Get-DynamicGroups: Dynamic group configurations

**Alerts, licenses and roles**
- Get-SecurityAlerts: Security alerts from Microsoft Defender
- Get-PIMAssignments: Privileged Identity Management assignments
- Get-AllRoleActivity: Administrative role activity logs
- Get-Licenses: License assignments and configurations
- Get-LicenseCompatibility: License compatibility analysis
- Get-EntraSecurityDefaults: Security defaults configuration

**Custom Operations**
- UALOperations: Custom Unified Audit Log operations based on specific activities

Template Customization
""""""""""""""""""""""""""
Templates are PowerShell data files (.psd1) that define which tasks to execute. You can:

1. **Modify existing templates**: Comment/uncomment tasks to customize execution
2. **Create new templates**: Add new .psd1 files to the Templates directory
3. **Define custom UAL operations**: Specify particular activities to search for

Example template structure:
::

    @{
        Tasks = @(
            'Get-Users',
            'Get-AdminUsers',
            'Get-MFA',
            @{
                Task = 'UALOperations'
                Operations = @('New-InboxRule', 'Set-InboxRule', 'Remove-InboxRule')
            }
        )
    }

Task Execution Logic
""""""""""""""""""""""""""
Start-MESTriage intelligently handles task execution:

- **User-specific tasks**: When UserIds are provided, filters data to specified users
- **Organization-wide tasks**: Some tasks automatically skip when UserIds are specified (e.g., Get-TransportRules)
- **Error handling**: Failed tasks don't stop execution; summary shows all results
- **Progress tracking**: Real-time status updates for each task
- **Output organization**: Results are organized in logical directory structures

Permissions Requirements
""""""""""""""""""""""""""
The specific connections and permissions required depend on your selected template and the tasks it includes. Tasks that require Microsoft Graph will fail if Connect-MgGraph hasn't been established, and Exchange-related tasks will fail without Connect-ExchangeOnline.
For detailed permissions requirements for each specific function, please refer to the Prerequisites and Permissions section of the documentation, which contains a comprehensive table mapping each functionality to its required roles and permissions.

Required Connections:
""""""""""""""""""""""""""
**Microsoft Graph Connection (Connect-MgGraph):**
Required for most Entra ID and Microsoft 365 related tasks including user information, audit logs, risk detections, and MFA status.

**Exchange Online Connection (Connect-ExchangeOnline):**
Required for Exchange-specific tasks including Unified Audit Logs, mailbox rules, mailbox permissions, message trace logs, and transport rules.

Key permissions needed:
- Exchange administrator or equivalent for mailbox operations
- Security administrator for audit log access
- View-Only Audit Logs or Audit Logs role for UAL access