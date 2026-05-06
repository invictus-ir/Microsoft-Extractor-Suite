Inbox Rules
=======
Inbox rules process messages in the inbox based on conditions and take actions such as moving a message to a specified folder or deleting a message.

Show mailbox rules
^^^^^^^^^^^
**Show-MailboxRules** shows the mailbox rules in your organization.

Usage
""""""""""""""""""""""""""
Show all mailbox rules in your organization:
::

   Show-MailboxRules

Show the mailbox rules for the users test[@]invictus-ir.com and HR[@]invictus-ir.com:
::

   Show-MailboxRules -UserIds "HR@invictus-ir.com,test@Invictus-ir.com"

Parameters
""""""""""""""""""""""""""
-UserIds (optional)
    - UserIds is the UserIds parameter filtering the log entries by the account of the user who performed the actions.

Get mailbox rules
^^^^^^^^^^^
**Get-MailboxRules** collects all the mailbox rules in your organization.

Usage
""""""""""""""""""""""""""
Get all mailbox rules in your organization:
::

   Get-MailboxRules

Get the mailbox rules for the user test[@]invictus-ir.com:
::

    Get-MailboxRules -UserIds Test@Invictus-ir.com

Get the mailbox rules for the users test[@]invictus-ir.com and HR[@]invictus-ir.com:
::

   Get-MailboxRules -UserIds "HR@invictus-ir.com,test@Invictus-ir.com"

Parameters
""""""""""""""""""""""""""
-UserIds (optional)
    - UserIds is the UserIds parameter filtering the log entries by the account of the user who performed the actions.

-OutputDir (optional)
    - OutputDir is the parameter specifying the output directory.
    - Default: Output\Rules

-Encoding (optional)
    - Encoding is the parameter specifying the encoding of the CSV output file.
    - Default: UTF8

-LogLevel (optional)
    - Specifies the level of logging. None: No logging. Minimal: Logs critical errors only. Standard: Normal operational logging. Debug: Detailed logging for debugging.
    - Default: Standard

Output
""""""""""""""""""""""""""
The output will be saved to the 'Rules' directory within the 'Output' directory, with the file name format: [date]-MailboxRules.csv

Get Inbox Rules (Graph API)
^^^^^^^^^^^
**Get-MailboxRulesGraph** retrieves mailbox inbox rules for all users or a specific user using the Microsoft Graph API. This function only requires Graph API access and does not rely on Exchange Online PowerShell.

Usage
""""""""""""""""""""""""""
Retrieve inbox rules for all users in the tenant:
::

   Get-MailboxRulesGraph

Retrieve inbox rules for a specific user:
::

   Get-MailboxRulesGraph -UserIds "HR@invictus-ir.com"

Parameters
""""""""""""""""""""""""""
-UserIds (optional)
    - UserIds is the parameter specifying a single user UPN or ID to filter results.
    - Default: All enabled users with Exchange licenses will be included if not specified.

-OutputDir (optional)
    - OutputDir is the parameter specifying the output directory.
    - Default: Output\Rules

-Encoding (optional)
    - Encoding is the parameter specifying the encoding of the CSV output file.
    - Default: UTF8

-LogLevel (optional)
    - Specifies the level of logging. None: No logging. Minimal: Logs critical errors only. Standard: Normal operational logging. Debug: Detailed logging for debugging.
    - Default: Standard

Output
""""""""""""""""""""""""""
The output will be saved to the 'Rules' directory within the 'Output' directory, with the file name format: [date]-MailboxRulesGraph.csv

The CSV file contains the following fields for each rule:

* UserPrincipalName
* RuleName
* Sequence
* Enabled
* ForwardTo
* RedirectTo
* ForwardAsAttachment
* Delete
* PermanentDelete
* MoveToFolder
* StopProcessingRules
* MarkAsRead
* From
* SubjectContains
* BodyContains
* HasAttachments
* IsImportant
* RuleId

Permissions
""""""""""""""""""""""""""
This function relies on the Microsoft Graph API. To enumerate inbox rules for all users in the tenant, the following permissions are required at the **Application** level. Delegated permissions only let the signed-in user read their own
mailbox settings and will not work for tenant-wide collection.

- User.Read.All
- MailboxSettings.Read

Your command would look like this: Connect-MgGraph -Scopes 'User.Read.All','MailboxSettings.Read'
