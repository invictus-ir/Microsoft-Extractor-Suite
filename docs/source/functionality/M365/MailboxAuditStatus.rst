
Retrieve Mailbox Audit Status
=======
Retrieves audit status and settings for all mailboxes in Microsoft 365, including detailed information about mailbox audit settings, audit status, bypass settings, and configured audit actions for owners, delegates, and administrators.

Usage
""""""""""""""""""""""""""
Running the script without any parameters retrieves audit status for all mailboxes and exports to a CSV file in the default directory.
::

Get-MailboxAuditStatus

Retrieves audit status for all mailboxes and exports the output to a CSV file with UTF-32 encoding.
::

Get-MailboxAuditStatus -Encoding utf32

Retrieves audit status for all mailboxes and saves the output to the C:\Temp folder.
::

Get-MailboxAuditStatus -OutputDir C:\Temp

Parameters
""""""""""""""""""""""""""
-OutputDir (optional)
    - OutputDir is the parameter specifying the output directory.
    - Default: Output\Audit Status

-Encoding (optional)
    - Encoding is the parameter specifying the encoding of the CSV output file.
    - Default: UTF8

-LogLevel (optional)
    - Specifies the level of logging. None: No logging. Minimal: Logs critical errors only. Standard: Normal operational logging. Debug: Detailed logging for debugging.
    - Default: Standard

-UserIds (optional)
    - UserIds is the UserIds parameter filtering the log entries by the account of the user who performed the actions.

Output
""""""""""""""""""""""""""
The output will be saved to the 'Audit Status' directory within the 'Output' directory. The script provides:

A CSV file containing detailed audit information for each mailbox:

* UserPrincipalName
* DisplayName
* AuditEnabled status
* AuditBypassEnabled status
* OwnerAuditActions
* DelegateAuditActions
* AdminAuditActions

Permissions
""""""""""""""""""""""""""
Before using this function, it is essential to have the appropriate permissions. This function requires a connection to Exchange Online PowerShell with one of the following roles:

- MailTips Management
- Organization Configuration
- View-Only Configuration

These roles are included as part of some administrator roles, such as:

- Global Administrator
- Exchange Administrator
- Compliance Administrator (for view-only configurations)
- Global Reader 

Ensure that you are connected to Microsoft 365 by running the Connect-M365 or Connect-ExchangeOnline command with the required administrative privileges before executing this script. Without the correct roles assigned, the function will not execute successfully.