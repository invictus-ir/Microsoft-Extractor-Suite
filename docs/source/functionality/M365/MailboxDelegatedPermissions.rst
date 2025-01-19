Retrieve Mailbox Delegated Permissions
=======
Retrieves detailed information about mailbox delegated permissions, including Full Access, Send As, Send on Behalf, Calendar permissions, and Inbox permissions for all mailboxes in Microsoft 365.

Usage
""""""""""""""""""""""""""
Running the script without any parameters retrieves delegated permissions for all mailboxes and exports to a CSV file in the default directory.
::

Get-MailboxPermissions

Retrieves delegated permissions and saves the output to C:\Temp with UTF-32 encoding.
::

Get-MailboxPermissions -OutputDir C:\Temp -Encoding UTF32

Retrieves delegated permissions and saves the report in the Reports folder with UTF-8 encoding.
::

Get-MailboxPermissions -OutputDir "Reports" -Encoding UTF8

Parameters
""""""""""""""""""""""""""
-OutputDir (optional)
    - OutputDir is the parameter specifying the output directory.
    - Default: Output\Delegated Permissions

-Encoding (optional)
    - Encoding is the parameter specifying the encoding of the CSV output file.
    - Default: UTF8

-LogLevel (optional)
    - Specifies the level of logging. None: No logging. Minimal: Logs critical errors only. Standard: Normal operational logging.
    - Default: Standard

-UserIds (optional)
    - UserIds is the UserIds parameter filtering the log entries by the account of the user who performed the actions.

Output
""""""""""""""""""""""""""
The output will be saved to the 'Delegated Permissions' directory within the 'Output' directory. The script provides:
A CSV file containing detailed delegation information for each mailbox:

*   UserPrincipalName
*   DisplayName
*   FullAccessUsers (users with full access to the mailbox)
*   FullAccessPermissions (detailed access rights and settings)
*   SendAsUsers (users with Send As permissions)
*   SendAsPermissions (detailed Send As rights and settings)
*   SendOnBehalfUsers (users with Send on Behalf permissions)
*   CalendarUsers (users with Calendar access)
*   CalendarPermissions (detailed Calendar access rights)
*   InboxUsers (users with Inbox access)
*   InboxPermissions (detailed Inbox access rights)
*   Permission Counts

Permissions
""""""""""""""""""""""""""
Before using this script, it is essential to ensure that the appropriate permissions are granted. The following cmdlets require specific management roles in Exchange Online PowerShell:

Cmdlet: Get-MailboxPermission Required Role(s):
- Mail Recipients
- View-Only Recipients

Cmdlet: Get-RecipientPermission Required Role(s):
- Mail Recipients

Cmdlet: Get-MailboxFolderPermission Required Role(s):
- Mail Recipients
- Mailbox Search
- MyBaseOptions
- View-Only Recipients

These roles are included as part of some administrator roles, such as:

- Global Administrator
- Exchange Administrator
- Compliance Administrator (for view-only configurations)
- Global Reader 

Make sure you are connected to Microsoft 365 by running the Connect-M365 or Connect-ExchangeOnline command before executing this script.

.. note::

  The script automatically filters out system accounts and inherited permissions to focus on explicitly assigned delegations.