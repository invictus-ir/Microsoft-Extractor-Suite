Prerequisites
=======

1. The tool only supports PowerShell on Windows. While it is possible to use PowerShell on MacOS/Linux  through WinRM, there are known issues that can cause issues.

2. Powershell module: Connect-ExchangeOnline

3. Powershell module: Connect-AzureADPreview

4. Microsoft 365 account with privileges to access/extract audit logging.

5. Check if the Unified Audit Log has been activated.

6. Ensure that your PowerShell Execution Policy is configured to "Unrestricted".

::

   Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser

Permissions
""""""""""""""""""""""""""
An account is needed with sufficient permissions to collect the mentioned logs. This action is often
overlooked and forgotten until collection is attempted. Requesting and implementing the correct
permissions is necessary to avoid these setbacks.

Each functionality requires one of the following permissions:

+---------------------------+-----------------------------------------+
| Functionality             | Roles needed                            |
+===========================+=========================================+
| Unified Audit Log         | AuditLogs                               |
+---------------------------+-----------------------------------------+
| Admin Audit Log           | AuditLogs                               |
+---------------------------+-----------------------------------------+
| Inbox rules               | MailRecipients                          |
|                           +-----------------------------------------+
|                           | MyBaseOptions                           |
|                           +-----------------------------------------+
|                           | UserOptions                             |
|                           +-----------------------------------------+
|                           | ViewOnlyRecipients                      |
+---------------------------+-----------------------------------------+
| Transport rule            | DataLossPrevention                      |
|                           +-----------------------------------------+
|                           | O365SupportViewConfig                   |
|                           +-----------------------------------------+
|                           | SecurityAdmin                           |
|                           +-----------------------------------------+
|                           | SecurityReader                          |
|                           +-----------------------------------------+
|                           | TransportRules                          |
|                           +-----------------------------------------+
|                           | ViewOnlyConfiguration                   |
+---------------------------+-----------------------------------------+
| Message Trace Log         | ComplianceAdmin                         |
|                           +-----------------------------------------+
|                           | DataLossPrevention                      |
|                           +-----------------------------------------+
|                           | SecurityAdmin                           |
|                           +-----------------------------------------+
|                           | SecurityReader                          |
|                           +-----------------------------------------+
|                           | ViewOnlyRecipients                      |
+---------------------------+-----------------------------------------+
| Azure AD Logs             | Reports Reader                          |
|                           +-----------------------------------------+
|                           | Security Reader                         |
|                           +-----------------------------------------+
|                           | Security Administrator                  |
|                           +-----------------------------------------+
|                           | Global Reader (sign-in logs only)       |
|                           +-----------------------------------------+
|                           | Global Administrator                    |
+---------------------------+-----------------------------------------+

Our preference
""""""""""""""""""""""""""
During our investigations we often ask for a Global Reader account with Audit Log roles assigned, which can be accomplished via the following steps:

1. Create a new user account in the Microsoft 365 admin center (admin.microsoft.com)
2. Assign the new user ‘Global Reader’ role
3. Go to Roles and select ‘Exchange’ and create a new role group
4. Next, select the ‘Unified Audit’ role and go to ‘Permissions’ and select the ‘View-Only Audit Logs’ permission
5. Add the new user to this role group

.. note::

   The simplest method is to obtain an administrator account, which grants unrestricted access to everything needed by the tool.
   
   However,  it's highly recommended to adhere to the principle of least privilege. This principle suggests granting only the necessary level of access to perform specific tasks and limiting access to other functionalities to minimize the risk of unauthorized access or malicious actions. Therefore, it's best to avoid granting administrator privileges unless it's absolutely necessary to perform specific actions.
