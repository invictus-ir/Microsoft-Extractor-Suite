Prerequisites and Permissions Guide
=======

System Requirements
""""""""""""""""""""""""""

**Platform Compatibility**

- **Operating System**: Windows only  
  While PowerShell is available on macOS/Linux through WinRM, there are known compatibility issues.  
  A native Windows environment is strongly recommended for optimal performance.

Required PowerShell Modules
---------------------------

- **ExchangeOnlineManagement**  
  Required for Microsoft 365 functionalities.  
  Handles Exchange Online operations.

- **AzureADPreview**  
  Required for Entra ID functionalities.  
  Provides advanced directory management capabilities.

- **Microsoft.Graph**  
  Required for Graph API functionalities.  
  Enables modern API access to Microsoft 365 services.

- **Az**  
  Required for Azure Activity log functionality.  
  Provides comprehensive Azure management capabilities.

Initial Setup
-------------
- A Microsoft 365 account with appropriate audit logging privileges.
- An admin account is required for initial Graph API scope consent (first-time setup only).
- PowerShell Execution Policy to allow execution of scripts, set the PowerShell execution policy:
::

   Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser

Permissions
""""""""""""""""""""""""""
An account is needed with sufficient permissions to collect the mentioned logs. This action is often
overlooked and forgotten until collection is attempted. Requesting and implementing the correct
permissions is necessary.

Each functionality requires one of the following permissions:

+---------------------------+-----------------------------------------+
| Functionality             | Roles needed                            |
+===========================+=========================================+
| Unified Audit Log         | AuditLogs                               |
|                           +-----------------------------------------+
|                           | AuditLogsQuery.Read.All                 |
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
| Mailbox Audit Status      | Exchange Administrator                  |
|                           +-----------------------------------------+
|                           | View-Only Organization Management       |
|                           +-----------------------------------------+
|                           | View-Only Audit Logs                    |
+---------------------------+-----------------------------------------+
| Mailbox Delegated         | Exchange Administrator                  |
| Permissions               +-----------------------------------------+
|                           | View-Only Recipients                    |
|                           +-----------------------------------------+
|                           | View-Only Configuration                 |
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
| MFA information           | UserAuthenticationMethod.Read.All       |
|                           +-----------------------------------------+
|                           | User.Read.All                           |
+---------------------------+-----------------------------------------+
| Conditional Access Policy | Policy.Read.All                         |
+---------------------------+-----------------------------------------+
| Risky users/detections    | IdentityRiskEvent.Read.All              |
+---------------------------+-----------------------------------------+
| E-mails/Attachments       | Mail.Read                               |
|                           +-----------------------------------------+
|                           | Mail.Readwrite (Application only)       |
+---------------------------+-----------------------------------------+
| User/Admin information    | User.Read.All                           |
|                           +-----------------------------------------+
|                           | Directory.AccessAsUser.All              |
|                           +-----------------------------------------+
|                           | User.ReadBasic.all                      |
|                           +-----------------------------------------+
|                           | Directory.Read.All                      |
+---------------------------+-----------------------------------------+
| Device information        | Device.Read.All                         |
|                           +-----------------------------------------+
|                           | Directory.Read.All                      |
+---------------------------+-----------------------------------------+
| Group information         | Group.Read.All                          |
|                           +-----------------------------------------+
|                           | Directory.Read.All                      |
+---------------------------+-----------------------------------------+
| License information       | Organization.Read.All                   |
|                           +-----------------------------------------+
|                           | Directory.Read.All                      |
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
