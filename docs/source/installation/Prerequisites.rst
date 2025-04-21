Prerequisites and Permissions 
=======

System Requirements
""""""""""""""""""""""""""

**Platform Compatibility**

- **Operating System**: Windows  

  While PowerShell is available on macOS/Linux through WinRM, there are known compatibility issues.  
  A native Windows environment is strongly recommended for optimal performance.

Required PowerShell Modules
---------------------------

- **ExchangeOnlineManagement** - Required for Microsoft 365 functionalities.  

- **AzureADPreview** - Required for Entra ID functionalities.  

- **Microsoft.Graph** - Required for Graph API functionalities.  

- **Az** - Required for Azure functionalities.  

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
| Entra ID Logs             | Reports Reader                          |
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


Authentication Methods
""""""""""""""""""""""""""
Microsoft Extractor Suite supports two different authentication methods: Delegated Authentication (user-based) and Application Authentication. 

+--------------------------------+------------------------------------------+
| Delegated Authentication       | Application Authentication               |
+================================+==========================================+
| Uses a user's credentials      | Uses an app's credentials                |
+--------------------------------+------------------------------------------+
| Actions performed on behalf    | Actions performed as the application     |
| of the signed-in user          | itself                                   |
+--------------------------------+------------------------------------------+
| Limited to user's permissions  | Has its own set of permissions           |
+--------------------------------+------------------------------------------+
| Suitable for interactive       | Required for background processes and    |
| scenarios with a user present  | accessing multiple users' data           |
+--------------------------------+------------------------------------------+
| Cannot use certain permission  | Required for permissions marked as       |
| types (like Mail.ReadBasic.All)| "Application only" in permissions table  |
+--------------------------------+------------------------------------------+

.. note::
Some Microsoft Graph API permissions (like Mail.ReadBasic.All) are only available as application permissions, not as delegated permissions. This means you cannot access those resources through a regular user login, even with a Global Admin account.

Our preference
""""""""""""""""""""""""""
**An account with the required permissions**

During our investigations we often ask for a Global Reader account with Audit Log roles assigned, which can be accomplished via the following steps:

1. Create a new user account in the Microsoft 365 admin center (admin.microsoft.com)
2. Assign the new user ‘Global Reader’ role
3. Navigate to the Exchange admin center (https://admin.cloud.microsoft/exchange#/adminRoles)
4. Go to Roles and select ‘Admin roles’ and create a new role group
5. Next, select the ‘View-Only Audit Logs’ permission under the Permissions section 
6. Add the new user to this role group

**Application with the required Graph API Permissions**

1. **Register an Application**:

   a. Log in to the Azure Portal with a Global Administrator or administrator-privileged user: `https://portal.azure.com/`.  
   b. Navigate to **Microsoft Entra ID**.  
   c. Select **App registrations** and click on **New registration**.  
   d. Provide a name for the application and click on **Register**.

2. **Generate a Client Secret**:

   a. Go to the application’s **Certificates & Secrets** section.  
   b. Create a **Client Secret** and set its expiration to 1 month.  

3. **Assign API Permissions**:

   a. Navigate to the **API Permissions** section of the application.  
   b. Click **Add a permission** and assign the following **Graph API permissions** (Application permissions):  

   +---------------------------+-----------------------------------------------------+
   | Permissions               | Description                                         |
   +===========================+=====================================================+
   | Application.Read.All      | Read all applications                               |
   +---------------------------+-----------------------------------------------------+
   | AuditLog.Read.All         | Read all audit log data                             |
   +---------------------------+-----------------------------------------------------+
   | AuditLogsQuery.Read.All   | Read audit logs data from all services              |
   +---------------------------+-----------------------------------------------------+
   | Directory.Read.All        | Read directory data                                 |
   +---------------------------+-----------------------------------------------------+
   | IdentityRiskEvent.Read.All| Read all identity risk event information            |
   +---------------------------+-----------------------------------------------------+
   | IdentityRiskyUser.Read.All| Read all identity risky user information            |
   +---------------------------+-----------------------------------------------------+
   | Mail.ReadBasic.All        | Read metadata of mail in all mailboxes              |
   +---------------------------+-----------------------------------------------------+
   | Policy.Read.All           | Read your organization's policies                   |
   +---------------------------+-----------------------------------------------------+
   | UserAuthenticationMethod.Read.All | Read all users authentication methods       |
   +---------------------------+-----------------------------------------------------+
   | Policy.Read.All           | Read the conditional access policies                |
   +---------------------------+-----------------------------------------------------+
   | User.Read.All             | Read all users full profiles                        |
   +---------------------------+-----------------------------------------------------+
   | Group.Read.All            | Allows the app to list groups                       |
   +---------------------------+-----------------------------------------------------+
   | Device.Read.All           | Read all device information                         |
   +---------------------------+-----------------------------------------------------+
   | Mail.ReadWrite (optional) | Read the content of emails in all mailboxes.        |
   |                           | This method requires write permissions.             |
   |                           | Alternatively, emails can be acquired by other      |
   |                           | means.                                              |
   +---------------------------+-----------------------------------------------------+

.. note::

   The simplest method is to obtain an administrator account, which grants unrestricted access to everything needed by the Microsoft Extractor Suite.
   
   However,  it's highly recommended to adhere to the principle of least privilege. This principle suggests granting only the necessary level of access to perform specific tasks and limiting access to other functionalities to minimize the risk of unauthorized access or malicious actions. Therefore, it's best to avoid granting administrator privileges unless it's absolutely necessary to perform specific actions.
