Installation
=======

Install the Microsoft-Extractor-Suite toolkit:
::

   Install-Module -Name Microsoft-Extractor-Suite

Install the Powershell module Microsoft.Graph for the Graph API functionalities:
::

   Install-Module -Name Microsoft.Graph

Install the Powershell module ExchangeOnlineManagement for the Microsoft 365 functionalities:
::

   Install-Module -Name ExchangeOnlineManagement

Install the Powershell module Az for the Azure Activity log functionality:
::

   Install-Module -Name Az

Install the Powershell module AzureADPreview for the Entra ID functionalities:
::

   Install-Module -Name AzureADPreview

.. note::

   If you receive an error message indicating that the specified commands already exist on your system, you can resolve the issue by including the "-AllowClobber" parameter in the "Install-Module" command. This parameter will allow the installation process to overwrite any existing versions of the module and replace them with the newer version.

 
Getting Started
-------
To get started with the Microsoft Extractor Suite tool, make sure the requirements are met.

The first step is to import or install the Microsoft-Extractor-Suite.

To import the Microsoft-Extractor-Suite:
::

   Import-Module .\Microsoft-Extractor-Suite.psd1
   
To install the Microsoft-Extractor-Suite:
::

   Install-Module -Name Microsoft-Extractor-Suite


Authentication Options
"""""""""""""""""""""
Before using Microsoft-Extractor-Suite functions, you must authenticate to Microsoft 365 or Azure. There are two primary authentication methods available:

1. User Authentication (Delegated Permissions):
   
   - Uses your user credentials and permissions
   - Suitable for interactive use and accessing your own resources
   - Uses the intersection of your permissions and the app's permissions

2. Application Authentication (App Permissions):

   - Uses an Azure AD registered application with its own permissions
   - Required for accessing organization-wide resources (like multiple mailboxes)
   - Necessary for certain API operations like Mail.ReadBasic.All
   - No user context is present

Basic User Authentication
""""""""""""""""""""""""
For simple scenarios where you only need to access resources the signed-in user has access to:

**Connect to Exchange Online (Microsoft 365)**:
::

   Connect-M365
   
   # Or alternatively
   Connect-ExchangeOnline

**Connect to Azure AD**:
::

   Connect-Azure
   
   # Or alternatively
   Connect-AzureAD

**Connect to Azure Resource Manager**:
::

   Connect-AzureAZ
   
   # Or alternatively
   Connect-AzAccount


Application Authentication
"""""""""""""""""""""""""

For scenarios requiring application permissions (e.g., accessing multiple users' mailboxes or certain APIs):

1. Register an application in Entra
2. Grant necessary permissions and admin consent
3. Connect using application credentials:

   ::

      # Store your application details
      $TenantId = "your-tenant-id"
      $ApplicationId = "App Id"
      $SecuredPassword = "Secret"

      $SecuredPasswordPassword = ConvertTo-SecureString -String $SecuredPassword -AsPlainText -Force
      $ClientSecretCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $ApplicationId, $SecuredPasswordPassword
      
      Connect-MgGraph -TenantId $tenantID -ClientSecretCredential $ClientSecretCredential -NoWelcome

.. note::

   Some Microsoft Extractor Suite functions require specific permission types (delegated or application).
   Refer to the "Authentication Methods" section for detailed guidance on when to use each authentication type.