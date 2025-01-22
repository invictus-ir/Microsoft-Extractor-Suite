.. image:: /Images/Invictus-Incident-Response.jpg
   :alt: Invictus logo
   
Microsoft-Extractor-Suite documentation!
===================================

**Microsoft-Extractor-Suite** is a fully-featured, actively-maintained, Powershell tool designed to streamline the process of collecting all necessary data and information from various sources within Microsoft.

.. note::

   🆘 Incident Response support reach out to cert@invictus-ir.com or go to https://www.invictus-ir.com/24-7-emergency-response

Supported sources
-------

===================================== =========================================================================================================================================================================== 
  Source                                Description                                                                                                                                                                
===================================== =========================================================================================================================================================================== 
  Unified Audit Log                     The unified audit log contains user, group, application, domain, and directory activities performed in the Microsoft 365 admin center or in the Azure management portal.   
  Admin Audit Log                       Administrator audit logging records when a user or administrator makes a change in your organization (in the Exchange admin center or by using cmdlets).                   
  Mailbox Audit Log                     Mailbox audit logs are generated for each mailbox that has mailbox audit logging enabled. This tracks all user actions on any items in a mailbox.                          
  Message Trace Log                     The message tracking log contains messages as they pass through the organization.                                                                                          
  OAuth Permissions                     OAuth is a way of authorizing third-party applications to login into user accounts.                                                                                        
  Inbox Rules                           Inbox rules process messages in the inbox based on conditions and take actions such as moving a message to a specified folder or deleting a message.                       
  Transport Rules                       Transport rules take action on messages while they're in transit.                                                                                                          
  Entra ID sign-in log                  Gets the Entra ID Sign-In log.                                                                                                                               
  Entra ID Audit Log                    Gets the Entra ID Audit log.  
  Azure Activity Log                    Gets the Azure Activity log.     
  Azure Directory Activity Log          Gets the Azure Directory Activity log.                                                                                                     
===================================== =========================================================================================================================================================================== 

Retrieve other relevant information
-------

===================================== =========================================================================================================================================================================== 
  Source                                Description                                                                                                                                                                
===================================== =========================================================================================================================================================================== 
  MFA                                   Retrieves the MFA status for all users.   
  User Information                      Retrieves the creation time and date of the last password change for all users.                  
  Risky Users                           Retrieves the risky users.                         
  Risky Detections                      Retrieves the risky detections from the Entra ID Identity Protection.                                                                                      
  Conditional Access Policies           Retrieves all the conditional access policies.                                                                                        
  Admin Users/Roles                     Retrieves Administrator directory roles, including the identification of users associated with each specific role.                      
  E-mails                               Get a specific email.                                                                                                          
  Attachments                           Get a specific attachment.                                                                                                                                                                                                                                          
  Devices                               Retrieves information about all devices registered in Azure AD/Entra ID. 
  Delegated Permissions                 Retrieves delegated permissions for all mailboxes in Microsoft 365.
  Audit Log Settings                    Retrieves audit status and settings for all mailboxes in Microsoft 365.
  Group Information                     Variety of functions designed to gather information about groups.
  License Information                   Variety of functions designed to gather information about licenses.
===================================== =========================================================================================================================================================================== 

Getting Started
-------
To get started with the Microsoft-Extractor-Suite tool, make sure the requirements are met. If you do not have the **Connect-ExchangeOnline** or/and **Connect-AzureAD** installed check
the installation page.

Install the Microsoft-Extractor-Suite toolkit:
::

   Install-Module -Name Microsoft-Extractor-Suite

To import the Microsoft-Extractor-Suite:
::

   Import-Module .\Microsoft-Extractor-Suite.psd1

To import the Microsoft-Extractor-Suite without the logo output:
::

   Import-Module .\Microsoft-Extractor-Suite.psd1 -ArgumentList $true

Additionally, you must sign-in to Microsoft 365 or Azure depending on your usage before M365-Toolkit functions are made available. To sign in, use the cmdlets:
::

   Connect-M365 or Connect-ExchangeOnline
   Connect-Azure or Connect-AzureAD
   Connect-AzureAZ or Connect-AzAccount

Getting Help
------------

Have a bug report or feature request? Open an issue on the Github repository.

.. toctree::
   :maxdepth: 2
   :hidden:
   :caption: Installation

   installation/Prerequisites
   installation/Installation

.. toctree::
   :maxdepth: 2
   :hidden:
   :caption: Microsoft 365 functionalities

   functionality/M365/UnifiedAuditLog
   functionality/M365/UnifiedAuditLogGraph
   functionality/M365/AdminAuditLog
   functionality/M365/MailboxAuditLog
   functionality/M365/MessageTraceLog
   functionality/M365/InboxRules
   functionality/M365/TransportRules
   functionality/M365/MailItemsAccessed
   functionality/M365/GetEmails
   functionality/M365/MailboxAuditStatus
   functionality/M365/MailboxDelegatedPermissions

.. toctree::
   :maxdepth: 2
   :hidden:
   :caption: Azure & Entra ID functionalities

   functionality/Azure/AzureActiveDirectorysign-inlogs
   functionality/Azure/AzureActiveDirectoryAuditLog
   functionality/Azure/AzureActivityLogs
   functionality/Azure/AzureDirectoryActivityLogs
   functionality/Azure/AzureSignInLogsGraph
   functionality/Azure/AzureAuditLogsGraph
   functionality/Azure/ConditionalAccessPolicies
   functionality/Azure/Devices
   functionality/Azure/OAuthPermissions
   functionality/Azure/GetUserInfo
   functionality/Azure/GetGroups
   functionality/Azure/ProductLicenses

.. toctree::
   :maxdepth: 2
   :hidden:
   :caption: Additional Tools

   functionality/Tools/EvidenceCollection

.. toctree::
   :maxdepth: 2
   :hidden:
   :caption: Project

   project/Aboutus
   project/FAQ
   project/KnownErrors