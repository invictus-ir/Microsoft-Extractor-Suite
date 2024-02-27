.. image:: /Images/Invictus-Incident-Response.jpg
   :alt: Invictus logo
   
Microsoft-Extractor-Suite documentation!
===================================

**Microsoft-Extractor-Suite** is a fully-featured, actively-maintained, Powershell tool designed to streamline the process of collecting all necessary data and information from various sources within Microsoft.

.. note::

   🆘 Incident Response support reach out to cert@invictus-ir.com or go to https://www.invictus-ir.com/247

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
  Azure Active Directory sign-in log    Gets the Azure Active Directory sign-in log.                                                                                                                               
  Azure Active Directory Audit Log      Gets the Azure Active Directory audit log.  
  Azure Activity Log                    Gets the Azure Activity log.                                                                                                           
===================================== =========================================================================================================================================================================== 

Retrieve other relevant information
-------

===================================== =========================================================================================================================================================================== 
  Source                                Description                                                                                                                                                                
===================================== =========================================================================================================================================================================== 
  MFA                                   Retrieves the MFA status for all users.   
  User information                      Retrieves the creation time and date of the last password change for all users.                  
  Risky users                           Retrieves the risky users.                         
  Risky Detections                      Retrieves the risky detections from the Entra ID Identity Protection.                                                                                      
  Conditional Access Policies           Retrieves all the conditional access policies.                                                                                        
  Admin users/roles                     Retrieves Administrator directory roles, including the identification of users associated with each specific role.                      
  E-mails                               Get a specific email.                                                                                                          
  Attachments                           Get a specific attachment.                                                                                                                                                                                                                                          
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

Additionally, you must sign-in to Microsoft 365 or Azure depending on your usage before M365-Toolkit functions are made available. To sign in, use the cmdlets:
::

   Connect-M365
   Connect-Azure
   Connect-AzureAZ
   Connect-GraphAPI

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
   :caption: Functionality
   
   functionality/UnifiedAuditLog
   functionality/AdminAuditLog
   functionality/MailboxAuditLog
   functionality/MessageTraceLog
   functionality/OAuthPermissions
   functionality/InboxRules
   functionality/TransportRules
   functionality/MailItemsAccessed
   functionality/AzureActiveDirectorysign-inlogs
   functionality/AzureActiveDirectoryAuditLog
   functionality/AzureActivityLogs
   functionality/AzureSignInLogsGraph
   functionality/AzureAuditLogsGraph
   functionality/ConditionalAccessPolicies
   functionality/GetEmails
   functionality/GetUserInfo

.. toctree::
   :maxdepth: 2
   :hidden:
   :caption: Project

   project/Aboutus
   project/FAQ
   project/KnownErrors
