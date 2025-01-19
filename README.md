![alt text](https://github.com/invictus-ir/Microsoft-Extractor-Suite/blob/main/docs/source/Images/Invictus-Incident-Response.jpg?raw=true)
![Language](https://img.shields.io/badge/Language-Powershell-blue)
[![Documentation](https://img.shields.io/badge/Read%20the%20Docs-Documentation-blue)](https://microsoft-365-extractor-suite.readthedocs.io/en/latest/)
[![Latest Version](https://img.shields.io/powershellgallery/v/Microsoft-Extractor-Suite?label=Latest%20Version&color=brightgreen)](https://www.powershellgallery.com/packages/Microsoft-Extractor-Suite)
![GitHub stars](https://img.shields.io/github/stars/invictus-ir/Microsoft-Extractor-Suite?style=social)
![Contributors](https://img.shields.io/github/contributors/invictus-ir/Microsoft-Extractor-Suite)
![PS Gallery Downloads](https://img.shields.io/powershellgallery/dt/Microsoft-Extractor-Suite?label=PS%20Gallery%20Downloads)
![Maintenance](https://img.shields.io/badge/Maintenance%20Level-Actively%20Developed-brightgreen)

# Getting started with the Microsoft-Extractor-Suite

To get started with the Microsoft-Extractor-Suite, check out the [Microsoft-Extractor-Suite docs.](https://microsoft-365-extractor-suite.readthedocs.io/en/latest/)

## About Microsoft-Extractor-Suite
Microsoft-Extractor-Suite is a fully-featured, actively-maintained, Powershell tool designed to streamline the process of collecting all necessary data and information from various sources within Microsoft.

The following Microsoft data sources are supported:
* Unified Audit Log
* Admin Audit Log
* Mailbox Audit Log
* Mailbox Rules
* Transport Rules
* Message Trace Logs
* Azure AD Sign-In Logs
* Azure AD Audit Logs
* Azure Activity Logs
* Azure Directory Activity Logs

In addition to the log sources above the tool is also able to retrieve other relevant information:
* Registered OAuth applications in Azure AD
* The MFA status for all users
* The creation time and date of the last password change for all users
* The risky users
* The risky detections
* The conditional access policies
* Administrator directory roles and their users
* A specific or list of e-mail(s) or attachment(s)
* Delegated permissions for all mailboxes in Microsoft 365.
* Information about all devices registered in Azure AD/Entra ID. 
* Audit status and settings for all mailboxes in Microsoft 365.
* Functions designed to gather information about groups.
* Functions designed to gather information about licenses.

Microsoft-Extractor-Suite was created by Joey Rentenaar and Korstiaan Stam and is maintained by the [Invictus IR](https://www.invictus-ir.com/) team.

## Usage
To get started with the Microsoft-Extractor-Suite tool, make sure the requirements are met. If you do not have the Connect-ExchangeOnline, AZ module or/and Connect-AzureAD installed check [the installation guide](https://microsoft-365-extractor-suite.readthedocs.io/en/latest/installation/Installation.html).

Install the Microsoft-Extractor-Suite toolkit:
> Install-Module -Name Microsoft-Extractor-Suite

To import the Microsoft-Extractor-Suite:
> Import-Module .\Microsoft-Extractor-Suite.psd1

You must sign-in to Microsoft 365 or Azure depending on your use case before running the functions. To sign in, use one of the cmdlets:
> Connect-M365 or connect-exchangeonline

> Connect-Azure or Connect-AzureAD

> Connect-AzureAZ or Connect-AzAccount

## Available Functions

### Authentication & Session Management
- `Connect-M365` - Connect to Microsoft 365 services
- `Connect-Azure` - Connect to Azure/Entra ID
- `Connect-AzureAZ` - Connect using Az module
- `Disconnect-M365` - Disconnect from Microsoft 365 services
- `Disconnect-Azure` - Disconnect from Azure/Entra ID
- `Disconnect-AzureAZ` - Disconnect from Az module session

### Unified Audit Log
- `Get-UALAll` - Collect all Unified Audit Logs
- `Get-UALStatistics` - Displays the total number of logs within the Unified Audit Logs per Record Type

### Mailbox & Transport Rules
- `Show-MailboxRules` - Shows mailbox rules
- `Get-MailboxRules` - Export mailbox rules
- `Get-TransportRules` - Export transport rules
- `Show-TransportRules` - Shows transport rules

### Mail and Message Tracking
- `Get-MailboxAuditLog` - Collect mailbox audit logs
- `Get-MessageTraceLog` - Collect message tracking logs
- `Get-Email` - Download specific or bullk emails
- `Get-Attachment` - Download email attachments
- `Show-Email` - Show email content
- `Get-Sessions` - Collect session information related to MailItemsaccessed events
- `Get-MessageIDs` - Extract message IDs from MailItemsaccessed events

### Entra ID & Directory Operations
- `Get-EntraAuditLogs` - Collect audit logs via AzureAD
- `Get-EntraSignInLogs` - Collect sign-in logs via AzureAD
- `Get-GraphEntraSignInLogs` - Collect sign-in logs via Graph API
- `Get-GraphEntraAuditLogs` - Collect audit logs via Graph API
- `Get-ActivityLogs` - Collect activity logs
- `Get-DirectoryActivityLogs` - Collect directory activity logs

### Security & Compliance
- `Get-OAuthPermissions` - Collect OAuth application permissions
- `Get-MFA` - Collect MFA status for users
- `Get-RiskyUsers` - Collect risky users
- `Get-RiskyDetections` - Collect risky detection events
- `Get-ConditionalAccessPolicies` - Collect conditional access policies

### User & Device Management
- `Get-Users` - Collect user information
- `Get-AdminUsers` - Collect users with administrative privileges
- `Get-Devices` - Collect device registration information

### Mailbox Administration
- `Get-MailboxAuditStatus` - Collect the mailbox audit configurations
- `Get-MailboxPermissions` - Collect delegated mailbox permissions

### License Management
- `Get-Licenses` - Collect all licenses in the tenant with retention times and premium license indicators
- `Get-LicenseCompatibility` - Checks the presence of E5, P2, P1, and E3 licenses and informs about functionality limitations
- `Get-EntraSecurityDefaults` - Checks the status of Entra ID security defaults
- `Get-LicensesByUser` - Collect license assignments for all users in the tenant

### Group Management
- `Get-Groups` - Collect all groups in the organization including details such as group ID and display name
- `Get-GroupMembers` - Collect all members of each group and their relevant details
- `Get-DynamicGroups` - Collect all dynamic groups and their membership rules

### Automatically collect everything you wants
- `Get-AllEvidence` - Collect all (almost) available evidence types automatically


## Related Projects
To enhance your analysis, consider exploring the [Microsoft-Analyzer-Suite](https://github.com/evild3ad/Microsoft-Analyzer-Suite) developed by evild3ad. This suite offers a collection of PowerShell scripts specifically designed for analyzing Microsoft 365 and Microsoft Entra ID data, which can be extracted using the Microsoft-Extractor-Suite.