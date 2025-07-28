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
* Entra ID Sign-In Logs
* Entra ID Audit Logs
* Azure Activity Logs
* Azure Directory Activity Logs

In addition to the log sources above the tool is also able to retrieve other relevant information:
* Registered OAuth applications in Entra ID
* The MFA status for all users
* The creation time and date of the last password change for all users
* The risky users
* The risky detections
* The conditional access policies
* Administrator directory roles and their users
* A specific or list of e-mail(s) or attachment(s)
* Delegated permissions for all mailboxes in Microsoft 365
* Information about all devices registered in Entra ID
* Audit status and settings for all mailboxes in Microsoft 365
* Functions designed to gather information about groups
* Functions designed to gather information about licenses
* Retrieve Role Activity Information
* Generates an overview of all Privileged Identity Management (PIM) role assignments
* Security alerts

Microsoft-Extractor-Suite was created by Joey Rentenaar and Korstiaan Stam and is maintained by the [Invictus IR](https://www.invictus-ir.com/) team.

## Usage
To get started with the Microsoft-Extractor-Suite tool, make sure the requirements are met. If you do not have the Connect-ExchangeOnline, AZ module or/and connect-mggraph installed check [the installation guide](https://microsoft-365-extractor-suite.readthedocs.io/en/latest/installation/Installation.html).

Install the Microsoft-Extractor-Suite toolkit:
> Install-Module -Name Microsoft-Extractor-Suite

To import the Microsoft-Extractor-Suite:
> Import-Module .\Microsoft-Extractor-Suite.psd1

You must sign-in to Microsoft 365 or Azure depending on your use case before running the functions. To sign in, use one of the cmdlets:
> Connect-M365 or connect-exchangeonline

> connect-mggraph

> Connect-AzureAZ or Connect-AzAccount

## Available Functions

### Unified Audit Log
- `Get-UAL` - Collect all Unified Audit Logs
- `Get-UALStatistics` - Displays the total number of logs within the Unified Audit Logs per Record Type
- `Get-MailboxAuditLog` - Collect Mailbox Audit Logs
- `Get-AdminAuditLog` - Collect Admin Audit Logs

### Mailbox & Transport Rules
- `Show-MailboxRules` - Shows mailbox rules
- `Get-MailboxRules` - Export mailbox rules
- `Get-TransportRules` - Export transport rules
- `Show-TransportRules` - Shows transport rules

### Mail and Message Tracking
- `Get-MessageTraceLog` - Collect message tracking logs
- `Get-Email` - Download specific or bullk emails
- `Show-Email` - Show email content
- `Get-Attachment` - Download email attachments
- `Get-Sessions` - Collect session information related to MailItemsaccessed events
- `Get-MessageIDs` - Extract message IDs from MailItemsaccessed events

### Sign-In & Audit Logging
- `Get-GraphEntraSignInLogs` - Collect sign-in logs via Graph API
- `Get-GraphEntraAuditLogs` - Collect audit logs via Graph API

### Activity Logging
- `Get-ActivityLogs` - Collect activity logs
- `Get-DirectoryActivityLogs` - Collect directory activity logs

### OAuth apps
- `Get-OAuthPermissions` - Collect OAuth application permissions Via AZ module
- `Get-OAuthPermissionsGraph` - Collect OAuth application permissions via Graph API

### User Related
- `Get-Users` - Collect user information
- `Get-AdminUsers` - Collect users with administrative privileges
- `Get-MFA` - Collect MFA status for users
- `Get-RiskyUsers` - Collect risky users
- `Get-RiskyDetections` - Collect risky detection events

### Conditional Access Policies
- `Get-ConditionalAccessPolicies` - Collect conditional access policies

### Device Management
- `Get-Devices` - Collect device registration information

### Permissions and Audit Settings
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

### Role Management
- `Get-PIMAssignments` - Generates a report of all Privileged Identity Management (PIM) role assignments in Entra ID.
- `Get-AllRoleActivity` - Retrieves all directory role memberships with last login information for users.

### Security Management
- `Get-SecurityAlerts` - Retrieves security alerts

### Automatically collect everything you want
- `Get-AllEvidence` - Collect all (almost) available evidence types automatically
- `Start-MESTriage` - Performs quick triage for specific users using customizable templates

### Authentication & Session Management
- `Connect-M365` - Connect to Microsoft 365 services
- `Connect-Azure` - Connect to Azure/Entra ID
- `Connect-AzureAZ` - Connect using Az module
- `Disconnect-M365` - Disconnect from Microsoft 365 services
- `Disconnect-Azure` - Disconnect from Azure/Entra ID
- `Disconnect-AzureAZ` - Disconnect from Az module session

## Related Projects
To enhance your analysis, consider exploring the [Microsoft-Analyzer-Suite](https://github.com/LETHAL-FORENSICS/Microsoft-Analyzer-Suite) developed by LETHAL FORENSICS. This suite offers a collection of PowerShell scripts specifically designed for analyzing Microsoft 365 and Microsoft Entra ID data, which can be extracted using the Microsoft-Extractor-Suite.
