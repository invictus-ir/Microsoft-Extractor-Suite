![alt text](https://github.com/invictus-ir/Microsoft-Extractor-Suite/blob/main/docs/source/Images/Invictus-Incident-Response.jpg?raw=true)

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
* Registered OAuth applications in Azure AD

Microsoft-Extractor-Suite was created by Joey Rentenaar and Korstiaan Stam.

Microsoft-Extractor-Suite is maintained by the [Invcitus IR](https://www.invictus-ir.com//) team.

## Usage
To get started with the Microsoft-Extractor-Suite tool, make sure the requirements are met. If you do not have the Connect-ExchangeOnline or/and Connect-AzureAD installed check [the installation guide.](https://microsoft-365-extractor-suite.readthedocs.io/en/latest/installation/Installation.html).

The first step is to import the Microsoft-Extractor-Suite:
> Import-Module .\Microsoft-Extractor-Suite.psd1

Additionally, you must sign-in to Microsoft 365 or Azure depending on your usage before M365-Toolkit functions are made available. To sign in, use the cmdlets:
> Connect-M365

> Connect-Azure


