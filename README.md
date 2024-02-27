![alt text](https://github.com/invictus-ir/Microsoft-Extractor-Suite/blob/main/docs/source/Images/Invictus-Incident-Response.jpg?raw=true)

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

In addition to the log sources above the tool is also able to retrieve other relevant information:
* Registered OAuth applications in Azure AD
* The MFA status for all users
* The creation time and date of the last password change for all users
* The risky users
* The risky detections
* The conditional access policies
* Administrator directory roles and their users
* A specific e-mail or attachment

Microsoft-Extractor-Suite was created by Joey Rentenaar and Korstiaan Stam and is maintained by the [Invictus IR](https://www.invictus-ir.com/) team.

## Usage
To get started with the Microsoft-Extractor-Suite tool, make sure the requirements are met. If you do not have the Connect-ExchangeOnline, AZ module or/and Connect-AzureAD installed check [the installation guide](https://microsoft-365-extractor-suite.readthedocs.io/en/latest/installation/Installation.html).

Install the Microsoft-Extractor-Suite toolkit:
> Install-Module -Name Microsoft-Extractor-Suite

To import the Microsoft-Extractor-Suite:
> Import-Module .\Microsoft-Extractor-Suite.psd1

You must sign-in to Microsoft 365 or Azure depending on your use case before running the functions. To sign in, use the cmdlets:
> Connect-M365

> Connect-Azure

> Connect-AzureAZ

