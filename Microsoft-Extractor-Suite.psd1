@{
RootModule = 'Microsoft-Extractor-Suite.psm1'

# Author of this module
Author = 'Joey Rentenaar & Korstiaan Stam'

# Company of this module
CompanyName = 'Invictus-IR'

# Version number of this module.
ModuleVersion = '1.1.0' 

# Copyright statement for this module
Copyright = 'Copyright (c) 2023 Invictus Incident Response'

# Description of the functionality provided by this module
Description = 'Microsoft-Extractor-Suite is a fully-featured, actively-maintained, Powershell tool designed to streamline the process of collecting all necessary data and information from various sources within Microsoft.'	

NestedModules = @(
	".\Scripts\Get-UAL.ps1"
	".\Scripts\Get-UALStatistics.ps1"
	".\Scripts\Connect.ps1"
	".\Scripts\Get-Rules.ps1"
	".\Scripts\Get-MailboxAuditLog.ps1"
	".\Scripts\Get-MessageTraceLog.ps1"
	".\Scripts\Get-AzureADLogs.ps1"
	".\Scripts\Get-OAuthPermissions.ps1"
	".\Scripts\Get-AdminAuditLog.ps1"
	".\Scripts\Get-AzureActivityLogs.ps1"
	".\Scripts\Get-AzureADGraphLogs.ps1"
)

FunctionsToExport = @(
	# Connect.ps1
	"Connect-M365"
	"Connect-Azure"
	"Connect-AzureAZ"
	"Connect-Graph"
	
	# Get-UAL.ps1
	"Get-UALAll"
	"Get-UALGroup"
	"Get-UALSpecific"
	
	# Get-UALStatistics.ps1
	"Get-UALStatistics"
	
	# Get-Rules.ps1
	"Show-MailboxRules"
	"Get-MailboxRules"
	"Get-TransportRules"
	"Show-TransportRules"
	
	# Get-MailboxAuditLog.ps1
	"Get-MailboxAuditLog"
	
	# Get-MessageTraceLog.ps1
	"Get-MessageTraceLog"
	
	# Get-AzureADLogs
	"Get-ADAuditLogs"
	"Get-ADSignInLogs"

	# Get-OAuthPermissions.ps1
	"Get-OAuthPermissions"

	# Get-AdminAuditLog.ps1
	"Get-AdminAuditLog"
	
	# Get-AzureActivityLogs.ps1
	"Get-ActivityLogs"

	# Get-AzureADGraphLogs.ps1
	"Get-ADSignInLogsGraph"
	"Get-ADAuditLogsGraph"
)

# Variables to export from this module
VariablesToExport = @(
	'$outputdir',
	'$curDir',
	'$logFile',
	'$retryCount'
)

# Cmdlets to export from this module, for best performance
CmdletsToExport = @()	
}