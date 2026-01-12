@{
	RootModule = 'Microsoft-Extractor-Suite.psm1'
	
	# Author of this module
	Author = 'Joey Rentenaar & Korstiaan Stam'
	
	# Company of this module
	CompanyName = 'Invictus-IR'
	
	# Version number of this module.
	ModuleVersion = '4.0.2' 
	
	# ID used to uniquely identify this module
	GUID = '4376306b-0078-4b4d-b565-e22804e3be01'
	
	# Copyright statement for this module
	Copyright = 'Copyright 2026 Invictus Incident Response'
	
	# Description of the functionality provided by this module
	Description = 'Microsoft-Extractor-Suite is a fully-featured, actively-maintained, Powershell tool designed to streamline the process of collecting all necessary data and information from various sources within Microsoft.'	
	
	NestedModules = @(
		".\Scripts\Get-UAL.ps1"
		".\Scripts\Get-UALStatistics.ps1"
		".\Scripts\Connect.ps1"
		".\Scripts\Disconnect.ps1"
		".\Scripts\Get-Rules.ps1"
		".\Scripts\Get-MailboxAuditLog.ps1"
		".\Scripts\Get-MessageTraceLog.ps1"
		".\Scripts\Get-OAuthPermissions.ps1"
		".\Scripts\Get-AdminAuditLog.ps1"
		".\Scripts\Get-AzureActivityLogs.ps1"
		".\Scripts\Get-AzureEntraGraphLogs.ps1"
		".\Scripts\Get-UsersInfo.ps1"
		".\Scripts\Get-MFAStatus.ps1"
		".\Scripts\Get-RiskyEvents.ps1"
		".\Scripts\Get-ConditionalAccessPolicy.ps1"
		".\Scripts\Get-Emails.ps1"
		".\Scripts\Get-MailItemsAccessed.ps1"
		".\Scripts\Get-UALGraph.ps1"
		".\Scripts\Get-AzureDirectoryActivityLogs.ps1"
		".\Scripts\Get-AuditLogSettings.ps1"
		".\Scripts\Get-MailboxPermissions.ps1"
		".\Scripts\Get-Devices.ps1"
		".\Scripts\Get-AllEvidence.ps1"
		".\Scripts\Get-ProductLicenses.ps1"
		".\Scripts\Get-Groups.ps1"
		".\Scripts\Get-SecurityAlerts.ps1"
		".\Scripts\Get-Roles.ps1"
		".\Scripts\Start-MESTriage.ps1"
		".\Scripts\TriageFunctions.ps1"
	)
	
	FunctionsToExport = @(
		# Connect.ps1
		"Connect-M365"
		"Connect-Azure"
		"Connect-AzureAZ"
		
		# Disconnect.ps1
		"Disconnect-M365"
		"Disconnect-Azure"
		"Disconnect-AzureAZ"

		# Get-UAL.ps1
		"Get-UAL"
		
		# Get-UALGraph
		"Get-UALGraph"
		
		# Get-UALStatistics.ps1
		"Get-UALStatistics"
		
		# Get-Rules.ps1
		"Show-MailboxRules"
		"Get-MailboxRules"
		"Get-TransportRules"
		"Show-TransportRules"
		
		# Get-MailboxAuditLog.ps1
		"Get-MailboxAuditLog"
		"Get-MailboxAuditLogLegacy"
		
		# Get-MessageTraceLog.ps1
		"Get-MessageTraceLog"
	
		# Get-OAuthPermissions.ps1
		"Get-OAuthPermissions"
		"Get-OAuthPermissionsGraph"
	
		# Get-AdminAuditLog.ps1
		"Get-AdminAuditLog"
		
		# Get-AzureActivityLogs.ps1
		"Get-ActivityLogs"
	
		# Get-AzureDirectoryActivityLogs.ps1
		"Get-DirectoryActivityLogs"
	
		# Get-AzureEntraGraphLogs.ps1
		"Get-GraphEntraSignInLogs"
		"Get-GraphEntraAuditLogs"
	
		# Get-UsersInfo.ps1
		"Get-Users"
		"Get-AdminUsers"
	
		# Get-MFAStatus.ps1
		"Get-MFA"
	
		# Get-RiskyEvents.ps1
		"Get-RiskyUsers"
		"Get-RiskyDetections"
	
		# Get-ConditionalAccessPolicy.ps1
		"Get-ConditionalAccessPolicies"
	
		# Get-Emails.ps1
		"Get-Email"
		"Get-Attachment"
		"Show-Email"

		# Get-MailItemsAccessed.ps1
		"Get-Sessions"
		"Get-MessageIDs"
	
		# Get-AuditLogSettings.ps1
		"Get-MailboxAuditStatus"
	
		# Get-MailboxPermissions.ps1
		"Get-MailboxPermissions"
	
		# Get-Devices.ps1
		"Get-Devices"
	
		# Get-AllEvidence.ps1
		"Start-EvidenceCollection"
				
		# Get-ProductLicenses.ps1
		"Get-Licenses"
		"Get-LicenseCompatibility"
		"Get-EntraSecurityDefaults"
		"Get-LicensesByUser"

		# Get-Groups.ps1
		"Get-Groups"
		"Get-GroupMembers"
		"Get-DynamicGroups"

		# Get-SecurityAlerts.ps1
		"Get-SecurityAlerts"

		# Get-Roles.ps1
		"Get-AllRoleActivity"
		"Get-PIMAssignments"

		# Start-MESTriage.ps1
		"Start-MESTriage"

		# TriageFunctions
		"Get-EntraApplicationsForSpecificUsers"
		"Get-QuickUALOperations"
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