<h2>Microsoft 365 Extractor Suite</h2>
This suite of scripts contains two different scripts that can be used to acquire the Microsoft 365 Unified Audit Log
<br>
Read the accompanying blog post on <here>
<br>




1.	_Microsoft365_Extractor_, the original script stems from the Office 365 Extractor and provides all features and complete customization. Choose this if you're not sure what to use. 
2.	_Microsoft365_Extractor_light_, lightweight version of the Microsoft365_Extractor that requires minimal configuration and grabs all available logging for the complete period. 

	
	
<h3>Microsoft 365 Extractor</h3>
This script makes it possible to extract log data out of a Microsoft 365 environment. The script has four options, which enable the investigator to easily extract logging out of an Microsoft 365 environment. 

1.	Show available log sources and amount of logging
2.	Extract all audit logging
3.	Extract group audit logging
4.	Extract Specific audit logging (advanced mode)

<h3>Show available log sources and amount of logging</h3>
Pretty straightforward a search is executed and the total number of logs within the<br>
set timeframe will be displayed and written to a csv file called "Amount_Of_Audit_Logs.csv" the file is prefixed with a random number to prevent duplicates.

<h3>Extract all audit logs</h3>
Extract all audit logs" this option wil get all available audit logs within the set timeframe and written out to a file called AuditRecords.CSV.

<h3>Extract group logging</h3>
Extract a group of logs. You can for example extract all Exchange or Azure logging in one go<br>

<h3>Extract specific audit logs</h3>
Extract specific audit logs" Use this option if you want to extract a subset of the audit logs. To configure what logs will be extracted the tool needs to<br>
be configured with the required Record Types. A full list of recordtypes can be found at the bottom of this page.<br>
The output files will be writen in a directory called 'Log_Directory" and will be given the name of their recordtype e.g. (ExchangeItem_AuditRecords.csv) <br>

<h3>Prerequisites</h3>
	- PowerShell<br>
	- Microsoft 365 account with privileges to access/extract audit logging<br>
	- An OS that supports Powershell you should be good. There are some issues with PowerShell on MacOS/Linux related to WinRM so your best option is to use Windows. 
<br>

<h3>Permissions</h3>

You have to be assigned the View-Only Audit Logs or Audit Logs role in Exchange Online to search the Microsoft 365 audit log.
By default, these roles are assigned to the Compliance Management and Organization Management role groups on the Permissions page in the Exchange admin center. To give a user the ability to search the Office 365 audit log with the minimum level of privileges, you can create a custom role group in Exchange Online, add the View-Only Audit Logs or Audit Logs role, and then add the user as a member of the new role group. For more information, see Manage role groups in Exchange Online.<br>
(https://docs.microsoft.com/en-us/office365/securitycompliance/search-the-audit-log-in-security-and-compliance)<br>

<h3>How to use Microsoft365_extractor</h3>
1.	Download Microsoft365_Extractor.ps1<br>
2.	Open PowerShell navigate to the script and run it or right click on the script and press "Run with PowerShell".<br>
3.	Select your prefered option.<br>
4.  The logs will be written to 'Log_Directory' in the folder where the script is located.<br><br>

See example video below: <br>

<h3>Output</h3>
<b>Amount_Of_Audit_Logs.csv:</b><br>
Will show what logs are available and how many for each RecordType.<br>
<b>AuditLog.txt:</b><br>
The AuditLog stores valuable information for debugging.<br>
<b>AuditRecords.csv:</b><br>
When all logs are extracted they will be written to this file.<br>
<b>[RecordType]__AuditRecords:</b><br>
When extracting specific RecordTypes, logs are sorted on RecordType and written to a CSV file.<br>
The name of this file is the RecordType + _AuditRecords.<br>

<h3>Available RecordTypes</h3>

ExchangeAdmin<br>
ExchangeItem<br>
ExchangeItemGroup<br>
SharePoint<br>
SyntheticProbe<br>
SharePointFileOperation<br>
OneDrive<br>
AzureActiveDirectory<br>
AzureActiveDirectoryAccountLogon<br>
DataCenterSecurityCmdlet<br>
ComplianceDLPSharePoint<br>
Sway<br>
ComplianceDLPExchange<br>
SharePointSharingOperation<br>
AzureActiveDirectoryStsLogon<br>
SkypeForBusinessPSTNUsage<br>
SkypeForBusinessUsersBlocked<br>
SecurityComplianceCenterEOPCmdlet<br>
ExchangeAggregatedOperation<br>
PowerBIAudit<br>
CRM<br>
Yammer<br>
SkypeForBusinessCmdlets<br>
Discovery<br>
MicrosoftTeams<br>
ThreatIntelligence<br>
MailSubmission<br>
MicrosoftFlow<br>
AeD<br>
MicrosoftStream<br>
ComplianceDLPSharePointClassification<br>
ThreatFinder<br>
Project<br>
SharePointListOperation<br>
SharePointCommentOperation<br>
DataGovernance<br>
Kaizala<br>
SecurityComplianceAlerts<br>
ThreatIntelligenceUrl<br>
SecurityComplianceInsights<br>
MIPLabel<br>
WorkplaceAnalytics<br>
PowerAppsApp<br>
PowerAppsPlan<br>
ThreatIntelligenceAtpContent<br>
TeamsHealthcare<br>
ExchangeItemAggregated<br>
HygieneEvent<br>
DataInsightsRestApiAudit<br>
InformationBarrierPolicyApplication<br>
SharePointListItemOperation<br>
SharePointContentTypeOperation<br>
SharePointFieldOperation<br>
MicrosoftTeamsAdmin<br>
HRSignal<br>
MicrosoftTeamsDevice<br>
MicrosoftTeamsAnalytics<br>
InformationWorkerProtection<br>
Campaign<br>
DLPEndpoint<br>
AirInvestigation<br>
Quarantine<br>
MicrosoftForms<br>
LabelContentExplorer<br>
ApplicationAudit<br>
ComplianceSupervisionExchange<br>
CustomerKeyServiceEncryption<br>
OfficeNative<br>
MipAutoLabelSharePointItem<br>
MipAutoLabelSharePointPolicyLocation<br>
MicrosoftTeamsShifts<br>
MipAutoLabelExchangeItem<br>
CortanaBriefing<br>
Search<br>
WDATPAlerts<br>
MDATPAudit<br>
SensitivityLabelPolicyMatch<br>
SensitivityLabelAction<br>
SensitivityLabeledFileAction<br>
AttackSim<br>
AirManualInvestigation<br>
SecurityComplianceRBAC<br>
UserTraining<br>
AirAdminActionInvestigation<br>
MSTIC<br>
PhysicalBadgingSignal<br>
AipDiscover<br>
AipSensitivityLabelAction<br>
AipProtectionAction<br>
AipFileDeleted<br>
AipHeartBeat<br>
MCASAlerts<br>
OnPremisesFileShareScannerDlp<br>
OnPremisesSharePointScannerDlp<br>
ExchangeSearch<br>
SharePointSearch<br>
PrivacyInsights<br>
MyAnalyticsSettings<br>
SecurityComplianceUserChange<br>
ComplianceDLPExchangeClassification<br>
MipExactDataMatch<br>
MS365DCustomDetection<br>
CoreReportingSettings<br>
ComplianceConnector<br>
Source:https://docs.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema#auditlogrecordtype <br>

<h3>Frequently Asked Questions</h3>
<b>If I enable mailbox auditing now can I see historical records?</b><br>
No, additionaly if you enable auditing now it can take up to 24 hours before events will be logged. 
<br>

<b>I logged into a mailbox with auditing turned on but I don't see my events?</b><br>
It can take up to 24 hours before an event is stored in the UAL.

<br>

<b>Which date format does the script accepts as input?</b><br>
The script will tell what the correct date format is. For Start and End data variables it will show between brackets what the format is (yyyy-MM-dd).<br>
<br>

<b>Do I need to configure the time period?</b><br>
No if you don't specify a time period the script will use the default If you don't include a timestamp in the value for the StartDate or EndDate parameters, the default timestamp 12:00 AM (midnight) is used.<br>
<br>

<b>What about timestamps?</b><br>
The audit logs are in UTC, and they will be exported as such<br>
<br>

<b>What is the retention period?</b><br>
Office 365 E3 - Audit records are retained for 90 days. That means you can search the audit log for activities that were performed within the last 90 days.

Office 365 E5 - Audit records are retained for 365 days (one year). That means you can search the audit log for activities that were performed within the last year. Retaining audit records for one year is also available for users that are assigned an E3/Exchange Online Plan 1 license and have an Office 365 Advanced Compliance add-on license.
<br>

<b>What if I have E5 or other license that has more than 90 days?</b><br>
Just define a manual startdate instead of the 'maximum' because the variable maximum is set to 90 days, which is the default for almost everyone.
<br>

<b>Can this script also acquire Message Trace Logs?</b><br>
At the moment it cannot, but there are several open-source scripts available that can help you with getting the MTL
One example can be found here: https://gallery.technet.microsoft.com/scriptcenter/Export-Mail-logs-to-CSV-d5b6c2d6
<br>

<h3>Known errors</h3>
<b>StartDate is later than EndDate</b><br>
This error occurs sometimes at the final step of the script if you have not defined an endDate. Doublecheck if you have all the logs using Option 1 to validate if you have all logs. Alternative: Define an endDate <br> <br>

<b>Import-PSSession : No command proxies have been created, because all of the requested remote....</b><br>
This error is caused when the script did not close correctly and an active session will be running in the background.
The script tries to import/load all modules again, but this is not necessary since it is already loaded. This error message has no impact on the script and will be gone when the open session gets closed. This can be done by restarting the PowerShell Windows or entering the following command: Get-PSSession | Remove-PSSession <br>

<b>Audit logging is enabled in the Office 365 environment but no logs are getting displayed?</b><br>
The user must be assigned an Office 365 E5 license. Alternatively, users with an Office 365 E1 or E3 license can be assigned an Advanced eDiscovery standalone license. Administrators and compliance officers who are assigned to cases and use Advanced eDiscovery to analyze data don't need an E5 license.<br>

<b>Audit log search argument start date should be after</b><br>
The start date should be earlier then the end date.

<b>New-PSSession: [outlook.office365.com] Connecting to remove server outlook.office365.com failed with the following error message: Access is denied.</b><br>
The password/username combination are incorrect or the user has not enough privileges to extract the audit logging.<br>
<br>
<b>Invalid Argument "Cannot convert value" to type "System.Int32"</b> <br>
Safe to ignore, only observed this on PowerShell on macOS, the script will work fine and continue. 
<br>

