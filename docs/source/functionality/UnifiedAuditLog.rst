Unified Audit Log
=======

The UAL is a critical piece of evidence in a BEC investigation because it is a centralized source for
all Office 365 events. The UAL contains at least 236 categories of data, including events from Azure,
Exchange, SharePoint, OneDrive, and Skype.

.. note::

  Audit (Standard) - Audit records are retained for 180 days.
  
  Audit (Premium) - Audit records are retained for 365 days. 

Show available log sources and amount of logging
^^^^^^^^^^^
Pretty straightforward a search is executed and the total number of logs within the set timeframe will be displayed and written to a csv file called "Amount_Of_Audit_Logs.csv" the file is prefixed with a random number to prevent duplicates.

Usage
""""""""""""""""""""""""""
Displays the total number of logs within the unified audit log:
::

   Get-UALStatistics

Displays the total number of logs within the unified audit log between 1/4/2023 and 5/4/2023 for the user test[@]invictus-ir.com:
::

   Get-UALStatistics -UserIds test[@]invictus-ir.com -StartDate 1/4/2023 -EndDate 5/4/2023

Parameters
""""""""""""""""""""""""""
-UserIds (optional)
    - UserIds is the UserIds parameter filtering the log entries by the account of the user who performed the actions.

-StartDate (optional)
    - StartDate is the parameter specifying the start date of the date range.
    - Default: Today -90 days

-EndDate (optional)
    - EndDate is the parameter specifying the end date of the date range.
    - Default: Now

-OutputDir (optional)
    - OutputDir is the parameter specifying the output directory.
    - Default: UnifiedAuditLog

.. note::

  **Important note** regarding the StartDate and EndDate variables. 

- When you do not specify a timestamp, the script will automatically default to midnight (00:00) of that day.
- If you provide a timestamp, it will be converted to the corresponding UTC time. For example, if your local timezone is UTC+2, a timestamp like 2023-01-01 08:15:00 will be converted to 2023-01-01 06:15:00 in UTC.
- To specify a date and time without conversion, please use the ISO 8601 format with UTC time (e.g., 2023-01-01T08:15:00Z). This format will retrieve data from January 1st, 2023, starting from a quarter past 8 in the morning until the specified end date.

Output
""""""""""""""""""""""""""
The output will be saved to the file 'Amount_Of_Audit_Logs.csv' within the 'Output' directory.

Extract all audit logs
^^^^^^^^^^^
Extract All Audit Logs will retrieve all available audit logs within the specified timeframe and export them.

Usage
""""""""""""""""""""""""""
Running the script without any parameters will gather the Unified Audit log for the last 90 days for all users:
::

   Get-UALAll

Get all the unified audit log entries for the user test[@]invictus-ir.com:
::

   Get-UALAll -UserIds test[@]invictus-ir.com

Get all the unified audit log entries for the users test[@]invictus-ir.com and HR[@]invictus-ir.com:
::

   Get-UALAll -UserIds "test@invictus-ir.com,HR@invictus-ir.com"
  
Get all the unified audit log entries between 1/4/2023 and 5/4/2023 for the user test[@]invictus-ir.com:
::

   Get-UALAll -UserIds test[@]invictus-ir.com -StartDate 1/4/2023 -EndDate 5/4/2023

Get all the unified audit log entries with a time interval of 720:
::

   Get-UALAll -UserIds -Interval 720

Get all the unified audit log entries for the user test[@]invictus-ir.com in JSON format:
::

   Get-UALAll -UserIds test[@]invictus-ir.com -Output JSON

Parameters
""""""""""""""""""""""""""
-UserIds (optional)
    - UserIds is the UserIds parameter filtering the log entries by the account of the user who performed the actions.

-StartDate (optional)
    - StartDate is the parameter specifying the start date of the date range.
    - Default: Today -90 days

-EndDate (optional)
    - EndDate is the parameter specifying the end date of the date range.
    - Default: Now

-Interval (optional)
    - Interval is the parameter specifying the interval in which the logs are being gathered.
    - Default: 60 minutes

-Output (optional)
    - Output is the parameter specifying the CSV, JSON or SOF-ELK output type.
    - The SOF-ELK output type can be used to export logs in a format suitable for the [platform of the same name](https://github.com/philhagen/sof-elk).
    - Default: CSV

-MergeOutput (optional)
    - MergeOutput is the parameter specifying if you wish to merge CSV, JSON or SOF-ELK outputs to a single file.

-OutputDir (optional)
    - OutputDir is the parameter specifying the output directory.
    - Default: UnifiedAuditLog

-Encoding (optional)
    - Encoding is the parameter specifying the encoding of the CSV/JSON output file.
    - Default: UTF8

-ObjecIDs (optional)
    - The ObjectIds parameter filters the log entries by object ID. The object ID is the target object that was acted upon, and depends on the RecordType and Operations values of the event.
	- You can enter multiple values separated by commas.

.. note::

  **Important note** regarding the StartDate and EndDate variables. 

- When you do not specify a timestamp, the script will automatically default to midnight (00:00) of that day.
- If you provide a timestamp, it will be converted to the corresponding UTC time. For example, if your local timezone is UTC+2, a timestamp like 2023-01-01 08:15:00 will be converted to 2023-01-01 06:15:00 in UTC.
- To specify a date and time without conversion, please use the ISO 8601 format with UTC time (e.g., 2023-01-01T08:15:00Z). This format will retrieve data from January 1st, 2023, starting from a quarter past 8 in the morning until the specified end date.

Output
""""""""""""""""""""""""""
The output will be saved to the 'UnifiedAuditLog' directory within the 'Output' directory, with the file name 'UAL-[$CurrentStart].[csv/json]'.

Extract group logging
^^^^^^^^^^^
You can extract a specific group of logs such as all Exchange or Azure logs in a single operation. The below groups are supported:

+-------------------+--------------------------------------------+
| Group             | Record Type                                |
+===================+============================================+
|  Azure            | AzureActiveDirectory                       |
|                   +--------------------------------------------+
|                   | AzureActiveDirectoryAccountLogon           |
|                   +--------------------------------------------+
|                   | AzureActiveDirectoryStsLogon               |
+-------------------+--------------------------------------------+
| SharePoint        | ComplianceDLPSharePoint                    |
|                   +--------------------------------------------+
|                   | SharePoint                                 |
|                   +--------------------------------------------+
|                   | SharePointFileOperation                    |
|                   +--------------------------------------------+
|                   | SharePointSharingOperation                 |
|                   +--------------------------------------------+
|                   | SharepointListOperation                    |
|                   +--------------------------------------------+
|                   | ComplianceDLPSharePointClassification      |
|                   +--------------------------------------------+
|                   | SharePointCommentOperation                 |
|                   +--------------------------------------------+
|                   | SharePointListItemOperation                |
|                   +--------------------------------------------+
|                   | SharePointContentTypeOperation             |
|                   +--------------------------------------------+
|                   | SharePointFieldOperation                   |
|                   +--------------------------------------------+
|                   | MipAutoLabelSharePointItem                 |
|                   +--------------------------------------------+
|                   | MipAutoLabelSharePointPolicyLocation       |
+-------------------+--------------------------------------------+
|  Skype            | SkypeForBusinessCmdlets                    |
|                   +--------------------------------------------+
|                   | SkypeForBusinessPSTNUsage                  |
|                   +--------------------------------------------+
|                   | SkypeForBusinessUsersBlocked               |
+-------------------+--------------------------------------------+
| Defender          | ThreatIntelligence                         |
|                   +--------------------------------------------+
|                   | ThreatFinder                               |
|                   +--------------------------------------------+
|                   | ThreatIntelligenceUrl                      |
|                   +--------------------------------------------+
|                   | ThreatIntelligenceAtpContent               |
|                   +--------------------------------------------+
|                   | Campaign                                   |
|                   +--------------------------------------------+
|                   | AirInvestigation                           |
|                   +--------------------------------------------+
|                   | WDATPAlerts                                |
|                   +--------------------------------------------+
|                   | AirManualInvestigation                     |
|                   +--------------------------------------------+
|                   | AirAdminActionInvestigation                |
|                   +--------------------------------------------+
|                   | MSTIC                                      |
|                   +--------------------------------------------+
|                   | MCASAlerts                                 |
+-------------------+--------------------------------------------+
| Exchange          | ExchangeAdmin                              |
|                   +--------------------------------------------+
|                   | ExchangeAggregatedOperation                |
|                   +--------------------------------------------+
|                   | ExchangeItem                               |
|                   +--------------------------------------------+
|                   | ExchangeItemGroup                          |
|                   +--------------------------------------------+
|                   | ExchangeItemAggregated                     |
|                   +--------------------------------------------+
|                   | ComplianceDLPExchange                      |
|                   +--------------------------------------------+
|                   | ComplianceSupervisionExchange              |
+-------------------+--------------------------------------------+

Usage
""""""""""""""""""""""""""
Running the script with only the group parameter will gather the Unified Audit log for the last 90 days for all users and the specified Azure group:
::

   Get-UALGroup -Group Azure

Get all Exchange related unified audit log entries for the user test[@]invictus-ir.com:
::

   Get-UALGroup -Group Exchange -UserIds test[@]invictus-ir.com

Get all Exchange related unified audit log entries for the users test[@]invictus-ir.com and HR[@]invictus-ir.com:
::

   Get-UALGroup -Group Exchange -UserIds "test@invictus-ir.com,HR@invictus-ir.com"
  
Get all the Azure related unified audit log entries between 1/4/2023 and 5/4/2023:
::

   Get-UALGroup -Group Azure -StartDate 1/4/2023 -EndDate 5/4/2023

Get all the Defender related unified audit log entries for the user test[@]invictus-ir.com in JSON format with a time interval of 720:
::

   Get-UALGroup -Group Defender -UserIds test[@]invictus-ir.com -Interval 720 -Output JSON

Parameters
""""""""""""""""""""""""""
-Group (required)
    - Group is the group of logging needed to be extracted.
    - Options are: Exchange, Azure, Sharepoint, Skype and Defender

-UserIds (optional)
    - UserIds is the UserIds parameter filtering the log entries by the account of the user who performed the actions.

-StartDate (optional)
    - StartDate is the parameter specifying the start date of the date range.
    - Default: Today -90 days

-EndDate (optional)
    - EndDate is the parameter specifying the end date of the date range.
    - Default: Now

-Interval (optional)
    - Interval is the parameter specifying the interval in which the logs are being gathered.
    - Default: 60 minutes

-Output (optional)
    - Output is the parameter specifying the CSV, JSON or SOF-ELK output type.
    - The SOF-ELK output type can be used to export logs in a format suitable for the [platform of the same name](https://github.com/philhagen/sof-elk).
    - Default: CSV

-MergeOutput (optional)
    - MergeOutput is the parameter specifying if you wish to merge CSV, JSON or SOF-ELK outputs to a single file.

-OutputDir (optional)
    - OutputDir is the parameter specifying the output directory.
    - Default: UnifiedAuditLog

-Encoding (optional)
    - Encoding is the parameter specifying the encoding of the CSV/JSON output file.
    - Default: UTF8

-ObjecIDs (optional)
    - The ObjectIds parameter filters the log entries by object ID. The object ID is the target object that was acted upon, and depends on the RecordType and Operations values of the event.
	- You can enter multiple values separated by commas.

.. note::

  **Important note** regarding the StartDate and EndDate variables. 

- When you do not specify a timestamp, the script will automatically default to midnight (00:00) of that day.
- If you provide a timestamp, it will be converted to the corresponding UTC time. For example, if your local timezone is UTC+2, a timestamp like 2023-01-01 08:15:00 will be converted to 2023-01-01 06:15:00 in UTC.
- To specify a date and time without conversion, please use the ISO 8601 format with UTC time (e.g., 2023-01-01T08:15:00Z). This format will retrieve data from January 1st, 2023, starting from a quarter past 8 in the morning until the specified end date.

Output
""""""""""""""""""""""""""
The output will be saved to the 'UnifiedAuditLog' directory within the 'Output' directory, with the file name 'UAL-[$CurrentStart].[csv/json]'.

Extract specific audit logs
^^^^^^^^^^^
If you want to extract a subset of audit logs. You can configure the tool by specifying the required Record Types to extract. The 236 supported Record Types can be found at the end of this page.

Usage
""""""""""""""""""""""""""
Running the script with only the RecordType parameter will gather the Unified Audit log for the last 90 days for all users and the specified ExchangeItem record type:
::

   Get-UALSpecific -RecordType ExchangeItem

Get the MipAutoLabelExchangeItem logging from the unified audit log for the user test[@]invictus-ir.com:
::

   Get-UALSpecific -RecordType MipAutoLabelExchangeItem -UserIds test[@]invictus-ir.com

Get the PrivacyInsights logging from the unified audit log for the uses test[@]invictus-ir.com and HR[@]invictus-ir.com:
::

   Get-UALSpecific -RecordType PrivacyInsights -UserIds "test@invictus-ir.com,HR@invictus-ir.com"
  
Get the ExchangeAdmin logging from the unified audit log entries between 1/4/2023 and 5/4/2023:
::

   Get-UALSpecific -RecordType ExchangeAdmin -StartDate 1/4/2023 -EndDate 5/4/2023

Get all the MicrosoftFlow logging from the unified audit log for the user test[@]invictus-ir.com in JSON format with a time interval of 720:
::

   Get-UALSpecific -RecordType MicrosoftFlow -UserIds test[@]invictus-ir.com -StartDate 25/3/2023 -EndDate 5/4/2023 -Interval 720 -Output JSON

Parameters
""""""""""""""""""""""""""
-RecordType (required)
    - The RecordType parameter filters the log entries by record type.
    - Options are: ExchangeItem, ExchangeAdmin, etc. A total of 236 RecordTypes are supported.

-UserIds (optional)
    - UserIds is the UserIds parameter filtering the log entries by the account of the user who performed the actions.

-StartDate (optional)
    - StartDate is the parameter specifying the start date of the date range.
    - Default: Today -90 days

-EndDate (optional)
    - EndDate is the parameter specifying the end date of the date range.
    - Default: Now

-Interval (optional)
    - Interval is the parameter specifying the interval in which the logs are being gathered.
    - Default: 60 minutes

-Output (optional)
    - Output is the parameter specifying the CSV, JSON or SOF-ELK output type.
    - The SOF-ELK output type can be used to export logs in a format suitable for the [platform of the same name](https://github.com/philhagen/sof-elk).
    - Default: CSV

-MergeOutput (optional)
    - MergeOutput is the parameter specifying if you wish to merge CSV, JSON or SOF-ELK outputs to a single file.

-OutputDir (optional)
    - OutputDir is the parameter specifying the output directory.
    - Default: UnifiedAuditLog

-Encoding (optional)
    - Encoding is the parameter specifying the encoding of the CSV/JSON output file.
    - Default: UTF8

-ObjecIDs (optional)
    - The ObjectIds parameter filters the log entries by object ID. The object ID is the target object that was acted upon, and depends on the RecordType and Operations values of the event.
	- You can enter multiple values separated by commas.

.. note::

  **Important note** regarding the StartDate and EndDate variables. 

- When you do not specify a timestamp, the script will automatically default to midnight (00:00) of that day.
- If you provide a timestamp, it will be converted to the corresponding UTC time. For example, if your local timezone is UTC+2, a timestamp like 2023-01-01 08:15:00 will be converted to 2023-01-01 06:15:00 in UTC.
- To specify a date and time without conversion, please use the ISO 8601 format with UTC time (e.g., 2023-01-01T08:15:00Z). This format will retrieve data from January 1st, 2023, starting from a quarter past 8 in the morning until the specified end date.

Output
""""""""""""""""""""""""""
The output will be saved to the 'UnifiedAuditLog' directory within the 'Output' directory, with the file name 'UAL-[$CurrentStart].[csv/json]'.

Supported Record Types
""""""""""""""""""""""""""
::

  ExchangeAdmin
  ExchangeItem
  ExchangeItemGroup
  SharePoint
  SyntheticProbe
  SharePointFileOperation
  OneDrive
  AzureActiveDirectory
  AzureActiveDirectoryAccountLogon
  DataCenterSecurityCmdlet
  ComplianceDLPSharePoint
  Sway
  ComplianceDLPExchange
  SharePointSharingOperation
  AzureActiveDirectoryStsLogon
  SkypeForBusinessPSTNUsage
  SkypeForBusinessUsersBlocked
  SecurityComplianceCenterEOPCmdlet
  ExchangeAggregatedOperation
  PowerBIAudit
  CRM
  Yammer
  SkypeForBusinessCmdlets
  Discovery
  MicrosoftTeams
  ThreatIntelligence
  MailSubmission
  MicrosoftFlow
  AeD
  MicrosoftStream
  ComplianceDLPSharePointClassification
  ThreatFinder
  Project
  SharePointListOperation
  SharePointCommentOperation
  DataGovernance
  Kaizala
  SecurityComplianceAlerts
  ThreatIntelligenceUrl
  SecurityComplianceInsights
  MIPLabel
  WorkplaceAnalytics
  PowerAppsApp
  PowerAppsPlan
  ThreatIntelligenceAtpContent
  LabelContentExplorer
  TeamsHealthcare
  ExchangeItemAggregated
  HygieneEvent
  DataInsightsRestApiAudit
  InformationBarrierPolicyApplication
  SharePointListItemOperation
  SharePointContentTypeOperation
  SharePointFieldOperation
  MicrosoftTeamsAdmin
  HRSignal
  MicrosoftTeamsDevice
  MicrosoftTeamsAnalytics
  InformationWorkerProtection
  Campaign
  DLPEndpoint
  AirInvestigation
  Quarantine
  MicrosoftForms
  ApplicationAudit
  ComplianceSupervisionExchange
  CustomerKeyServiceEncryption
  OfficeNative
  MipAutoLabelSharePointItem
  MipAutoLabelSharePointPolicyLocation
  MicrosoftTeamsShifts
  SecureScore
  MipAutoLabelExchangeItem
  CortanaBriefing
  Search
  WDATPAlerts
  PowerPlatformAdminDlp
  PowerPlatformAdminEnvironment
  MDATPAudit
  SensitivityLabelPolicyMatch
  SensitivityLabelAction
  SensitivityLabeledFileAction
  AttackSim
  AirManualInvestigation
  SecurityComplianceRBAC
  UserTraining
  AirAdminActionInvestigation
  MSTIC
  PhysicalBadgingSignal
  TeamsEasyApprovals
  AipDiscover
  AipSensitivityLabelAction
  AipProtectionAction
  AipFileDeleted
  AipHeartBeat
  MCASAlerts
  OnPremisesFileShareScannerDlp
  OnPremisesSharePointScannerDlp
  ExchangeSearch
  SharePointSearch
  PrivacyDataMinimization
  LabelAnalyticsAggregate
  MyAnalyticsSettings
  SecurityComplianceUserChange
  ComplianceDLPExchangeClassification
  ComplianceDLPEndpoint
  MipExactDataMatch
  MSDEResponseActions
  MSDEGeneralSettings
  MSDEIndicatorsSettings
  MS365DCustomDetection
  MSDERolesSettings
  MAPGAlerts
  MAPGPolicy
  MAPGRemediation
  PrivacyRemediationAction
  PrivacyDigestEmail
  MipAutoLabelSimulationProgress
  MipAutoLabelSimulationCompletion
  MipAutoLabelProgressFeedback
  DlpSensitiveInformationType
  MipAutoLabelSimulationStatistics
  LargeContentMetadata
  Microsoft365Group
  CDPMlInferencingResult
  FilteringMailMetadata
  CDPClassificationMailItem
  CDPClassificationDocument
  OfficeScriptsRunAction
  FilteringPostMailDeliveryAction
  CDPUnifiedFeedback
  TenantAllowBlockList
  ConsumptionResource
  HealthcareSignal
  DlpImportResult
  CDPCompliancePolicyExecution
  MultiStageDisposition
  PrivacyDataMatch
  FilteringDocMetadata
  FilteringEmailFeatures
  PowerBIDlp
  FilteringUrlInfo
  FilteringAttachmentInfo
  CoreReportingSettings
  ComplianceConnector
  PowerPlatformLockboxResourceAccessRequest
  PowerPlatformLockboxResourceCommand
  CDPPredictiveCodingLabel
  CDPCompliancePolicyUserFeedback
  WebpageActivityEndpoint
  OMEPortal
  CMImprovementActionChange
  FilteringUrlClick
  MipLabelAnalyticsAuditRecord
  FilteringEntityEvent
  FilteringRuleHits
  FilteringMailSubmission
  LabelExplorer
  MicrosoftManagedServicePlatform
  PowerPlatformServiceActivity
  ScorePlatformGenericAuditRecord
  FilteringTimeTravelDocMetadata
  Alert
  AlertStatus
  AlertIncident
  IncidentStatus
  Case
  CaseInvestigation
  RecordsManagement
  PrivacyRemediation
  DataShareOperation
  CdpDlpSensitive
  EHRConnector
  FilteringMailGradingResult
  PublicFolder
  PrivacyTenantAuditHistoryRecord
  AipScannerDiscoverEvent
  EduDataLakeDownloadOperation
  M365ComplianceConnector
  MicrosoftGraphDataConnectOperation
  MicrosoftPurview
  FilteringEmailContentFeatures
  PowerPagesSite
  PowerAppsResource
  PlannerPlan
  PlannerCopyPlan
  PlannerTask
  PlannerRoster
  PlannerPlanList
  PlannerTaskList
  PlannerTenantSettings
  ProjectForTheWebProject
  ProjectForTheWebTask
  ProjectForTheWebRoadmap
  ProjectForTheWebRoadmapItem
  ProjectForTheWebProjectSettings
  ProjectForTheWebRoadmapSettings
  QuarantineMetadata
  MicrosoftTodoAudit
  TimeTravelFilteringDocMetadata
  TeamsQuarantineMetadata
  SharePointAppPermissionOperation
  MicrosoftTeamsSensitivityLabelAction
  FilteringTeamsMetadata
  FilteringTeamsUrlInfo
  FilteringTeamsPostDeliveryAction
  MDCAssessments
  MDCRegulatoryComplianceStandards
  MDCRegulatoryComplianceControls
  MDCRegulatoryComplianceAssessments
  MDCSecurityConnectors
  MDADataSecuritySignal
  VivaGoals
  FilteringRuntimeInfo
  AttackSimAdmin
  MicrosoftGraphDataConnectConsent
  FilteringAtpDetonationInfo
  PrivacyPortal
  ManagedTenants
  UnifiedSimulationMatchedItem
  UnifiedSimulationSummary
  UpdateQuarantineMetadata
  MS365DSuppressionRule
  PurviewDataMapOperation
  FilteringUrlPostClickAction
  IrmUserDefinedDetectionSignal
  TeamsUpdates
  PlannerRosterSensitivityLabel
  MS365DIncident
  FilteringDelistingMetadata
  ComplianceDLPSharePointClassificationExtended
  MicrosoftDefenderForIdentityAudit
  SupervisoryReviewDayXInsight
  DefenderExpertsforXDRAdmin
  CDPEdgeBlockedMessage
  HostedRpa

Extract specific audit logs
^^^^^^^^^^^
Makes it possible to extract a group of specific unified audit activities out of a Microsoft 365 environment. You can for example extract all Inbox Rules or Azure Changes in one go.

Usage
""""""""""""""""""""""""""
Gets the New-InboxRule logging from the unified audit log:
::

   Get-UALSpecificActivity -ActivityType New-InboxRule

Gets the Sharepoint FileDownload logging from the unified audit log for the user Test@invictus-ir.com:
::

  Get-UALSpecificActivity -ActivityType FileDownloaded -UserIds "Test@invictus-ir.com"
  
Gets the Add Service Principal. logging from the unified audit log for the uses Test@invictus-ir.com and HR@invictus-ir.com:
::

   Get-UALSpecificActivity -ActivityType "Add service principal." -UserIds "Test@invictus-ir.com,HR@invictus-ir.com"

Gets all the MailItemsAccessed logging from the unified audit log for the user Test@invictus-ir.com in JSON format with a time interval of 720:
::

   Get-UALSpecificActivity -ActivityType MailItemsAccessed -UserIds Test@invictus-ir.com -StartDate 25/3/2023 -EndDate 5/4/2023 -Interval 720 -Output JSON

Parameters
""""""""""""""""""""""""""
-ActivityType (required)
    - The ActivityType parameter filters the log entries by operation or activity type.
	- Options are: New-MailboxRule, MailItemsAccessed, etc. A total of 108 common ActivityTypes are supported.

-UserIds (optional)
    - UserIds is the UserIds parameter filtering the log entries by the account of the user who performed the actions.

-StartDate (optional)
    - StartDate is the parameter specifying the start date of the date range.
    - Default: Today -90 days

-EndDate (optional)
    - EndDate is the parameter specifying the end date of the date range.
    - Default: Now

-MergeOutput (optional)
    - MergeOutput is the parameter specifying if you wish to merge CSV, JSON or SOF-ELK outputs to a single file.

-Interval (optional)
    - Interval is the parameter specifying the interval in which the logs are being gathered.
    - Default: 60 minutes

-Output (optional)
    - Output is the parameter specifying the CSV, JSON or SOF-ELK output type.
    - The SOF-ELK output type can be used to export logs in a format suitable for the [platform of the same name](https://github.com/philhagen/sof-elk).
    - Default: CSV

-OutputDir (optional)
    - OutputDir is the parameter specifying the output directory.
    - Default: Output\UnifiedAuditLog

-Encoding (optional)
    - Encoding is the parameter specifying the encoding of the CSV/JSON output file.
    - Default: UTF8

.. note::

  **Important note** regarding the StartDate and EndDate variables. 

- When you do not specify a timestamp, the script will automatically default to midnight (00:00) of that day.
- If you provide a timestamp, it will be converted to the corresponding UTC time. For example, if your local timezone is UTC+2, a timestamp like 2023-01-01 08:15:00 will be converted to 2023-01-01 06:15:00 in UTC.
- To specify a date and time without conversion, please use the ISO 8601 format with UTC time (e.g., 2023-01-01T08:15:00Z). This format will retrieve data from January 1st, 2023, starting from a quarter past 8 in the morning until the specified end date.

Output
""""""""""""""""""""""""""
The output will be saved to the 'Name of the Activity' directory within the 'Output' directory.