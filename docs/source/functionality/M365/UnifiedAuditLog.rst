Unified Audit Log
=======

The UAL is a critical piece of evidence in a BEC investigation because it is a centralized source for
all Office 365 events. The UAL contains at least 236 categories of data, including events from Azure,
Exchange, SharePoint, OneDrive, and Skype.

Why is the acquisition slow?
^^^^^^^^^^^
To retrieve the Unified Audit Log, we use the `Search-UnifiedAuditLog` cmdlet. Unfortunately, there is a limitation of retrieving only 5,000 records per call. If there are more than 5,000 records within the specified time window, only the first 5,000 records are collected, and the rest are ignored.
To address this, our script dynamically reduces the time interval to ensure that no more than 5,000 records are collected per call. It iterates through the time windows until all records are retrieved. For each interval (up to 5,000 records), the script typically makes 2–3 API calls to ensure completeness.
This approach, while effective, results in the script being quite slow due to the number of calls required. If you have any suggestions for optimizing or speeding up the process, we would greatly appreciate your input!

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

Displays the total number of logs within the unified audit log between 1/4/2024 and 5/4/2024 for the user test[@]invictus-ir.com:
::

   Get-UALStatistics -UserIds test[@]invictus-ir.com -StartDate 1/4/2024 -EndDate 5/4/2024

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

-LogLevel (optional)
    - Specifies the level of logging. None: No logging. Minimal: Logs critical errors only. Standard: Normal operational logging.
    - Default: Standard

.. note::

  **Important note** regarding the StartDate and EndDate variables. 

- When you do not specify a timestamp, the script will automatically default to midnight (00:00) of that day.
- If you provide a timestamp, it will be converted to the corresponding UTC time. For example, if your local timezone is UTC+2, a timestamp like 2024-01-01 08:15:00 will be converted to 2024-01-01 06:15:00 in UTC.
- To specify a date and time without conversion, please use the ISO 8601 format with UTC time (e.g., 2024-01-01T08:15:00Z). This format will retrieve data from January 1st, 2024, starting from a quarter past 8 in the morning until the specified end date.

Output
""""""""""""""""""""""""""
The output will be saved to the file 'Amount_Of_Audit_Logs.csv' within the 'Output' directory.

Extract Unified Audit Logs
^^^^^^^^^^^
The Get-UAL function extracts Unified Audit Log from Microsoft 365. You can retrieve all logs, filter by groups (like Exchange or Azure), specific record types, or activities.

Usage
""""""""""""""""""""""""""
Running the script without any parameters will gather all Unified Audit logs for the last 90 days for all users:
::

    Get-UAL

Get Exchange related logs:
::

    Get-UAL -Group Exchange

Get specific Record Types:
::

    Get-UAL -RecordType ExchangeItem

Get specific Activity Types:
::

    Get-UAL -ActivityType New-InboxRule

Filter logs for specific users:
::

    Get-UAL -UserIds test@invictus-ir.com

Get logs for a specific date range:
::
    
    Get-UAL -StartDate 1/4/2024 -EndDate 5/4/2024 -Group Azure

Get logs in JSON format:
::

    Get-UAL -Output JSON -MergeOutput


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

-Output (optional)
    - Output is the parameter specifying the CSV or JSON output type.
    - Default: CSV

-MergeOutput (optional)
    - MergeOutput is the parameter specifying if you wish to merge CSV outputs to a single file.

-OutputDir (optional)
    - OutputDir is the parameter specifying the output directory.
    - Default: UnifiedAuditLog

-Encoding (optional)
    - Encoding is the parameter specifying the encoding of the CSV/JSON output file.
    - Default: UTF8

-ObjecIDs (optional)
    - The ObjectIds parameter filters the log entries by object ID. The object ID is the target object that was acted upon, and depends on the RecordType and Operations values of the event.
	- You can enter multiple values separated by commas.

-LogLevel (optional)
    - Specifies the level of logging. None: No logging. Minimal: Logs critical errors only. Standard: Normal operational logging.
    - Default: Standard

.. note::

  **Important note** regarding the StartDate and EndDate variables. 

- When you do not specify a timestamp, the script will automatically default to midnight (00:00) of that day.
- If you provide a timestamp, it will be converted to the corresponding UTC time. For example, if your local timezone is UTC+2, a timestamp like 2024-01-01 08:15:00 will be converted to 2024-01-01 06:15:00 in UTC.
- To specify a date and time without conversion, please use the ISO 8601 format with UTC time (e.g., 2024-01-01T08:15:00Z). This format will retrieve data from January 1st, 2024, starting from a quarter past 8 in the morning until the specified end date.

Output
""""""""""""""""""""""""""
The output will be saved to the 'UnifiedAuditLog' directory within the 'Output' directory, with the file name 'UAL-[$CurrentStart].[csv/json]'.

Extract group logging
""""""""""""""""""""""""""
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
