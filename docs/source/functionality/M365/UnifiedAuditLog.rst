Unified Audit Log
=======

The UAL is a critical piece of evidence in a BEC investigation because it is a centralized source for
all Office 365 events. The UAL contains at least 353 categories of data, including events from Azure,
Exchange, SharePoint, OneDrive, and Skype.

Why does the acquisition take a lot of time?
^^^^^^^^^^^
To retrieve the Unified Audit Log, we use the `Search-UnifiedAuditLog` cmdlet. Unfortunately, there is a limitation of retrieving only 5,000 records per call. If there are more than 5,000 records within the specified time window, only the first 5,000 records are collected, and the rest are ignored.
To address this, our script dynamically reduces the time interval to ensure that no more than 5,000 records are collected per call. It iterates through the time windows until all records are retrieved. For each interval (up to 5,000 records), the script typically makes 2–3 API calls to ensure completeness.
This approach, while effective, results in the script being quite slow due to the number of calls required. If you have any suggestions for optimizing or speeding up the process, we would greatly appreciate your input!

.. note::

  Audit (Standard) - Audit records are retained for 180 days.
  
  Audit (Premium) - Audit records are retained for 365 days. 


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

    Get-UAL -Operation New-InboxRule

Filter logs for specific users:
::

    Get-UAL -UserIds test@invictus-ir.com

Get logs for a specific date range:
::
    
    Get-UAL -StartDate 2026-04-01 -EndDate 2026-04-05 -Group Azure

Get logs in JSON format:
::

    Get-UAL -Output JSON -MergeOutput


Parameters
""""""""""""""""""""""""""
-UserIds (optional)
    - UserIds is the UserIds parameter filtering the log entries by the account of the user who performed the actions.

-StartDate (optional)
    - StartDate is the parameter specifying the start date of the date range.
    - Default: Today -180 days

-EndDate (optional)
    - EndDate is the parameter specifying the end date of the date range.
    - Default: Now

-Interval (optional)
    - Interval is the parameter specifying the interval in which the logs are being gathered.

-Output (optional)
    - Output is the parameter specifying the CSV, JSONL, SOF-ELK or JSON output type.
    - Default: CSV

-MergeOutput (optional)
    - MergeOutput is the parameter specifying if you wish to merge CSV outputs to a single file.

-OutputDir (optional)
    - OutputDir is the parameter specifying the output directory.
    - Default: UnifiedAuditLog

-Encoding (optional)
    - Encoding is the parameter specifying the encoding of the CSV/JSON output file.
    - Default: UTF8

-ObjectIDs (optional)
    - The ObjectIds parameter filters the log entries by object ID. The object ID is the target object that was acted upon, and depends on the RecordType and Operations values of the event.
    
-LogLevel (optional)
    - Specifies the level of logging. None: No logging. Minimal: Logs critical errors only. Standard: Normal operational logging. Debug: Detailed logging for debugging.
    - Default: Standard

-Group (optional)
    - Group is the group of logging needed to be extracted.
	- Options are: Exchange, Azure, Sharepoint, Skype and Defender

-RecordType (optional)
    - The RecordType parameter filters the log entries by record type.
	- Options are: ExchangeItem, ExchangeAdmin, etc. A total of 353 RecordTypes are supported.

-Operation (optional)
    - The Operation parameter filters the log entries by operation or activity type.
	- Options are: New-MailboxRule, MailItemsAccessed, etc.

-TargetEventsPerWindow (optional)
    - The ideal number of events the adaptive algorithm aims to retrieve per window. The Microsoft API caps a single non-session call at 5000 events; this target is what the script steers toward when sizing intervals.
    - Lower values are safer (more headroom below the 5000 cap, fewer cap-hit retries) but produce more API calls.
    - Higher values produce fewer calls but increase the chance of hitting the 5000 cap and having to shrink and refetch.
    - The shrink threshold is derived as TargetEventsPerWindow * 1.5 (clamped just below the 5000 API cap).
    - Must be between 1 and 5000
    - Default: 3000

-AuditDataOnly (optional)
    - AuditDataOnly is a switch parameter that extracts only the AuditData property from each log entry.
    - When enabled, the output will contain only the parsed AuditData JSON content without the wrapper properties (CreationDate, UserIds, Operations, ResultIndex, etc.).
    - This is useful when you only need the actual audit event data and want to reduce file size and improve readability.
    - Works with all output formats: CSV, JSON, JSONL, and SOF-ELK.

-IPAddresses (optional)
    - The IPAddresses parameter filters the log entries by the IP address of the client that performed the action.
    - You can enter multiple values separated by commas.

.. note::

  **Important note** regarding the StartDate and EndDate variables. 

- When you do not specify a timestamp, the script will automatically default to midnight (00:00) of that day.
- If you provide a timestamp, it will be converted to the corresponding UTC time. For example, if your local timezone is UTC+2, a timestamp like 2026-01-01 08:15:00 will be converted to 2026-01-01 06:15:00 in UTC.
- To specify a date and time without conversion, please use the ISO 8601 format with UTC time (e.g., 2026-01-01T08:15:00Z). This format will retrieve data from January 1st, 2026, starting from a quarter past 8 in the morning until the specified end date.

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