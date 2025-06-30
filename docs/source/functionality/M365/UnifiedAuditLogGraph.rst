Unified Audit Log via Graph API
=======

The UAL is a critical piece of evidence in a BEC investigation because it is a centralized source for
all Office 365 events. The UAL contains at least 353 categories of data, including events from Azure,
Exchange, SharePoint, OneDrive, and Skype.

.. note::

  Audit (Standard) - Audit records are retained for 180 days.
  
  Audit (Premium) - Audit records are retained for 365 days. 

Extract the Unified Audit Logs
^^^^^^^^^^^
Extract the Unified Audit Logs within the specified timeframe and export them.

Usage
""""""""""""""""""""""""""
Running the script without any parameters will gather the Unified Audit log for the last 90 days for all users:
::

   Get-UALGraph -SearchName Test 

Gets all the unified audit log entries for the user Test@invictus-ir.com:
::

   Get-UALGraph -SearchName Test -UserIds Test@invictus-ir.com

Retrieves audit log data for the specified time range March 10, 2024 to March 20, 2024 and filters the results to include only events related to the Exchange service:
::

   Get-UALGraph -SearchName Scan1GraphAPI -startDate "2024-03-10T09:28:56Z" -endDate "2024-03-20T09:28:56Z" -Service Exchange
  
Retrieve audit log data for the specified time range March 1, 2024 to March 10, 2024 and filter the results to include only entries associated with the IP address 182.74.242.26:
::

   Get-UALGraph -searchName scan1 -startDate "2024-03-01" -endDate "2024-03-10" -IPAddress 182.74.242.26

Parameters
""""""""""""""""""""""""""
-SearchName (required)
    - Specifies the name of the search query. This parameter is required.

-UserIds (optional)
    - UserIds is the UserIds parameter filtering the log entries by the account of the user who performed the actions.

-StartDate (optional)
    - StartDate is the parameter specifying the start date of the date range.
    - Default: Today -180 days

-EndDate (optional)
    - EndDate is the parameter specifying the end date of the date range.
    - Default: Now

-IPAddress (optional)
    - The IP address parameter is used to filter the logs by specifying the desired IP address.

-Operations (optional)
    - The Operations parameter filters the log entries by operation or activity type. Usage: -Operations UserLoggedIn,MailItemsAccessed
	- Options are: New-MailboxRule, MailItemsAccessed, etc.

-Service (optional)
    - The Service parameter filters the Unified Audit Log based on the specific services.
    - Options are: Exchange,Skype,Sharepoint etc.

-Keyword (optional)
    - The Keyword parameter allows you to filter the Unified Audit Log for specific keywords.

-RecordType (optional)
    - The RecordType parameter filters the log entries by record type.
    - Options are: ExchangeItem, ExchangeAdmin, etc. A total of 353 RecordTypes are supported.

-ObjecIDs (optional)
    - Exact data returned depends on the service in the current `@odatatype.microsoft.graph.security.auditLogQuery` record.
    - For Exchange admin audit logging, the name of the object modified by the cmdlet. 
    - For SharePoint activity, the full URL path name of the file or folder accessed by a user. 
    - For Microsoft Entra activity, the name of the user account that was modified.|

-OutputDir (optional)
    - OutputDir is the parameter specifying the output directory.
    - Default: UnifiedAuditLog

-Encoding (optional)
    - Encoding is the parameter specifying the encoding of the JSON output file.
    - Default: UTF8

-LogLevel (optional)
    - Specifies the level of logging. None: No logging. Minimal: Logs critical errors only. Standard: Normal operational logging. Debug: Detailed logging for debugging.
    - Default: Standard

-Output (optional)
    - Output is the parameter specifying the CSV, JSONL or JSON output type.
    - Default: JSON

-MaxEventsPerFile (optional)
    - Specifies the maximum number of events per output file. When this number is reached, a new file will be created.
    - Default: 250000

-SplitFiles (optional)
    - When specified, splits output into multiple files based on MaxEventsPerFile.
    - Default: If not specified, outputs to a single file.

Permissions
""""""""""""""""""""""""""
- When you do not specify a timestamp, the script will automatically default to midnight (00:00) of that day.
- If you provide a timestamp, it will be converted to the corresponding UTC time. For example, if your local timezone is UTC+2, a timestamp like 2024-01-01 08:15:00 will be converted to 2024-01-01 06:15:00 in UTC.
- To specify a date and time without conversion, please use the ISO 8601 format with UTC time (e.g., 2024-01-01T08:15:00Z). This format will retrieve data from January 1st, 2024, starting from a quarter past 8 in the morning until the specified end date.

Output
""""""""""""""""""""""""""
The output will be saved to the 'UnifiedAuditLog' directory within the 'Output' directory, with the file name '$date-$searchName-UnifiedAuditLog.json'.

Permissions
""""""""""""""""""""""""""
- Before utilizing this function, it is essential to ensure that the appropriate permissions have been granted. This function relies on the Microsoft Graph API and requires an application or user to authenticate with specific scopes that grant the necessary access levels.
- Make sure to connect using the following permission: "AuditLogsQuery.Read.All".
- Your command would look like this: Connect-MgGraph -Scopes 'AuditLogsQuery.Read.All'