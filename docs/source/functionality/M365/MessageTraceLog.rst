Message Trace Log
=======
Message trace follows email messages as they travel through your Exchange Online organization. You can
determine if a message was received, rejected, deferred, or delivered by the service. It also shows what
actions were taken on the message before it reached its final status.

This tool uses the Get-MessageTraceV2 cmdlet which allows querying up to 90 days of message trace data. The tool handles pagination (5000 records per page) and the 10-day query window limitation automatically.

Usage
""""""""""""""""""""""""""
Running the script without any parameters will gather the message trace logs for all users for the past 90 days:
::

   Get-MessageTraceLog

Get the trace messages for the user HR[@]invictus-ir.com:
::

   Get-MessageTraceLog -UserIds HR[@]invictus-ir.com

Get the trace messages for the users HR[@]invictus-ir.com and test[@]invictus-ir.com:
::

   Get-MessageTraceLog -UserIds "test@invictus-ir.com,HR@invictus-ir.com"

Get the trace messages for the full @invictus-ir.com domain:
::

   Get-MessageTraceLog -UserIds "*@invictus-ir.com"

Get the trace messages for the user test[@]invictus-ir.com between 1/4/2024 and 5/4/2024:
::

   Get-MessageTraceLog -UserIds test[@]invictus-ir.com -StartDate 1/4/2024 -EndDate 5/4/2024

Parameters
""""""""""""""""""""""""""
-UserIds (optional)
    - Filters the log entries by the account of the user who performed the actions.
    - Can be a single user, multiple comma-separated users, or a domain using wildcard (*)

-OutputDir (optional)
    - OutputDir is the parameter specifying the output directory.
    - Default: Output\MessageTrace

-Encoding (optional)
    - Encoding is the parameter specifying the encoding of the CSV output file.
    - Default: UTF8

-StartDate (optional)
    - StartDate is the parameter specifying the start date of the date range.
    - Default: Today minus 90 days

-EndDate (optional)
    - EndDate is the parameter specifying the end date of the date range.
    - Default: Now

-LogLevel (optional)
    - Specifies the level of logging. None: No logging. Minimal: Logs critical errors only. Standard: Normal operational logging. Debug: Detailed logging for debugging.
    - Default: Standard

.. note::

  **Important note** regarding the StartDate and EndDate variables. 

- When you do not specify a timestamp, the script will automatically default to midnight (00:00) of that day.
- If you provide a timestamp, it will be converted to the corresponding UTC time. For example, if your local timezone is UTC+2, a timestamp like 2024-01-01 08:15:00 will be converted to 2024-01-01 06:15:00 in UTC.
- To specify a date and time without conversion, please use the ISO 8601 format with UTC time (e.g., 2024-01-01T08:15:00Z). This format will retrieve data from January 1st, 2024, starting from a quarter past 8 in the morning until the specified end date.

Output
""""""""""""""""""""""""""
For queries targeting all users, the output will be saved as:
Output\MessageTrace\YYYYMMDDHHMM-AllUsers-MTL.csv

For specific user or domain queries, the output will be saved as:
Output\MessageTrace\[email/domain]-MTL.csv