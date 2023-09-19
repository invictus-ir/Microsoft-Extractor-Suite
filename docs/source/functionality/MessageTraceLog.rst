Message Trace Log
=======
Message trace follows email messages as they travel through your Exchange Online organization. You can
determine if a message was received, rejected, deferred, or delivered by the service. It also shows what
actions were taken on the message before it reached its final status.

.. note::

   To search for message data that is greater than 10 days old, use the Start-HistoricalSearch and Get-HistoricalSearch cmdlets.

   The tool allows for a maximum of 5000 received emails and 5000 sent emails to be extracted in a single operation.

Usage
""""""""""""""""""""""""""
Running the script without any parameters will gather the message trace logs for the last 10 days for all users:
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

Get the trace messages for the user test[@]invictus-ir.com between 1/4/2023 and 5/4/2023:
::

   Get-MessageTraceLog -UserIds test[@]invictus-ir.com -StartDate 1/4/2023 -EndDate 5/4/2023

Parameters
""""""""""""""""""""""""""
-UserIds (optional)
    - UserIds is the UserIds parameter filtering the log entries by the account of the user who performed the actions.

-OutputDir (optional)
    - OutputDir is the parameter specifying the output directory.
    - Default: MessageTrace

-Encoding (optional)
    - Encoding is the parameter specifying the encoding of the CSV output file.
    - Default: UTF8

-StartDate (optional)
    - StartDate is the parameter specifying the start date of the date range.
    - Default: Today -10 days

-EndDate (optional)
    - EndDate is the parameter specifying the end date of the date range.
    - Default: Now

.. note::

  **Important note** regarding the StartDate and EndDate variables. 

- When you do not specify a timestamp, the script will automatically default to midnight (00:00) of that day.
- If you provide a timestamp, it will be converted to the corresponding UTC time. For example, if your local timezone is UTC+2, a timestamp like 2023-01-01 08:15:00 will be converted to 2023-01-01 06:15:00 in UTC.
- To specify a date and time without conversion, please use the ISO 8601 format with UTC time (e.g., 2023-01-01T08:15:00Z). This format will retrieve data from January 1st, 2023, starting from a quarter past 8 in the morning until the specified end date.

Output
""""""""""""""""""""""""""
The output will be saved to the 'MessageTrace' directory within the 'Output' directory, with the file name '[email]+[date].csv'.