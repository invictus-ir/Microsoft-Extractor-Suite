Entra ID Audit Logs
=======
Use **Get-EntraAuditLogs** to collect the contents of the Entra ID Audit Log.

.. note::

    This GraphAPI functionality is currently in beta. If you encounter any issues or have suggestions for improvements please let us know.

Usage
""""""""""""""""""""""""""
Running the script without any parameters will gather the Entra ID Audit Log for the last 7 days (Entra ID Free) or 30 days (Entra ID P1+P2):
::

   Get-EntraAuditLogs

Get theEntra ID Audit Log before 2024-04-12:
::

   Get-EntraAuditLogs -endDate 2024-04-12

Get the Entra ID Audit Log after 2024-04-12:
::

   Get-EntraAuditLogs -startDate 2024-04-12

Parameters
""""""""""""""""""""""""""
-startDate (optional)
    - startDate is the parameter specifying the start date of the date range.

-endDate (optional)
    - endDate is the parameter specifying the end date of the date range.

-OutputDir (optional)
    - OutputDir is the parameter specifying the output directory.
    - Default: The output will be written to: "Output\EntraID\{date_AuditLogs}\Auditlogs.json

-Encoding (optional)
    - Encoding is the parameter specifying the encoding of the JSON output file.
    - Default: UTF8

-MergeOutput (optional)
    - MergeOutput is the parameter specifying if you wish to merge CSV outputs to a single file.

-Interval (optional)
    - Interval is the parameter specifying the interval in which the logs are being gathered.
    - Default: 720 minutes

-LogLevel (optional)
    - Specifies the level of logging. None: No logging. Minimal: Logs critical errors only. Standard: Normal operational logging. Debug: Detailed logging for debugging.
    - Default: Standard

Output
""""""""""""""""""""""""""
The output will be saved to the 'EntraID' directory within the 'Output' directory, with the file name 'Auditlogs.json'. 