Admin Audit Log
=======

Use **Get-AdminAuditLog** to collect the contents of the administrator audit log. Administrator audit logging records when a user or administrator makes a change in your organization (in the Exchange admin center or by using cmdlets).


.. note::

   The Exchange Online PowerShell cmdlet Search-AdminAuditLog is deprecated. The Get-AdminAuditLog function now uses Search-UnifiedAuditLog with RecordType 'ExchangeAdmin' to retrieve the admin audit logging.


Usage
""""""""""""""""""""""""""
Running the script without any parameters will gather the Admin Audit log for the last 90 days for all users:
::

   Get-AdminAuditLog

Get the admin audit log between 1/4/2024 and 5/4/2024:
::

   Get-AdminAuditLog -StartDate 1/4/2024 -EndDate 5/4/2024

Parameters
""""""""""""""""""""""""""
-StartDate (optional)
    - StartDate is the parameter specifying the start date of the date range.
    - Default: Today -90 days

-EndDate (optional)
    - EndDate is the parameter specifying the end date of the date range.
    - Default: Now

-OutputDir (optional)
    - OutputDir is the parameter specifying the output directory.
    - Default: Output\AdminAuditLog

-Output (optional)
    - Output is the parameter specifying the CSV, JSON or SOF-ELK output type.
    - The SOF-ELK output type can be used to export logs in a format suitable for the [platform of the same name](https://github.com/philhagen/sof-elk).
    - Default: CSV

-MergeOutput (optional)
    - MergeOutput is the parameter specifying if you wish to merge CSV, JSON or SOF-ELK outputs to a single file.

-UserIds (optional)
    - UserIds is the UserIds parameter filtering the log entries by the account of the user who performed the actions.

-Encoding (optional)
    - Encoding is the parameter specifying the encoding of the CSV output file.
    - Default: UTF8

-LogLevel (optional)
    - Specifies the level of logging. None: No logging. Minimal: Logs critical errors only. Standard: Normal operational logging. Debug: Detailed logging for debugging.
    - Default: Standard

Output
""""""""""""""""""""""""""
The output files will be saved to the specified OutputDir (default: 'Output\AdminAuditLog'). Each file will be named with the format 'AdminAuditLog-[timestamp]' and the appropriate extension (.csv, .json, or .json for SOF-ELK).
When MergeOutput is specified, a single combined file will be created as 'AdminAuditLog-Combined' with the appropriate extension.
