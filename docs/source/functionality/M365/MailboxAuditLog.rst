Mailbox Audit Log
=======
Mailbox audit logs are generated for each mailbox that has mailbox audit logging enabled. This tracks all user actions on any items in a mailbox.
Use **Get-MailboxAuditLog** to collect the mailbox audit log for a specific user or all user accounts.

.. note::

   The Exchange Online PowerShell cmdlet Search-MailboxAuditLog is deprecated. The Get-MailboxAuditLog function now uses Search-UnifiedAuditLog with RecordType 'ExchangeItem' to retrieve mailbox audit logging.

Usage
""""""""""""""""""""""""""
Running the script without any parameters will gather the mailbox audit logs for all users for the last 90 days:
::

   Get-MailboxAuditLog

Get mailbox audit log entries for the user HR[@]invictus-ir.com:
::

   Get-MailboxAuditLog -UserIds HR[@]invictus-ir.com

Get mailbox audit log entries for the users HR[@]invictus-ir.com and test[@]invictus-ir.com:
::

   Get-MailboxAuditLog -UserIds "test@invictus-ir.com,HR@invictus-ir.com"

Get mailbox audit log entries for the user test@invictus-ir.com between 1/4/2025 and 5/4/2025:
::

   Get-MailboxAuditLog -UserIds test[@]invictus-ir.com -StartDate 1/4/2025 -EndDate 5/4/2025

Parameters
""""""""""""""""""""""""""
-UserIds (optional)
    - UserIds is the UserIds parameter filtering the log entries by the account of the user who performed the actions.
    - Default: All users

-StartDate (optional)
    - StartDate is the parameter specifying the start date of the date range.
    - Default: Today -90 days

-EndDate (optional)
    - EndDate is the parameter specifying the end date of the date range.
    - Default: Now

-OutputDir (optional)
    - OutputDir is the parameter specifying the output directory.
    - Default: Output\MailboxAuditLog

-Output (optional)
    - Output is the parameter specifying the CSV, JSON or SOF-ELK output type.
    - The SOF-ELK output type can be used to export logs in a format suitable for the [platform of the same name](https://github.com/philhagen/sof-elk).
    - Default: CSV

-MergeOutput (optional)
    - MergeOutput is the parameter specifying if you wish to merge CSV, JSON or SOF-ELK outputs to a single file.

-Encoding (optional)
    - Encoding is the parameter specifying the encoding of the CSV output file.
    - Default: UTF8

-LogLevel (optional)
    - Specifies the level of logging. None: No logging. Minimal: Logs critical errors only. Standard: Normal operational logging. Debug: Detailed logging for debugging.
    - Default: Standard

Output
""""""""""""""""""""""""""
The output files will be saved to the specified OutputDir (default: 'Output\MailboxAuditLog'). Each file will be named with the format 'MailboxAuditLog-[timestamp]' and the appropriate extension (.csv, .json, or .json for SOF-ELK).

When MergeOutput is specified, a single combined file will be created as 'MailboxAuditLog-Combined' with the appropriate extension.
