Admin Audit Log
=======

Use **Get-AdminAuditLog** to collect the contents of the administrator audit log. Administrator audit logging records when a user or administrator makes a change in your organization (in the Exchange admin center or by using cmdlets).

Usage
""""""""""""""""""""""""""
Running the script without any parameters will gather the Admin Audit log for the last 90 days for all users:
::

   Get-AdminAuditLog

Get the admin audit log between 2023/04/01 and 2023/04/05:
::

   Get-AdminAuditLog -StartDate 2023/04/01 -EndDate 2023/04/05

Parameters
""""""""""""""""""""""""""
-StartDate (optional)
    - StartDate is the parameter specifying the start date of the date range.
    - Default: Today -90 days

-EndDate (optional)
    - EndDate is the parameter specifying the end date of the date range.
    - Default: Now

Output
""""""""""""""""""""""""""
The output will be saved to the 'AdminAuditLog' directory within the 'Output' directory, with the file name 'AdminAuditLog.csv'.
