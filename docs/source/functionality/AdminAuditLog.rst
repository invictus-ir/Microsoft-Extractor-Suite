Admin Audit Log
=======

Use **Get-AdminAuditLog** to collect the contents of the administrator audit log. Administrator audit logging records when a user or administrator makes a change in your organization (in the Exchange admin center or by using cmdlets).

Usage
""""""""""""""""""""""""""
Running the script without any parameters will gather the Admin Audit log for the last 90 days for all users:
::

   Get-AdminAuditLog

Get the admin audit log between 1/4/2023 and 5/4/2023:
::

   Get-AdminAuditLog -StartDate 1/4/2023 -EndDate 5/4/2023

Parameters
""""""""""""""""""""""""""
-StartDate (optional)
    - StartDate is the parameter specifying the start date of the date range.
    - Default: Today -90 days

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
The output will be saved to the 'AdminAuditLog' directory within the 'Output' directory, with the file name 'AdminAuditLog.csv'.