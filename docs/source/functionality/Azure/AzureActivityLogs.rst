Azure Activity Logs
=======
Use **Get-ActivityLogs** to collect the contents of the Azure Activity Log.

Usage
""""""""""""""""""""""""""
Running the script without any parameters will gather the Azure Activity Logs for all subscriptions for the last 89 days:
::

   Get-ActivityLogs

Get all the activity logs before 2024-03-04:
::

   Get-ActivityLogs -EndDate 2024-06-05

Get all the activity logs after 2024-06-05:
::

   Get-ActivityLogs -StartDate 2024-06-05

Get all the activity logs for the subscription 4947f939-cf12-4329-960d-4dg68a3eb66f:
::

   Get-ActivityLogs -SubscriptionID "4947f939-cf12-4329-960d-4dg68a3eb66f"

Parameters
""""""""""""""""""""""""""
-StartDate (optional)
    - StartDate is the parameter specifying the start date of the date range.
    - Default: Today -89 days

-EndDate (optional)
    - EndDate is the parameter specifying the end date of the date range.
    - Default: Now

-SubscriptionID (optional)
    - SubscriptionID is the parameter specifies the subscription ID for which the collection of Activity logs is required.
    - Default: All subscriptions

-OutputDir (optional)
    - OutputDir is the parameter specifying the output directory.
    - Default: Output\ActivityLogs

-Encoding (optional)
    - Encoding is the parameter specifying the encoding of the JSON output file.
    - Default: UTF8

-LogLevel (optional)
    - Specifies the level of logging. None: No logging. Minimal: Logs critical errors only. Standard: Normal operational logging.
    - Default: Standard

Output
""""""""""""""""""""""""""
The output will be saved to the 'ActivityLogs' directory within the 'Output' directory, with the file name 'ActivityLog.json'.