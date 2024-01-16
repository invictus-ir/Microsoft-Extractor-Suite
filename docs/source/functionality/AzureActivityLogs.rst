Azure Activity Logs
=======
Use **Get-ActivityLogs** to collect the contents of the Azure Activity Log.

.. note::

    This functionality is currently in beta. If you encounter any issues or have suggestions for improvements please let us know.

Usage
""""""""""""""""""""""""""
Running the script without any parameters will gather the Azure Activity Logs for all subscriptions for the last 89 days:
::

   Get-ActivityLogs

Get all the activity logs before 2023-04-12:
::

   Get-ActivityLogs -EndDate 2023-04-12

Get all the activity logs after 2023-04-12:
::

   Get-ActivityLogs -StartDate 2023-04-12

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
    - Default: Output\AzureActivityLogs

-Encoding (optional)
    - Encoding is the parameter specifying the encoding of the JSON output file.
    - Default: UTF8

Output
""""""""""""""""""""""""""
The output will be saved to the 'AzureAD' directory within the 'Output' directory, with the file name 'SignInLogs.json'. Each time an acquisition is performed, the output JSON file will be overwritten. Therefore, if you perform multiple acquisitions, the JSON file will only contain the results from the latest acquisition.
