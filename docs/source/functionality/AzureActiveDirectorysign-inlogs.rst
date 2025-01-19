Azure Entra ID sign-in logs
=======
Use **Get-EntraSignInLogs** to collect the contents of the Azure Entra ID sign-in log.

.. note::

  **Important note** This module requires the Graph Beta module. Install it using the command: 'Install-Module Microsoft.Graph.Beta'.


Usage
""""""""""""""""""""""""""
Running the script without any parameters will gather the Entra ID sign-in log for the last 30 days:
::

   Get-EntraSignInLogs

Get the Entra ID Audit Log before 2024-04-12:
::

   Get-EntraSignInLogs -endDate 2024-04-12

Get the Entra ID Audit Log after 2024-04-12:
::

   Get-EntraSignInLogs -startDate 2024-04-12

Parameters
""""""""""""""""""""""""""
-startDate (optional)
    - startDate is the parameter specifying the start date of the date range.

-endDate (optional)
    - endDate is the parameter specifying the end date of the date range.

-OutputDir (optional)
    - OutputDir is the parameter specifying the output directory.
    - Default: The output will be written to: Output\EntraID\{date_SignInLogs}\SignInLogs.json

-Encoding (optional)
    - Encoding is the parameter specifying the encoding of the JSON output file.
    - Default: UTF8

-UserIds (optional)
    - UserIds is the UserIds parameter filtering the log entries by the account of the user who performed the actions.

-MergeOutput (optional)
    - MergeOutput is the parameter specifying if you wish to merge CSV outputs to a single file.

-UserIds (optional)
    - UserIds is the UserIds parameter filtering the log entries by the account of the user who performed the actions.

-Interval (optional)
    - Interval is the parameter specifying the interval in which the logs are being gathered.
    - Default: 1440 minutes

-LogLevel (optional)
    - Specifies the level of logging. None: No logging. Minimal: Logs critical errors only. Standard: Normal operational logging.
    - Default: Standard

Output
""""""""""""""""""""""""""
The output will be saved to the 'AzureAD' directory within the 'Output' directory, with the file name 'SignInLogs.json'.