Azure Sign-in Logs via Graph API
=======
Use **Get-EntraSignInLogsGraph** to collect the contents of the Entra ID sign-in log.

Usage
""""""""""""""""""""""""""
Running the script without any parameters will gather the Entra ID sign-in log for the last 30 days:
::

   Get-EntraSignInLogsGraph

Get the Entra ID Audit Log before 2024-04-12:
::

   Get-EntraSignInLogsGraph -endDate 2024-04-12

Get the Entra ID Audit Log after 2024-04-12:
::

   Get-EntraSignInLogsGraph -startDate 2024-04-12

Get the Azure Active Directory SignIn Log in a sof-elk format and merge all data into a single file:
::

   Get-GraphEntraSignInLogs -Output SOF-ELK -MergeOutput

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

-MergeOutput (optional)
    - MergeOutput is the parameter specifying if you wish to merge CSV outputs to a single file.

-Output (optional)
    - Output is the parameter specifying the JSON or SOF-ELK output type.
    - The SOF-ELK output type can be used to export logs in a format suitable for the [platform of the same name](https://github.com/philhagen/sof-elk).
    - Default: JSON

-UserIds (optional)
    - UserIds is the UserIds parameter filtering the log entries by the account of the user who performed the actions.

-LogLevel (optional)
    - Specifies the level of logging. None: No logging. Minimal: Logs critical errors only. Standard: Normal operational logging.
    - Default: Standard

Output
""""""""""""""""""""""""""
The output will be saved to the 'EntraID' directory within the 'Output' directory, with the file name 'SignInLogsGraph.json'. 

Permissions
""""""""""""""""""""""""""
- Before utilizing this function, it is essential to ensure that the appropriate permissions have been granted. This function relies on the Microsoft Graph API and requires an application or user to authenticate with specific scopes that grant the necessary access levels.
- Make sure to connect using at least one of the following permissions: "AuditLog.Read.All", "Directory.Read.All".
- For instance, if you choose to use User.Read.All, your command would look like this: Connect-MgGraph -Scopes "Directory.Read.All"