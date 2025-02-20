Entra ID Audit Logs via Graph API
=======
Use **Get-GraphEntraAuditLogs** to collect the contents of the Entra ID Audit Log.

Usage
""""""""""""""""""""""""""
Running the script without any parameters will gather the Entra ID Audit Log for the last 30 days:
::

   Get-GraphEntraAuditLogs

Get the Entra ID Audit Log before 2024-04-12:
::

   Get-GraphEntraAuditLogs -startDate 2024-04-12

Get the Entra ID Audit Log after 2024-04-12:
::

   Get-GraphEntraAuditLogs -endDate 2024-04-12

Get sign-in logs for 'user@example.com', including both userPrincipalName and targetResources in the filter:
::

   Get-GraphEntraAuditLogs -UserIds 'user@example.com' -All

Parameters
""""""""""""""""""""""""""
-startDate (optional)
    - startDate is the parameter specifying the start date of the date range.

-endDate (optional)
    - endDate is the parameter specifying the end date of the date range.

-OutputDir (optional)
    - OutputDir is the parameter specifying the output directory.
    - Default: The output will be written to: "Output\EntraID\{date_AuditLogs}\Auditlogs.json

-MergeOutput (optional)
    - MergeOutput is the parameter specifying if you wish to merge CSV outputs to a single file.

-Encoding (optional)
    - Encoding is the parameter specifying the encoding of the JSON output file.
    - Default: UTF8

-Output (optional)
    - Output is the parameter specifying the JSON or SOF-ELK output type.
    - The SOF-ELK output type can be used to export logs in a format suitable for the [platform of the same name](https://github.com/philhagen/sof-elk).
    - Default: JSON

-UserIds (optional)
    - UserIds is the UserIds parameter filtering the log entries by the account of the user who performed the actions.

-All (optional)
    - When specified along with UserIds, this parameter filters the results to include events where the provided UserIds match any user principal name found in either the userPrincipalNames or targetResources fields.

-LogLevel (optional)
    - Specifies the level of logging. None: No logging. Minimal: Logs critical errors only. Standard: Normal operational logging.
    - Default: Standard

-Output (optional)
    - Output is the parameter specifying the JSON or SOF-ELK output type.
    - The SOF-ELK output type can be used to export logs in a format suitable for the [platform of the same name](https://github.com/philhagen/sof-elk).
    - Default: JSON

Output
""""""""""""""""""""""""""
The output will be saved to the 'EntraID' directory within the 'Output' directory, with the file name 'AuditlogsGraph.json'. Each time an acquisition is performed, the output JSON file will be overwritten. Therefore, if you perform multiple acquisitions, the JSON file will only contain the results from the latest acquisition.

.. note::

Permissions
""""""""""""""""""""""""""

- Before utilizing this function, it is essential to ensure that the appropriate permissions have been granted. This function relies on the Microsoft Graph API and requires an application or user to authenticate with specific scopes that grant the necessary access levels.
- Make sure to connect using at least one of the following permissions: "AuditLog.Read.All", "Directory.Read.All".
- For instance, if you choose to use User.Read.All, your command would look like this: Connect-MgGraph -Scopes "Directory.Read.All"