Azure Audit Logs via Graph API
=======
Use **Get-ADAuditLogsGraph** to collect the contents of the Azure Active Directory Audit Log.

Usage
""""""""""""""""""""""""""
Running the script without any parameters will gather the Azure Active Directory Audit Log for the last 30 days:
::

   Get-ADAuditLogsGraph

Get the Azure Active Directory Audit Log before 2023-04-12:
::

   Get-ADAuditLogsGraph -startDate 2023-04-12

Get the Azure Active Directory Audit Log after 2023-04-12:
::

   Get-ADAuditLogsGraph -endDate 2023-04-12

Get sign-in logs for 'user@example.com', including both userPrincipalName and targetResources in the filter:
::

   Get-ADAuditLogsGraph -UserIds 'user@example.com' -All

Parameters
""""""""""""""""""""""""""
-startDate (optional)
    - startDate is the parameter specifying the start date of the date range.

-endDate (optional)
    - endDate is the parameter specifying the end date of the date range.

-OutputDir (optional)
    - OutputDir is the parameter specifying the output directory.
    - Default: The output will be written to: "Output\AzureAD\{date_AuditLogs}\Auditlogs.json

-MergeOutput (optional)
    - MergeOutput is the parameter specifying if you wish to merge CSV outputs to a single file.

-Encoding (optional)
    - Encoding is the parameter specifying the encoding of the JSON output file.
    - Default: UTF8

-UserIds (optional)
    - UserIds is the UserIds parameter filtering the log entries by the account of the user who performed the actions.

-All (optional)
    - When specified along with UserIds, this parameter filters the results to include events where the provided UserIds match any user principal name found in either the userPrincipalNames or targetResources fields.

Output
""""""""""""""""""""""""""
The output will be saved to the 'AzureAD' directory within the 'Output' directory, with the file name 'AuditlogsGraph.json'. Each time an acquisition is performed, the output JSON file will be overwritten. Therefore, if you perform multiple acquisitions, the JSON file will only contain the results from the latest acquisition.

.. note::

Permissions
""""""""""""""""""""""""""

- Before utilizing this function, it is essential to ensure that the appropriate permissions have been granted. This function relies on the Microsoft Graph API and requires an application or user to authenticate with specific scopes that grant the necessary access levels.
- Make sure to connect using at least one of the following permissions: "AuditLog.Read.All", "Directory.Read.All".
- For instance, if you choose to use User.Read.All, your command would look like this: Connect-MgGraph -Scopes "Directory.Read.All"