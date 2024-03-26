Azure Audit Logs via Graph API
=======
Use **Get-ADAuditLogsGraph** to collect the contents of the Azure Active Directory Audit Log.

.. note::

    This GraphAPI functionality is currently in beta. If you encounter any issues or have suggestions for improvements please let us know.

Usage
""""""""""""""""""""""""""
Running the script without any parameters will gather the Azure Active Directory Audit Log for the last 90 days:
::

   Get-ADAuditLogsGraph

Get the Azure Active Directory Audit Log before 2023-04-12:
::

   Get-ADAuditLogsGraph -startDate 2023-04-12

Get the Azure Active Directory Audit Log after 2023-04-12:
::

   Get-ADAuditLogsGraph -endDate 2023-04-12

Parameters
""""""""""""""""""""""""""
-startDate (optional)
    - startDate is the parameter specifying the start date of the date range. The time format supported is limited to yyyy-mm-dd only.

-endDate (optional)
    - endDate is the parameter specifying the end date of the date range. The time format supported is limited to yyyy-mm-dd only.

-OutputDir (optional)
    - OutputDir is the parameter specifying the output directory.
    - Default: Output\AzureAD

-Application (optional)
    - Application is the parameter specifying App-only access (access without a user) for authentication and authorization.
    - Default: Delegated access (access on behalf a user)

-Encoding (optional)
    - Encoding is the parameter specifying the encoding of the JSON output file.
    - Default: UTF8

-MergeOutput (optional)
    - MergeOutput is the parameter specifying if you wish to merge CSV outputs to a single file.
    - Default: No

-UserIds (optional)
    - UserIds is the UserIds parameter filtering the log entries by the account of the user who performed the actions.

Output
""""""""""""""""""""""""""
The output will be saved to the 'AzureAD' directory within the 'Output' directory, with the file name 'AuditlogsGraph.json'. Each time an acquisition is performed, the output JSON file will be overwritten. Therefore, if you perform multiple acquisitions, the JSON file will only contain the results from the latest acquisition.

.. note::

Permissions
""""""""""""""""""""""""""

- Before utilizing this function, it is essential to ensure that the appropriate permissions have been granted. This function relies on the Microsoft Graph API and requires an application or user to authenticate with specific scopes that grant the necessary access levels.
- Make sure to connect using at least one of the following permissions: "AuditLog.Read.All", "Directory.Read.All".
- For instance, if you choose to use User.Read.All, your command would look like this: Connect-MgGraph -Scopes "Directory.Read.All"