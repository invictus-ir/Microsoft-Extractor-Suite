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

   Get-ADAuditLogsGraph -Before 2023-04-12

Get the Azure Active Directory Audit Log after 2023-04-12:
::

   Get-ADAuditLogsGraph -After 2023-04-12

Parameters
""""""""""""""""""""""""""
-After (optional)
    - After is the parameter specifying the start date of the date range. The time format supported is limited to yyyy-mm-dd only.

-Before (optional)
    - Before is the parameter specifying the end date of the date range. The time format supported is limited to yyyy-mm-dd only.

-OutputDir (optional)
    - OutputDir is the parameter specifying the output directory.
    - Default: Output\AzureAD

-Application (optional)
    - Application is the parameter specifying App-only access (access without a user) for authentication and authorization.
    - Default: Delegated access (access on behalf a user)

-Encoding (optional)
    - Encoding is the parameter specifying the encoding of the JSON output file.
    - Default: UTF8

Output
""""""""""""""""""""""""""
The output will be saved to the 'AzureAD' directory within the 'Output' directory, with the file name 'AuditlogsGraph.json'. Each time an acquisition is performed, the output JSON file will be overwritten. Therefore, if you perform multiple acquisitions, the JSON file will only contain the results from the latest acquisition.