Azure Active Directory Audit Log
=======
Use **Get-ADAuditLogs** to collect the contents of the Azure Active Directory Audit Log.

.. note::

    This GraphAPI functionality is currently in beta. If you encounter any issues or have suggestions for improvements please let us know.

Usage
""""""""""""""""""""""""""
Running the script without any parameters will gather the Azure Active Directory Audit Log for the last 7 days (Entra ID Free) or 30 days (Entra ID P1+P2):
::

   Get-ADAuditLogs

Get the Azure Active Directory Audit Log before 2023-04-12:
::

   Get-ADAuditLogs -Before 2023-04-12

Get the Azure Active Directory Audit Log after 2023-04-12:
::

   Get-ADAuditLogs -After 2023-04-12

Parameters
""""""""""""""""""""""""""
-After (optional)
    - After is the parameter specifying the start date of the date range. The time format supported is limited to yyyy-mm-dd only.

-Before (optional)
    - EndDate is the parameter specifying the end date of the date range. The time format supported is limited to yyyy-mm-dd only.

-OutputDir (optional)
    - OutputDir is the parameter specifying the output directory.
    - Default: Output\AzureAD

-Encoding (optional)
    - Encoding is the parameter specifying the encoding of the JSON output file.
    - Default: UTF8

Output
""""""""""""""""""""""""""
The output will be saved to the 'AzureAD' directory within the 'Output' directory, with the file name 'Auditlogs.json'. Each time an acquisition is performed, the output JSON file will be overwritten. Therefore, if you perform multiple acquisitions, the JSON file will only contain the results from the latest acquisition.