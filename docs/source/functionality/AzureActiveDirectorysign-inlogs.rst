Azure Active Directory sign-in logs
=======
Use **Get-ADSignInLogs** to collect the contents of the Azure Active Directory sign-in log.

Usage
""""""""""""""""""""""""""
Running the script without any parameters will gather the Azure Active Directory sign-in log for the last 30 days:
::

   Get-ADSignInLogs

Get the Azure Active Directory Audit Log before 2023-04-12:
::

   Get-ADSignInLogs -Before 2023-04-12

Get the Azure Active Directory Audit Log after 2023-04-12:
::

   Get-ADSignInLogs -After 2023-04-12

Parameters
""""""""""""""""""""""""""
-After (optional)
    - After is the parameter specifying the start date of the date range. The time format supported is limited to yyyy-mm-dd only.

-Before (optional)
    - EndDate is the parameter specifying the end date of the date range. The time format supported is limited to yyyy-mm-dd only.

-OutputDir (optional)
    - OutputDir is the parameter specifying the output directory.
    - Default: Output\AzureAD

Output
""""""""""""""""""""""""""
The output will be saved to the 'AzureAD' directory within the 'Output' directory, with the file name 'SignInLogs.json'. Each time an acquisition is performed, the output JSON file will be overwritten. Therefore, if you perform multiple acquisitions, the JSON file will only contain the results from the latest acquisition.
