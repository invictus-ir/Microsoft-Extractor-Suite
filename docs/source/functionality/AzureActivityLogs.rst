Azure Directory Activity Logs
=======
Use **Get-DirectoryActivityLogs** to collect the contents of the Azure Activity Log.

.. note::

    This functionality is currently in beta. If you encounter any issues or have suggestions for improvements please let us know.

Usage
""""""""""""""""""""""""""
Running the script without any parameters will gather the Azure Directory Activity Logs for the last 90 days:
::

   Get-DirectoryActivityLogs

Get all the Directory Activity Logs before 2024-03-05:
::

   Get-DirectoryActivityLogs -EndDate 2024-06-05

Get all the Directory Activity Logs after 2024-06-05:
::

   Get-DirectoryActivityLogs -StartDate 2024-06-05


Parameters
""""""""""""""""""""""""""
-StartDate (optional)
    - StartDate is the parameter specifying the start date of the date range.
    - Default: Today -90 days

-EndDate (optional)
    - EndDate is the parameter specifying the end date of the date range.
    - Default: Now

-Output (optional)
    - Output is the parameter specifying the CSV or JSON output type.
    - Default: CSV

-OutputDir (optional)
    - OutputDir is the parameter specifying the output directory.
    - Default: Output\DirectoryActivityLogs

-Encoding (optional)
    - Encoding is the parameter specifying the encoding of the JSON output file.
    - Default: UTF8

-LogLevel (optional)
    - Specifies the level of logging. None: No logging. Minimal: Logs critical errors only. Standard: Normal operational logging.
    - Default: Standard

Output
""""""""""""""""""""""""""
The output will be saved to the 'DirectoryActivityLogs' directory within the 'Output' directory, with the file name 'DirectoryActivityLogs.csv'. 