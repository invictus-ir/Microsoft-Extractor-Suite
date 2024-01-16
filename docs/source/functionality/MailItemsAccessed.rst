MailItemsAccessed
=======
This section comprises a variety of functions designed to gather information session ID(s) and/or Internet Message ID(s) assosiated with a threat actor. This information can be used to find and download all messages and their attachments.

Find SessionID(s) in the Unified Audit Log.
^^^^^^^^^^^
Find SessionID(s) in the Unified Audit Log. You can filter based on IP address or Username. The first step is to identify what sessions belong to the threat actor. 

Usage
""""""""""""""""""""""""""
Collects all sessions for all users between 1/4/2023 and 5/4/2023.
::

   Get-Sessions -StartDate 1/4/2023 -EndDate 5/4/2023

Collects all sessions for the user HR@invictus-ir.com.
::

   Get-Sessions Get-Sessions -StartDate 1/4/2023 -EndDate 5/4/2023 -UserIds HR@invictus-ir.com

Parameters
""""""""""""""""""""""""""
-UserIds (optional)
    - UserIds is the UserIds parameter filtering the log entries by the account of the user who performed the actions.

-StartDate (Mandatory)
    - StartDate is the parameter specifying the start date of the date range.

-EndDate (Mandatory)
    - EndDate is the parameter specifying the end date of the date range.

-Output (optional)
    - "Y" or "N" to specify whether the output should be saved to a file.
    - Default: Y

-IP (optional)
    - The IP address parameter is used to filter the logs by specifying the desired IP address.

-OutputDir (optional)
    - OutputDir is the parameter specifying the output directory.
    - Default: MailItemsAccessed

-Encoding (optional)
    - Encoding is the parameter specifying the encoding of the CSV/JSON output file.
    - Default: UTF8

Output
""""""""""""""""""""""""""
The output will be saved to the 'MailItemsAccessed' directory within the 'Output' directory.

Find the InternetMessageID(s).
^^^^^^^^^^^
Find the InternetMessageID(s). You can filter on SessionID(s) or IP addresses. After you identified the session(s) of the threat actor, you can use this information to find all MessageID(s).

Usage
""""""""""""""""""""""""""
Collects all sessions for all users between 1/4/2023 and 5/4/2023.
::

   Get-MessageIDs -StartDate 1/4/2023 -EndDate 5/4/2023

Collects all sessions for the user HR@invictus-ir.com.
::

   Get-MessageIDs -StartDate 1/4/2023 -EndDate 5/4/2023 -UserIds HR@invictus-ir.com

Parameters
""""""""""""""""""""""""""
-StartDate (Mandatory)
    - StartDate is the parameter specifying the start date of the date range.

-EndDate (Mandatory)
    - EndDate is the parameter specifying the end date of the date range.

-Output (optional)
    - "Y" or "N" to specify whether the output should be saved to a file.
    - Default: Y

-IP (optional)
    - The IP address parameter is used to filter the logs by specifying the desired IP address.

-Download (optional)
    - To specifiy whether the messages and their attachments should be saved.
    - Default: No

-SessionID (optional)
    - The sessionsID parameter is used to filter the logs by specifying the desired session id.

-OutputDir (optional)
    - OutputDir is the parameter specifying the output directory.
    - Default: MailItemsAccessed

-Encoding (optional)
    - Encoding is the parameter specifying the encoding of the CSV/JSON output file.
    - Default: UTF8

Output
""""""""""""""""""""""""""
The output will be saved to the 'MailItemsAccessed' directory within the 'Output' directory.