User Information
=======
This section comprises a variety of functions designed to gather information about user accounts. These functions include retrieving all users' creation dates and their last password change dates, the risky detections and users, as well as identifying all administrator users and the MFA status of all accounts.

Retrieve information for all users.
^^^^^^^^^^^
Retrieves the creation time and date of the last password change for all users.

Usage
""""""""""""""""""""""""""
Running the script without any parameters retrieves the creation time and date of the last password change for all users.
::

   Get-Users

Retrieves the creation time and date of the last password change for all users and exports the output to a CSV file with UTF-32 encoding.
::

   Get-Users -Encoding utf32

Retrieves the creation time and date of the last password change for all users and saves the output to the C:\Windows\Temp folder.	
::

   Get-Users -OutputDir C:\Windows\Temp

Parameters
""""""""""""""""""""""""""
-OutputDir (optional)
    - OutputDir is the parameter specifying the output directory.
    - Default: UserInfo

-Encoding (optional)
    - Encoding is the parameter specifying the encoding of the CSV/JSON output file.
    - Default: UTF8


Retrieve all Administrator directory roles.
^^^^^^^^^^^
Retrieves Administrator directory roles, including the identification of users associated with each specific role.

Usage
""""""""""""""""""""""""""
Running the script without any parameters retrieves Administrator directory roles, including the identification of users associated with each specific role.
::

   Get-AdminUsers

Retrieves the creation time and date of the last password change for all users and exports the output to a CSV file with UTF-32 encoding.
::

   Get-AdminUsers -Encoding utf32

Retrieves the creation time and date of the last password change for all users and saves the output to the C:\Windows\Temp folder.	
::

   Get-AdminUsers -OutputDir C:\Windows\Temp

Parameters
""""""""""""""""""""""""""
-OutputDir (optional)
    - OutputDir is the parameter specifying the output directory.
    - Default: UserInfo

-Encoding (optional)
    - Encoding is the parameter specifying the encoding of the CSV/JSON output file.
    - Default: UTF8

Retrieves MFA status
^^^^^^^^^^^
Retrieves the MFA status for all users.

Usage
""""""""""""""""""""""""""
Running the script without any parameters retrieves the MFA status for all users.
::

   Get-MFA

Retrieves the MFA status for all users and exports the output to a CSV file with UTF-32 encoding.
::

   Get-MFA -Encoding utf32

Parameters
""""""""""""""""""""""""""
-OutputDir (optional)
    - OutputDir is the parameter specifying the output directory.
    - Default: UserInfo

-Encoding (optional)
    - Encoding is the parameter specifying the encoding of the CSV/JSON output file.
    - Default: UTF8

Retrieves the risky users
^^^^^^^^^^^
Retrieves the risky users from the Entra ID Identity Protection, which marks an account as being at risk based on the pattern of activity for the account.

Usage
""""""""""""""""""""""""""
Running the script without any parameters retrieves all risky users.
::

   Get-RiskyUsers

Parameters
""""""""""""""""""""""""""
-OutputDir (optional)
    - OutputDir is the parameter specifying the output directory.
    - Default: UserInfo

-Encoding (optional)
    - Encoding is the parameter specifying the encoding of the CSV/JSON output file.
    - Default: UTF8

Retrieves the risky detections
^^^^^^^^^^^
Retrieves the risky detections from the Entra ID Identity Protection.

Usage
""""""""""""""""""""""""""
Running the script without any parameters retrieves all the risky detections.
::

   Get-RiskyDetections

Parameters
""""""""""""""""""""""""""
-OutputDir (optional)
    - OutputDir is the parameter specifying the output directory.
    - Default: UserInfo

-Encoding (optional)
    - Encoding is the parameter specifying the encoding of the CSV/JSON output file.
    - Default: UTF8