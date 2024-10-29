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
    - Default: Users

-Encoding (optional)
    - Encoding is the parameter specifying the encoding of the CSV/JSON output file.
    - Default: UTF8

Output
""""""""""""""""""""""""""
The output will be saved to the 'Users' directory within the 'Output' directory.

Permissions
""""""""""""""""""""""""""
- Before utilizing this function, it is essential to ensure that the appropriate permissions have been granted. This function relies on the Microsoft Graph API and requires an application or user to authenticate with specific scopes that grant the necessary access levels.
- Make sure to connect using at least one of the following permissions: "User.Read.All", "Directory.AccessAsUser.All", "Directory.Read.All".
- For instance, if you choose to use User.Read.All, your command would look like this: Connect-MgGraph -Scopes 'User.Read.All'

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
    - Default: Admins

-Encoding (optional)
    - Encoding is the parameter specifying the encoding of the CSV/JSON output file.
    - Default: UTF8

Output
""""""""""""""""""""""""""
The output will be saved to the 'Admins' directory within the 'Output' directory.

Permissions
""""""""""""""""""""""""""
- Before utilizing this function, it is essential to ensure that the appropriate permissions have been granted. This function relies on the Microsoft Graph API and requires an application or user to authenticate with specific scopes that grant the necessary access levels.
- Make sure to connect using at least one of the following permissions: "User.Read.All", "Directory.AccessAsUser.All", "Directory.Read.All".
- For instance, if you choose to use User.Read.All, your command would look like this: Connect-MgGraph -Scopes 'User.Read.All'

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
    - Default: MFA

-Encoding (optional)
    - Encoding is the parameter specifying the encoding of the CSV/JSON output file.
    - Default: UTF8

Output
""""""""""""""""""""""""""
The output will be saved to the 'MFA' directory within the 'Output' directory.

Permissions
""""""""""""""""""""""""""
- Before utilizing this function, it is essential to ensure that the appropriate permissions have been granted. This function relies on the Microsoft Graph API and requires an application or user to authenticate with specific scopes that grant the necessary access levels.
- Make sure to connect using both of the following permissions: "UserAuthenticationMethod.Read.All",'User.Read.All".
- Your command would look like this: Connect-MgGraph -Scopes 'User.Read.All','UserAuthenticationMethod.Read.All'

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
    - Default: RiskyEvents

-Encoding (optional)
    - Encoding is the parameter specifying the encoding of the CSV/JSON output file.
    - Default: UTF8

-UserIds (optional)
    - An array of User IDs to retrieve risky user information for.
    - Default: If not specified, retrieves all risky users.

Output
""""""""""""""""""""""""""
The output will be saved to the 'RiskyEvents' directory within the 'Output' directory.

Permissions
""""""""""""""""""""""""""
- Before utilizing this function, it is essential to ensure that the appropriate permissions have been granted. This function relies on the Microsoft Graph API and requires an application or user to authenticate with specific scopes that grant the necessary access levels.
- Make sure to connect using the following permission: "IdentityRiskyUser.Read.All".
- Your command would look like this: Connect-MgGraph -Scopes 'IdentityRiskyUser.Read.All'

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
    - Default: RiskyEvents

-Encoding (optional)
    - Encoding is the parameter specifying the encoding of the CSV/JSON output file.
    - Default: UTF8

-UserIds (optional)
    - An array of User IDs to retrieve risky detections information for.
    - Default: If not specified, retrieves all risky detections.

Output
""""""""""""""""""""""""""
The output will be saved to the 'RiskyEvents' directory within the 'Output' directory.

Permissions
""""""""""""""""""""""""""
- Before utilizing this function, it is essential to ensure that the appropriate permissions have been granted. This function relies on the Microsoft Graph API and requires an application or user to authenticate with specific scopes that grant the necessary access levels.
- Make sure to connect using the following permission: "IdentityRiskEvent.Read.All".
- Your command would look like this: Connect-MgGraph -Scopes 'IdentityRiskEvent.Read.All'