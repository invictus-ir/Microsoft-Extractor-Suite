Conditional Access Policies
=======
Retrieves the risky users from the Entra ID Identity Protection, which marks an account as being at risk based on the pattern of activity for the account.

Usage
""""""""""""""""""""""""""
Retrieves all the conditional access policies.
::

   Get-ConditionalAccessPolicies

Parameters
""""""""""""""""""""""""""
-OutputDir (optional)
    - OutputDir is the parameter specifying the output directory.
    - Default: UserInfo

-Encoding (optional)
    - Encoding is the parameter specifying the encoding of the CSV/JSON output file.
    - Default: UTF8

-Application (optional)
    - Application is the parameter specifying App-only access (access without a user) for authentication and authorization.
    - Default: Delegated access (access on behalf a user)

Output
""""""""""""""""""""""""""
The output will be saved to the 'UserInfo' directory within the 'Output' directory.

.. note::

  **Important note** Permission Requirement. 

- Before utilizing this function, it is essential to ensure that the appropriate permissions have been granted. This function relies on the Microsoft Graph API and requires an application or user to authenticate with specific scopes that grant the necessary access levels.
- Make sure to connect using the following permission: "Policy.Read.All".
- Your command would look like this: Connect-MgGraph -Scopes 'Policy.Read.All'