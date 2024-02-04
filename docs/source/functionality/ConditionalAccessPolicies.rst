Conditional Access Policies
=======
Retrieves the risky users from the Entra ID Identity Protection, which marks an account as being at risk based on the pattern of activity for the account.

Usage
""""""""""""""""""""""""""
Retrieves all the conditional access policies.
::

   Get-ConditionalAccess

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