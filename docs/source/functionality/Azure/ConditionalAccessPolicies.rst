Conditional Access Policies
=======
Retrieves all the conditional access policies.

Usage
""""""""""""""""""""""""""
Retrieves all the conditional access policies.
::

   Get-ConditionalAccessPolicies

Parameters
""""""""""""""""""""""""""
-OutputDir (optional)
    - OutputDir is the parameter specifying the output directory.
    - Default: ConditionalAccessPolicies

-Encoding (optional)
    - Encoding is the parameter specifying the encoding of the CSV/JSON output file.
    - Default: UTF8

-LogLevel (optional)
    - Specifies the level of logging. None: No logging. Minimal: Logs critical errors only. Standard: Normal operational logging. Debug: Detailed logging for debugging.
    - Default: Standard

Output
""""""""""""""""""""""""""
The output will be saved to the 'ConditionalAccessPolicies' directory within the 'Output' directory.

Permissions
""""""""""""""""""""""""""
- Before utilizing this function, it is essential to ensure that the appropriate permissions have been granted. This function relies on the Microsoft Graph API and requires an application or user to authenticate with specific scopes that grant the necessary access levels.
- Make sure to connect using the following permission: "Policy.Read.All".
- Your command would look like this: Connect-MgGraph -Scopes 'Policy.Read.All'