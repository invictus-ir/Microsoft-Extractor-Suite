OAuth Permissions
=======
OAuth is a way of authorizing third-party applications to login into user accounts such as social media and webmail. The advantage of OAuth is that users don’t have to reveal their password; instead, the third-party applications use a token for authentication. In an OAuth abuse attack, a victim authorizes a third-party application to access their account. Once authorized, the application accesses the user’s data without the need for credentials. The user receives a message to accept the application with its requested API permissions. After the user selects accept, the threat actor has control of the user’s account.

.. note::

   Script made by psignoret: https://gist.github.com/psignoret/41793f8c6211d2df5051d77ca3728c09

Parameters
""""""""""""""""""""""""""
-OutputDir (optional)
    - OutputDir is the parameter specifying the output directory.
    - Default: Output\OAuthPermissions

-Encoding (optional)
    - Encoding is the parameter specifying the encoding of the CSV output file.
    - Default: UTF8

-LogLevel (optional)
    - Specifies the level of logging. None: No logging. Minimal: Logs critical errors only. Standard: Normal operational logging.
    - Default: Standard

Usage
""""""""""""""""""""""""""
List delegated permissions (OAuth2PermissionGrants) and application permissions (AppRoleAssignments):
::

   Get-OAuthPermissions

Output
""""""""""""""""""""""""""
The output will be saved to the 'OAuthPermissions' directory within the 'Output' directory, with the file name 'OAuthPermissions.csv'.

Graph API Variant
^^^^^^^^^^^

Parameters
^^^^^^^^^^^^^^^^^^^^^^^^^^
-OutputDir (optional)
    - OutputDir is the parameter specifying the output directory.
    - Default: Output\OAuthPermissions

-Encoding (optional)
    - Encoding is the parameter specifying the encoding of the CSV output file.
    - Default: UTF8

-LogLevel (optional)
    - Specifies the level of logging. None: No logging. Minimal: Logs critical errors only. Standard: Normal operational logging.
    - Default: Standard

Usage
^^^^^^^^^^^^^^^^^^^^^^^^^^
List delegated permissions (OAuth2PermissionGrants) and application permissions (AppRoleAssignments) using Microsoft Graph API:
::

   Get-OAuthPermissionsGraph

Prerequisites
^^^^^^^^^^^^^^^^^^^^^^^^^^
Ensure you have the Microsoft.Graph.Applications module installed and are connected to Microsoft Graph with appropriate permissions:
::

   Connect-MgGraph -Scopes "Directory.Read.All", "Application.Read.All"

Output
""""""""""""""""""""""""""
Both variants will save their output to the 'OAuthPermissions' directory within the 'Output' directory, with the file name 'OAuthPermissions.csv'.