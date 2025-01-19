Group Information
=======
This section comprises a variety of functions designed to gather information about groups. These functions include retrieving all groups, their members, and dynamic group configurations.

Retrieve all groups
^^^^^^^^^^^
Retrieves all groups in the organization, including their configuration and settings.

Usage
""""""""""""""""""""""""""
Running the script without any parameters retrieves all groups and exports the output to a CSV file.
::

    Get-Groups

Retrieves all groups and exports the output to a CSV file with UTF-32 encoding.
::

    Get-Groups -Encoding utf32

Retrieves all groups and saves the output to the C:\Windows\Temp folder.
::

    Get-Groups -OutputDir C:\Windows\Temp

Parameters
""""""""""""""""""""""""""
-OutputDir (optional)
- OutputDir is the parameter specifying the output directory.
- Default: Output\Groups

-Encoding (optional)
- Encoding is the parameter specifying the encoding of the CSV output file.
- Default: UTF8

-LogLevel (optional)
- Specifies the level of logging. None: No logging. Minimal: Logs critical errors only. Standard: Normal operational logging.
- Default: Standard

Output
""""""""""""""""""""""""""
The output will be saved to the 'Groups' directory within the 'Output' directory.

Permissions
""""""""""""""""""""""""""
Before utilizing this function, ensure appropriate permissions are granted. This function relies on the Microsoft Graph API.
Required permissions: "Group.Read.All", "AuditLog.Read.All"
Connect using: Connect-MgGraph -Scopes 'Group.Read.All','AuditLog.Read.All'

Retrieve group members
^^^^^^^^^^^
Enumerates all members of every group in the organization.

Usage
""""""""""""""""""""""""""
Running the script without any parameters retrieves all group members and their details.
::

    Get-GroupMembers

Retrieves all group members and saves details to C:\Temp with UTF-32 encoding.
::

    Get-GroupMembers -OutputDir C:\Temp -Encoding utf32

Parameters
""""""""""""""""""""""""""
-OutputDir (optional)
- OutputDir is the parameter specifying the output directory.
- Default: Output\Groups

-Encoding (optional)
- Encoding is the parameter specifying the encoding of the CSV output file.
- Default: UTF8

-LogLevel (optional)
- Specifies the level of logging. None: No logging. Minimal: Logs critical errors only. Standard: Normal operational logging.
- Default: Standard

Output
""""""""""""""""""""""""""
The output will be saved to the 'Groups' directory within the 'Output' directory.

Permissions
""""""""""""""""""""""""""
Required permissions: "Group.Read.All", "Directory.Read.All"
Connect using: Connect-MgGraph -Scopes 'Group.Read.All','Directory.Read.All'

Retrieve dynamic groups
^^^^^^^^^^^
Retrieves all dynamic groups and their membership rules, which determine automatic user inclusion.

Usage
""""""""""""""""""""""""""
Running the script without any parameters retrieves all dynamic groups and their membership rules.
::

    Get-DynamicGroups

Retrieves dynamic groups and saves details to C:\Temp with UTF-32 encoding.
::

    Get-DynamicGroups -OutputDir C:\Temp -Encoding utf32

Parameters
""""""""""""""""""""""""""
-OutputDir (optional)
- OutputDir is the parameter specifying the output directory.
- Default: Output\Groups

-Encoding (optional)
- Encoding is the parameter specifying the encoding of the CSV output file.
- Default: UTF8

-LogLevel (optional)
- Specifies the level of logging. None: No logging. Minimal: Logs critical errors only. Standard: Normal operational logging.
- Default: Standard

Output
""""""""""""""""""""""""""
The output will be saved to the 'Groups' directory within the 'Output' directory.

Permissions
""""""""""""""""""""""""""
Required permissions: "Group.Read.All", "Directory.Read.All"
Connect using: Connect-MgGraph -Scopes 'Group.Read.All','Directory.Read.All'