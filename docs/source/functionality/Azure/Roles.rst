## Role Management
=======
This section contains functions for managing and auditing role assignments in Microsoft Entra ID. These functions help identify who has access to administrative roles, both through direct assignments and through Privileged Identity Management (PIM).

Retrieve Role Activity Information
^^^^^^^^^^^
Retrieves all directory role memberships with last login information for users.

Usage
""""""""""""""""""""""""""
Running the function without any parameters exports all directory role memberships with last login information to the default output directory.
::

   Get-AllRoleActivity

Exports directory role memberships with UTF-32 encoding.
::

   Get-AllRoleActivity -Encoding utf32

Exports directory role memberships to a specified directory.
::

   Get-AllRoleActivity -OutputDir C:\Reports

Exports directory role memberships and includes empty roles in the summary.
::

   Get-AllRoleActivity -IncludeEmptyRoles

Parameters
""""""""""""""""""""""""""
-OutputDir (optional)
    - OutputDir is the parameter specifying the output directory.
    - Default: Output\Roles

-Encoding (optional)
    - Encoding is the parameter specifying the encoding of the CSV output file.
    - Default: UTF8

-IncludeEmptyRoles (optional)
    - When specified, includes roles with no members in the summary output.
    - Default: False

-LogLevel (optional)
    - Specifies the level of logging. None: No logging. Minimal: Logs critical errors only. Standard: Normal operational logging.
    - Default: Standard

Output
""""""""""""""""""""""""""
The output will be saved to the 'Roles' directory within the 'Output' directory with the file name format: [date]-All-Roles.csv

Permissions
""""""""""""""""""""""""""
- Before utilizing this function, it is essential to ensure that the appropriate permissions have been granted. This function relies on the Microsoft Graph API and requires an application or user to authenticate with specific scopes that grant the necessary access levels.
- Make sure to connect using the following permissions: "User.Read.All", "Directory.Read.All", "AuditLog.Read.All".
- Your command would look like this: Connect-MgGraph -Scopes 'User.Read.All','Directory.Read.All','AuditLog.Read.All'

Retrieve PIM Role Assignments
^^^^^^^^^^^
Generates a report of all Privileged Identity Management (PIM) role assignments in Entra ID.

Usage
""""""""""""""""""""""""""
Running the function without any parameters exports all PIM role assignments to the default output directory.
::

   Get-PIMAssignments

Exports PIM role assignments with UTF-32 encoding.
::

   Get-PIMAssignments -Encoding utf32

Exports PIM role assignments to a specified directory.
::

   Get-PIMAssignments -OutputDir C:\Reports

Exports PIM role assignments with minimal logging.
::

   Get-PIMAssignments -LogLevel Minimal

Parameters
""""""""""""""""""""""""""
-OutputDir (optional)
    - OutputDir is the parameter specifying the output directory.
    - Default: Output\Roles

-Encoding (optional)
    - Encoding is the parameter specifying the encoding of the CSV output file.
    - Default: UTF8

-LogLevel (optional)
    - Specifies the level of logging. None: No logging. Minimal: Logs critical errors only. Standard: Normal operational logging.
    - Default: Standard

Output
""""""""""""""""""""""""""
The output will be saved to the 'Roles' directory within the 'Output' directory with the file name format: [date]-PIM-Assignments.csv

Permissions
""""""""""""""""""""""""""
- Before utilizing this function, it is essential to ensure that the appropriate permissions have been granted. This function relies on the Microsoft Graph API and requires an application or user to authenticate with specific scopes that grant the necessary access levels.
- Make sure to connect using the following permissions: "RoleAssignmentSchedule.Read.Directory", "RoleEligibilitySchedule.Read.Directory", "User.Read.All", "Group.Read.All".
- Your command would look like this: Connect-MgGraph -Scopes 'RoleAssignmentSchedule.Read.Directory','RoleEligibilitySchedule.Read.Directory','User.Read.All','Group.Read.All'