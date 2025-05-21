License Information
=======
This section includes functions designed to gather information about licenses in the Microsoft tenant. These functions include retrieving all tenant licenses, product licenses, license assignments per user, and license compatibility checks.

Retrieve all tenant licenses
^^^^^^^^^^^
Retrieves all licenses in the tenant with retention times and premium license indicators.

Usage
""""""""""""""""""""""""""
Running the script without any parameters retrieves all licenses in the tenant.
::
    Get-Licenses

Parameters
""""""""""""""""""""""""""
-OutputDir (optional)
- OutputDir is the parameter specifying the output directory.
- Default: Output\Licenses

-LogLevel (optional)
- Specifies the level of logging. None: No logging. Minimal: Logs critical errors only. Standard: Normal operational logging. Debug: Detailed logging for debugging.
- Default: Standard

Output
""""""""""""""""""""""""""
The output will be saved to the 'Licenses' directory within the 'Output' directory. The following information is collected:
- License SKUs and their status
- Number of units consumed
- Retention periods
- Premium features (E3, E5, P1, P2)
- Defender capabilities

Permissions
""""""""""""""""""""""""""
- Before utilizing this function, it is essential to ensure that the appropriate permissions have been granted. This function relies on the Microsoft Graph API and requires an application or user to authenticate with specific scopes that grant the necessary access levels.
- Make sure to connect using at least one of the following permissions: "Directory.Read.All", "Organization.Read.All".

Check license compatibility
^^^^^^^^^^^
Checks the presence of E5, P2, P1, and E3 licenses and informs about functionality limitations.

Usage
""""""""""""""""""""""""""
Running the script without any parameters checks license compatibility.
::
Get-LicenseCompatibility

Parameters
""""""""""""""""""""""""""
-LogLevel (optional)
- Specifies the level of logging. None: No logging. Minimal: Logs critical errors only. Standard: Normal operational logging. Debug: Detailed logging for debugging.
- Default: Standard

Output
""""""""""""""""""""""""""
The function provides:
- Current license status (E5, E3, P1, P2)
- Feature compatibility information
- Recommendations based on current licensing

Permissions
""""""""""""""""""""""""""
- Before utilizing this function, it is essential to ensure that the appropriate permissions have been granted. This function relies on the Microsoft Graph API and requires an application or user to authenticate with specific scopes that grant the necessary access levels.
- Make sure to connect using the following permission: "Directory.Read.All".

Check Entra ID security defaults
^^^^^^^^^^^
Checks the status of Entra ID security defaults.

Usage
""""""""""""""""""""""""""
Running the script without any parameters checks security defaults status.
::
Get-EntraSecurityDefaults

Parameters
""""""""""""""""""""""""""
-OutputDir (optional)
- OutputDir is the parameter specifying the output directory.
- Default: Output\Licenses

-LogLevel (optional)
- Specifies the level of logging. None: No logging. Minimal: Logs critical errors only. Standard: Normal operational logging. Debug: Detailed logging for debugging.
- Default: Standard

Output
""""""""""""""""""""""""""
The output will be saved to the 'Licenses' directory within the 'Output' directory. The function provides:
- Security defaults status
- License context
- Recommendations based on current configuration

Permissions
""""""""""""""""""""""""""
- Before utilizing this function, it is essential to ensure that the appropriate permissions have been granted. This function relies on the Microsoft Graph API and requires an application or user to authenticate with specific scopes that grant the necessary access levels.
- Make sure to connect using the following permissions: "Policy.Read.All".

Retrieve licenses by user
^^^^^^^^^^^
Retrieves license assignments for all users in the tenant.

Usage
""""""""""""""""""""""""""
Running the script without any parameters retrieves all user license assignments.
::
Get-LicensesByUser

Running the script with a custom output directory.
::
Get-LicensesByUser -OutputDir "C:\CustomPath"

Parameters
""""""""""""""""""""""""""
-OutputDir (optional)
- OutputDir is the parameter specifying the output directory.
- Default: Output\Licenses

-LogLevel (optional)
- Specifies the level of logging. None: No logging. Minimal: Logs critical errors only. Standard: Normal operational logging. Debug: Detailed logging for debugging.
- Default: Standard

Output
""""""""""""""""""""""""""
The output will be saved to the 'Licenses' directory within the 'Output' directory. The function provides:
- Complete list of users and their assigned licenses
- Summary of licensed vs unlicensed users
- License distribution across the tenant
- Total license assignments

Permissions
""""""""""""""""""""""""""
- Before utilizing this function, it is essential to ensure that the appropriate permissions have been granted. This function relies on the Microsoft Graph API and requires an application or user to authenticate with specific scopes that grant the necessary access levels.
- Make sure to connect using the following permissions: "User.Read.All", "Directory.Read.All".

Retrieve product license information
^^^^^^^^^^^
Retrieves detailed product license information from Microsoft Graph including Defender, Exchange Online, and SharePoint Online products.

Usage
""""""""""""""""""""""""""
Running the script without any parameters retrieves all product license information.
::
Get-ProductLicenses

Retrieves all product license information and exports the output to a CSV file with UTF-32 encoding.
::
Get-ProductLicenses -Encoding utf32

Retrieves all product license information and saves the output to the C:\Windows\Temp folder.
::
Get-ProductLicenses -OutputDir C:\Windows\Temp

Parameters
""""""""""""""""""""""""""
-OutputDir (optional)
- OutputDir is the parameter specifying the output directory.
- Default: Output\Licenses
-Encoding (optional)

- Encoding is the parameter specifying the encoding of the CSV output file.
- Default: UTF8

-LogLevel (optional)
- Specifies the level of logging. None: No logging. Minimal: Logs critical errors only. Standard: Normal operational logging. Debug: Detailed logging for debugging.
- Default: Standard

Output
""""""""""""""""""""""""""
The output will be saved to the 'Licenses' directory within the 'Output' directory.

Permissions
""""""""""""""""""""""""""
- Before utilizing this function, it is essential to ensure that the appropriate permissions have been granted. This function relies on the Microsoft Graph API and requires an application or user to authenticate with specific scopes that grant the necessary access levels.
- Make sure to connect using at least one of the following permissions: "Directory.Read.All", "Organization.Read.All".
