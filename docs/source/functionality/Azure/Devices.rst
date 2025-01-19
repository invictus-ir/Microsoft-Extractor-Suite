Retrieve Device Information
=======
Retrieves information about all devices registered in Azure AD/Entra ID, including detailed information about device status, operating system details, trust type, and management information.

Usage
""""""""""""""""""""""""""
Running the script without any parameters retrieves information about all devices and exports to a CSV file in the default directory.
::

Get-Devices

Retrieves information about all devices and exports to a JSON file.
::
    
Get-Devices -Output JSON

Retrieves device information and saves the output to the C:\Windows\Temp folder with UTF-32 encoding.
::

Get-Devices -OutputDir C:\Windows\Temp -Encoding UTF32

Retrieves device information and saves as a JSON file in the Reports folder with UTF-8 encoding.
::

Get-Devices -OutputDir "Reports" -Output JSON -Encoding UTF8

Parameters
""""""""""""""""""""""""""
-OutputDir (optional)
    - OutputDir is the parameter specifying the output directory.
    - Default: Output\Device Information
    
-Encoding (optional)
    - Encoding is the parameter specifying the encoding of the output file.
    - Default: UTF8

-Output (optional)
    - Output is the parameter specifying the type of output file (CSV or JSON).
    - Default: CSV

-LogLevel (optional)
    - Specifies the level of logging. None: No logging. Minimal: Logs critical errors only. Standard: Normal operational logging.
    - Default: Standard

-UserIds (optional)
    - UserIds is the UserIds parameter filtering the log entries by the account of the user who performed the actions.

Output
""""""""""""""""""""""""""
The output will be saved to the 'Device Information' directory within the 'Output' directory. The script provides:
A CSV/JSON file containing detailed device information including:

* CreatedDateTime
* DeviceId
* ObjectId
* AccountEnabled
* DeviceOwnership
* DisplayName
* EnrollmentType
* IsCompliant
* IsManaged
* IsRooted
* ManagementType
* DeviceCategory
* OperatingSystem
* OperatingSystemVersion
* Manufacturer
* Model
* LastSignInDateTime
* TrustType
* RegisteredOwners
* RegisteredUsers
* MDMAppId
* OnPremisesSyncEnabled
* ProfileType
* SecurityIdentifier

Permissions
""""""""""""""""""""""""""
Before utilizing this function, it is essential to ensure that the appropriate permissions have been granted. This function relies on the Microsoft Graph API and requires an application or user to authenticate with specific scopes that grant the necessary access levels.
Make sure to connect using both of the following permissions:

- Device.Read.All
- Directory.Read.All

Your command would look like this: Connect-MgGraph -Scopes 'Device.Read.All','Directory.Read.All'