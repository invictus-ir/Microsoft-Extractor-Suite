Known errors
=======
1. StartDate is later than EndDate
    - Ensure that the StartDate you enter is earlier than the EndDate.

2. Audit logging is enabled in the Microsoft 365 environment but no logs are getting displayed?
    - The user must be assigned an Office 365 E5 license. Alternatively, users with an Office 365 E1 or E3 license can be assigned an Advanced eDiscovery standalone license. Administrators and compliance officers who are assigned to cases and use Advanced eDiscovery to analyze data don't need an E5 license.

3. Invalid Argument "Cannot convert value" to type "System.Int32"
    - Safe to ignore, only observed this on PowerShell on macOS, the script will work fine and continue.

4. Output directory expected
    - The Output directory, as part of the folderstructurer from GitHub, is expected to be used for all output. If you attempt to use the script from a location outside of the folder structure provided by the GitHub repository, then errors will be thrown by the script, or the output won't be written to disk.
