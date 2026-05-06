Secure Score
============
Retrieves Microsoft Secure Score recommendations and current status using the Microsoft Graph Security API. The function collects control profiles, derives recommendation statuses, and exports actionable remediation data.

Get Secure Score
^^^^^^^^^^^^^^^^
**Get-SecureScore** retrieves Secure Score control profiles and current scores, and derives statuses for all recommendations.

Usage
""""""""""""""""""""""""""
Retrieve all Secure Score recommendations:
::

   Get-SecureScore

Retrieve only at-risk recommendations:
::

   Get-SecureScore -StatusFilter AtRisk

Retrieve recommendations for the Identity category only:
::

   Get-SecureScore -Category "Identity"

Retrieve recommendations for Exchange only:
::

   Get-SecureScore -Service "Exchange"

Save output to a custom directory:
::

   Get-SecureScore -OutputDir C:\Windows\Temp

Parameters
""""""""""""""""""""""""""
-OutputDir (optional)
    - OutputDir is the parameter specifying the output directory.
    - Default: Output\SecureScore

-Encoding (optional)
    - Encoding is the parameter specifying the encoding of the CSV output file.
    - Default: UTF8

-Category (optional)
    - Filters results to a specific control category (e.g., "Identity", "Data", "Device", "Apps", "Infrastructure").
    - Default: All categories will be included if not specified.

-Service (optional)
    - Filters results to a specific service (e.g., "Exchange", "SharePoint", "AAD").
    - Default: All services will be included if not specified.

-StatusFilter (optional)
    - Filters results to a specific status. Valid values: AtRisk, Partial, MeetsStandard, NotApplicable.
    - Default: All statuses will be included if not specified.

-LogLevel (optional)
    - Specifies the level of logging. None: No logging. Minimal: Logs critical errors only. Standard: Normal operational logging. Debug: Detailed logging for debugging.
    - Default: Standard

Output
""""""""""""""""""""""""""
The output will be saved to the 'SecureScore' directory within the 'Output' directory, with the file name format: [date]-SecureScore.csv

The CSV file contains the following fields for each recommendation:

* Category
* Title
* Service
* Status (At risk / Partial / Meets standard / Not applicable)
* CurrentScore
* MaxScore
* ScoreGap
* State
* ActionType
* ActionUrl
* ImplementationCost
* UserImpact
* Tier
* Rank
* Deprecated
* Threats
* Remediation
* RemediationImpact
* LastModifiedDateTime

Summary statistics including:

* Current Score and Maximum Score
* Percentage score
* Total number of recommendations
* Count per status (At Risk, Partial, Meets Standard, Not Applicable)

Permissions
""""""""""""""""""""""""""
Before utilizing this function, it is essential to ensure that the appropriate permissions have been granted. This function relies on the Microsoft Graph API and requires an application or user to authenticate with specific scopes that grant the necessary access levels.

Make sure to connect using the following permission:

- SecurityEvents.Read.All

Your command would look like this: Connect-MgGraph -Scopes 'SecurityEvents.Read.All'
