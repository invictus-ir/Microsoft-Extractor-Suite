Security Alerts
=======
Retrieves security alerts from Microsoft Graph Security API, providing information about security incidents and threats detected across your environment. The function automatically selects the appropriate API endpoint based on your authentication type.

Usage
""""""""""""""""""""""""""
Running the script without any parameters retrieves all security alerts from the past 90 days.
::

   Get-SecurityAlerts

Retrieves security alerts from the past 7 days.
::

   Get-SecurityAlerts -DaysBack 7

Retrieves a specific security alert by ID.
::

   Get-SecurityAlerts -AlertId "123456-abcdef-7890"

Retrieves high severity security alerts using a custom filter.
::

   Get-SecurityAlerts -Filter "severity eq 'high'"

Exports security alerts to a specified directory with UTF-8 encoding.
::

   Get-SecurityAlerts -OutputDir "C:\Reports" -Encoding UTF8

Parameters
""""""""""""""""""""""""""
-OutputDir (optional)
    - OutputDir is the parameter specifying the output directory.
    - Default: Output\SecurityAlerts

-Encoding (optional)
    - Encoding is the parameter specifying the encoding of the CSV output file.
    - Default: UTF8

-AlertId (optional)
    - AlertId is the parameter specifying a specific alert ID to retrieve.
    - Default: All alerts will be retrieved if not specified.

-DaysBack (optional)
    - Number of days to look back for alerts.
    - Default: 90

-Filter (optional)
    - Custom filter string to apply to the alert retrieval.
    - Default: None

-LogLevel (optional)
    - Specifies the level of logging. None: No logging. Minimal: Logs critical errors only. Standard: Normal operational logging.
    - Default: Standard

Output
""""""""""""""""""""""""""
The output will be saved to the 'SecurityAlerts' directory within the 'Output' directory with the file name format: [date]-SecurityAlerts.csv

The script provides A CSV file containing detailed security alert information including:

* Id
* Title 
* Category
* Severity
* Status
* CreatedDateTime
* EventDateTime
* LastModifiedDateTime
* AssignedTo
* Description
* DetectionSource
* AffectedUser
* AffectedHost
* AzureTenantId
* AzureSubscriptionId
* Confidence
* ActivityGroupName
* ClosedDateTime
* Feedback
* LastEventDateTime
* SourceURL
* CloudAppStates
* Comments
* Tags
* Vendor
* Provider
* SubProvider
* ProviderVersion
* IncidentIds

Summary statistics including:

* Total number of alerts
* Severity distribution (High, Medium, Low, Informational)
* Status distribution (New, In Progress, Resolved, Dismissed, Unknown)

Permissions
""""""""""""""""""""""""""
Before utilizing this function, it is essential to ensure that the appropriate permissions have been granted. This function relies on the Microsoft Graph API and requires an application or user to authenticate with specific scopes that grant the necessary access levels.

Make sure to connect using the following permission:

- SecurityEvents.Read.All

Your command would look like this: Connect-MgGraph -Scopes 'SecurityEvents.Read.All'

.. note::

   **API Endpoint Selection**
   
   The function automatically chooses between Get-MgSecurityAlert and Get-MgSecurityAlertV2 based on your authentication type:
   
   - **Application authentication**: Uses Get-MgSecurityAlertV2
   - **Delegated authentication**: Uses Get-MgSecurityAlert
   
   This ensures optimal compatibility and performance regardless of your authentication method.