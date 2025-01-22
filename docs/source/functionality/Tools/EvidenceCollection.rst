Automated Evidence Collection (BETA)
=======
Automates the collection of evidence from Microsoft 365 and Azure/Entra ID environments, supporting both interactive and automated collection modes with customizable scope and filtering options.

This functionality is currently in beta. If you run into any issues, please let us know so we can try to fix them.

.. note::
    It is recommended to run the tool for specific users rather than the entire environment. While running it for the full environment is possible, it may take a considerable amount of time to collect all data, depending on the size of the organization. The Unified Audit Log, Audit Settings, and Mailbox Permissions can be particularly slow in large environments.
    
    Esure you are properly connected before running the tool. For the Microsoft 365 components, confirm that you are connected using Connect-Exchange or Connect-M365. For the Entra/Azure components, ensure you are connected using Connect-MgGraph.
  
Usage
""""""""""""""""""""""""""
Running the script in interactive mode for all platforms with a specific project name:
::
    Start-EvidenceCollection -ProjectName "Investigation2024" -Interactive

Collecting specific platform data for a particular user with standard logging:
::
    Start-EvidenceCollection -ProjectName "HR_Case" -Platform "M365" -UserIds "user@domain.com"  -LogLevel "Standard"

Collecting all Azure/Entra ID data in non-interactive mode:
::
    Start-EvidenceCollection -ProjectName "SecurityAudit" -Platform "Azure"

Parameters
""""""""""""""""""""""""""
-ProjectName (mandatory)
    - Specifies the name of the investigation/project.
    - Used to create the output directory structure.
    - Example: "Case123", "Investigation2024"

-Platform (optional)
    - Specifies which platform to collect from.
    - Valid values: "All", "Azure", "M365"
    - Default: "All"

-LogLevel (optional)
    - Controls the verbosity of logging output
    - Valid values: "None", "Minimal", "Standard"
    - Default: "Minimal"

-UserIds (optional)
    - Comma-separated list of user IDs to filter the collection scope
    - Example: "user1@domain.com" or "user1@domain.com,user2@domain.com"

-Interactive (optional)
    - Switch parameter to enable interactive collection menu
    - When enabled, displays a menu to select specific collection tasks
    - Default: False

Output
""""""""""""""""""""""""""
The output will be saved to the 'Output\ProjectName' directory with the following structure:

Azure/Entra ID Collections:

- RiskyEvents (Risky users and detections)
- MFA (MFA configuration status)
- Users (General user information)
- Admins (Administrative user details)
- Devices (Device information)
- ConditionalAccessPolicies
- Sign-In logs
- Audit logs

Microsoft 365 Collections:

- Rules (Inbox and Transport rules)
- MessageTrace
- DelegatedPermissions
- MailboxAudit
- UnifiedAuditLog

Each collection generates detailed CSV or JSON files containing relevant information based on the collection type.

.. note::

  The script performs automatic connection testing and will notify you if any required connections are missing.

    
Required connections
""""""""""""""""""""""""""
For Microsoft evidence collection, a valid session is required with: Connect-ExchangeOnline. For Azure Connect-MgGraph is required.