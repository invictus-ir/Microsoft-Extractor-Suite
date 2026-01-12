# Collection configuration hashtable
$Global:CollectionTasks = @{
    Azure = @{
        "RiskyUsers" = @{
            Name = "Risky Users"
            Description = "Collects information about users marked as risky"
            Function = { param($OutputDir, $LogLevel, $UserIds, $Output)
                if ($UserIds) {
                    if ($OutputDir) {
                        Get-RiskyUsers -OutputDir $OutputDir -LogLevel $LogLevel -UserIds $UserIds
                    } else {
                        Get-RiskyUsers -LogLevel $LogLevel -UserIds $UserIds
                    }
                    
                } else {
                    if ($OutputDir) {
                        Get-RiskyUsers -OutputDir $OutputDir -LogLevel $LogLevel
                    } else {
                        Get-RiskyUsers -LogLevel $LogLevel
                    }
                }
                return $true
            }
            Enabled = $true
        }
        "RiskyDetections" = @{
            Name = "Risky Detections"
            Description = "Collects risk detection events"
            Function = { param($OutputDir, $LogLevel, $UserIds, $Output)
                if ($UserIds) {
                    if ($OutputDir) {
                        Get-RiskyDetections -OutputDir $OutputDir -LogLevel $LogLevel -UserIds $UserIds
                    } else {
                        Get-RiskyDetections -LogLevel $LogLevel -UserIds $UserIds
                    }
                } else {
                    if ($OutputDir) {
                        Get-RiskyDetections -OutputDir $OutputDir -LogLevel $LogLevel
                    } else {
                        Get-RiskyDetections -LogLevel $LogLevel
                    }
                }
                return $true
            }
            Enabled = $true
        }
        "MFAStatus" = @{
            Name = "MFA Status"
            Description = "Collects MFA configuration and status"
            Function = { param($OutputDir, $LogLevel, $UserIds, $Output)
                if ($UserIds) {
                    if ($OutputDir) {
                        Get-MFA -OutputDir $OutputDir -LogLevel $LogLevel -UserIds $UserIds
                    } else {
                        Get-MFA -LogLevel $LogLevel -UserIds $UserIds
                    } 
                } else {
                    if ($OutputDir) {
                        Get-MFA -OutputDir $OutputDir -LogLevel $LogLevel
                    } else {
                        Get-MFA -LogLevel $LogLevel
                    }
                }
                return $true
            }
            Enabled = $true
        }
        "Users" = @{
            Name = "Users"
            Description = "Collects general user information"
            Function = { param($OutputDir, $LogLevel, $UserIds, $Output)
                if (-not $UserIds) {
                    if ($OutputDir) {
                        Get-Users -LogLevel $LogLevel -OutputDir $OutputDir
                    } else {
                        Get-Users -LogLevel $LogLevel
                    }
                    return $true
                }
                return $false
            }
            Enabled = $true
        }
        "AdminUsers" = @{
            Name = "Admin Users"
            Description = "Collects administrative user information"
            Function = { param($OutputDir, $LogLevel, $UserIds, $Output)
                if (-not $UserIds) {
                    if ($OutputDir) {
                        Get-AdminUsers -OutputDir $OutputDir -LogLevel $LogLevel
                    } else {
                        Get-AdminUsers -LogLevel $LogLevel
                    }
                    return $true
                }
                return $false
            }
            Enabled = $true
        }
        "Devices" = @{
            Name = "Devices"
            Description = "Collects device information"
            Function = { param($OutputDir, $LogLevel, $UserIds, $Output)
                if ($UserIds) {
                    if ($OutputDir) {
                        Get-Devices -OutputDir $OutputDir -LogLevel $LogLevel -UserIds $UserIds
                    } else {
                        Get-Devices -LogLevel $LogLevel -UserIds $UserIds
                    }                    
                } else {
                    if ($OutputDir) {
                        Get-Devices -OutputDir $OutputDir -LogLevel $LogLevel
                    } else {
                        Get-Devices -LogLevel $LogLevel
                    }
                }
                return $true
            }
            Enabled = $true
        }
        "ConditionalAccess" = @{
            Name = "Conditional Access"
            Description = "Collects Conditional Access Policies"
            Function = { param($OutputDir, $LogLevel, $UserIds, $Output)
                if (-not $UserIds) {
                    if ($OutputDir) {
                        Get-ConditionalAccessPolicies -OutputDir $OutputDir -LogLevel $LogLevel
                    } else {
                        Get-ConditionalAccessPolicies -LogLevel $LogLevel
                    }
                    return $true
                }
                return $false
            }
            Enabled = $true
        }
        "SignInLogs" = @{
            Name = "Sign-In Logs"
            Description = "Collects Azure Entra sign-in logs"
            Function = { param($OutputDir, $LogLevel, $UserIds, $Output = 'JSON')
                $OutputDirAudit = "$OutputDir\Sign-In logs"
                New-Item -ItemType Directory -Force -Path $OutputDirAudit > $null

                if ($Output -eq 'CSV') {
                    Write-LogFile -Message "[WARNING] CSV output not supported for Sign-In Logs. Using JSON format." -Color "Yellow" -Level Minimal
                    $Output = 'JSON'
                }

                if ($UserIds) {
                    Get-GraphEntraSignInLogs -OutputDir $OutputDirAudit -LogLevel $LogLevel -UserIds $UserIds -Output $Output -MergeOutput -EventTypes interactiveUser,nonInteractiveUser
                    
                } else {
                    Get-GraphEntraSignInLogs -OutputDir $OutputDirAudit -LogLevel $LogLevel -Output $Output -MergeOutput
                }
                return $true
            }
            Enabled = $true
        }
        "AuditLogs" = @{
            Name = "Audit Logs"
            Description = "Collects Azure Entra audit logs"
            Function = { param($OutputDir, $LogLevel, $UserIds, $Output = 'JSON')
                $OutputDirAudit = "$OutputDir\Audit logs"
                New-Item -ItemType Directory -Force -Path $OutputDirAudit > $null

                if ($Output -eq 'CSV') {
                    Write-LogFile -Message "[WARNING] CSV output not supported for Audit Logs. Using JSON format." -Color "Yellow" -Level Minimal
                    $Output = 'JSON'
                }

                if ($UserIds) {
                    Get-GraphEntraAuditLogs -OutputDir $OutputDirAudit -LogLevel $LogLevel -UserIds $UserIds -Output $Output -MergeOutput
                } else {
                    Get-GraphEntraAuditLogs -OutputDir $OutputDirAudit -LogLevel $LogLevel -Output $Output -MergeOutput
                }
                return $true
            }
            Enabled = $true
        }
        "OAuthPermissions" = @{
            Name = "OAuth Permissions"
            Description = "Collects delegated and application permissions using Microsoft Graph API"
            Function = { param($OutputDir, $LogLevel, $UserIds, $Output)
                if (-not $UserIds) {
                    if ($OutputDir) {
                        Get-OAuthPermissionsGraph -OutputDir $OutputDir -LogLevel $LogLevel
                    } else {
                        Get-OAuthPermissionsGraph -LogLevel $LogLevel
                    }
                    return $true
                }
                return $false
            }
            Enabled = $true
        }
        "AllRoleActivity" = @{
            Name = "Directory Role Activity"
            Description = "Exports all directory role memberships with last login information"
            Function = { param($OutputDir, $LogLevel, $UserIds, $Output)
            if (-not $UserIds) {
                if ($OutputDir) {
                    Get-AllRoleActivity -OutputDir $OutputDir -LogLevel $LogLevel
                } else {
                    Get-AllRoleActivity -LogLevel $LogLevel
                }
                return $true
            }
            return $false
        }
            Enabled = $true
        }
        "PIMAssignments" = @{
            Name = "PIM Assignments"
            Description = "Generates a report of all Entra ID PIM role assignments (active and eligible)"
            Function = { param($OutputDir, $LogLevel, $UserIds, $Output)
                if (-not $UserIds) {
                    if ($OutputDir) {
                        Get-PIMAssignments -OutputDir $OutputDir -LogLevel $LogLevel
                    } else {
                        Get-PIMAssignments -LogLevel $LogLevel
                    }
                    return $true
                }
                return $false
            }
            Enabled = $true
        }
        "SecurityAlerts" = @{
            Name = "Security Alerts"
            Description = "Retrieves security alerts from Microsoft Graph Security API"
            Function = { param($OutputDir, $LogLevel, $UserIds, $Output)
            if (-not $UserIds) {
                if ($OutputDir) {
                    Get-SecurityAlerts -OutputDir $OutputDir -LogLevel $LogLevel
                } else {
                    Get-SecurityAlerts -LogLevel $LogLevel
                }
                return $true
            }
            return $false
        }
            Enabled = $true
        }
    }
    M365 = @{
        "InboxRules" = @{
            Name = "Inbox Rules"
            Description = "Collects Exchange inbox rules"
            Function = { param($OutputDir, $LogLevel, $UserIds, $Output)
            if ($UserIds) {
                if ($OutputDir) {
                    Get-MailboxRules -OutputDir $OutputDir -LogLevel $LogLevel -UserIds $UserIds
                } else {
                    Get-MailboxRules -LogLevel $LogLevel -UserIds $UserIds
                }
            } else {
                if ($OutputDir) {
                    Get-MailboxRules -OutputDir $OutputDir -LogLevel $LogLevel
                } else {
                    Get-MailboxRules -LogLevel $LogLevel
                }
            }
            return $true
        }
            Enabled = $true
        }
        "MessageTrace" = @{
            Name = "Message Trace"
            Description = "Collects Exchange message tracking logs"
            Function = { param($OutputDir, $LogLevel, $UserIds, $Output)
            if ($UserIds) {
                if ($OutputDir) {
                    Get-MessageTraceLog -OutputDir $OutputDir -LogLevel $LogLevel -UserIds $UserIds
                } else {
                    Get-MessageTraceLog -LogLevel $LogLevel -UserIds $UserIds
                }
            } else {
                if ($OutputDir) {
                    Get-MessageTraceLog -OutputDir $OutputDir -LogLevel $LogLevel
                } else {
                    Get-MessageTraceLog -LogLevel $LogLevel
                }
            }
            return $true
        }
            Enabled = $true
        }
        "TransportRules" = @{
            Name = "Transport Rules"
            Description = "Collects Exchange transport rules"
            Function = { param($OutputDir, $LogLevel, $UserIds, $Output)
            if (-not $UserIds) {
                if ($OutputDir) {
                    Get-TransportRules -OutputDir $OutputDir -LogLevel $LogLevel
                } else {
                    Get-TransportRules -LogLevel $LogLevel
                }
                return $true
            }
            return $false
        }
            Enabled = $true
        }
        "MailboxPermissions" = @{
            Name = "Delegated Mailbox Permissions"
            Description = "Collects mailbox delegated permissions"
            Function = { param($OutputDir, $LogLevel, $UserIds, $Output)
                if ($UserIds) {
                    if ($OutputDir) {
                        Get-MailboxPermissions -OutputDir $OutputDir -LogLevel $LogLevel -UserIds $UserIds
                    } else {
                        Get-MailboxPermissions -LogLevel $LogLevel -UserIds $UserIds
                    }
                } else {
                    if ($OutputDir) {
                        Get-MailboxPermissions -OutputDir $OutputDir -LogLevel $LogLevel
                    } else {
                        Get-MailboxPermissions -LogLevel $LogLevel
                    }
                }
                return $true
            }
            Enabled = $true
        }
        "MailboxAudit" = @{
            Name = "Mailbox Audit"
            Description = "Collects mailbox audit configuration"
            Function = { param($OutputDir, $LogLevel, $UserIds, $Output)
                if ($UserIds) {
                    if ($OutputDir) {
                        Get-MailboxAuditStatus -OutputDir $OutputDir -LogLevel $LogLevel -UserIds $UserIds
                    } else {
                        Get-MailboxAuditStatus -LogLevel $LogLevel -UserIds $UserIds
                    }
                } else {
                    if ($OutputDir) {
                        Get-MailboxAuditStatus -OutputDir $OutputDir -LogLevel $LogLevel
                    } else {
                        Get-MailboxAuditStatus -LogLevel $LogLevel
                    }
                }
                return $true
            }
            Enabled = $true
        }
        "UnifiedAuditLog" = @{
            Name = "Unified Audit Log"
            Description = "Collects Office 365 Unified Audit Logs"
            Function = { param($OutputDir, $LogLevel, $UserIds, $Output = 'CSV')
                Write-LogFile -Message "Starting Unified Audit Log collection (this may take a while)..." -Color "Yellow" -Level Minimal
                if ($UserIds) {
                    if ($OutputDir) {
                        Get-UAL -LogLevel $LogLevel -UserIds $UserIds -MergeOutput -Output $Output -OutputDir $OutputDir
                    } else {
                        Get-UAL -LogLevel $LogLevel -UserIds $UserIds -MergeOutput -Output $Output
                    }
                } else {
                    if ($OutputDir) {
                        Get-UAL -LogLevel $LogLevel -MergeOutput -Output $Output -OutputDir $OutputDir
                    } else {
                        Get-UAL -LogLevel $LogLevel -MergeOutput -Output $Output
                    }
                }
                return $true
            }
            Enabled = $true
        }
    }
}

function Write-TaskProgress {
<#
    .SYNOPSIS
    Writes task progress information with visual status indicators.

    .DESCRIPTION
    Displays task progress information with color-coded status indicators and formatted messages.
    The output includes status symbols ([DONE], [FAILED], [INPROGRESS]) and supports error message display.

    .PARAMETER TaskName
    The name of the task being executed.

    .PARAMETER Status
    The status of the task. Valid values are:
    - Complete
    - Failed
    - InProgress

    .PARAMETER ErrorMessage
    Optional error message to display when task status is Failed.

    .EXAMPLE
    Write-TaskProgress -TaskName "User Collection" -Status "Complete"
    Displays a completion message for the User Collection task.

    .EXAMPLE
    Write-TaskProgress -TaskName "Audit Logs" -Status "Failed" -ErrorMessage "Access Denied"
    Displays a failure message for the Audit Logs task with the error message.
#>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$TaskName,
        [Parameter(Mandatory=$true)]
        [ValidateSet('Complete', 'Failed', 'InProgress')]
        [string]$Status,
        [Parameter(Mandatory=$false)]
        [string]$ErrorMessage
    )

    $symbol = switch ($Status) {
        'Complete'    { '[DONE] ' }
        'Failed'      { '[FAILED] ' }
        'InProgress'  { '[INPROGRESS] ' }
    }

    $color = switch ($Status) {
        'Complete'    { 'Green' }
        'Failed'      { 'Red' }
        'InProgress'  { 'Yellow' }
    }

    $message = "{0}{1}" -f $symbol, $TaskName
    if ($Status -eq 'Failed' -and $ErrorMessage) {
        $message += " - $ErrorMessage"
    }

    Write-LogFile -Message $message -Level Minimal -Color $color
}

function Test-RequiredConnections {
<#
    .SYNOPSIS
    Tests the required service connections based on the selected platform.

    .DESCRIPTION
    Verifies the necessary service connections for Microsoft 365 and/or Azure/Entra ID depending on the platform selection.
    For M365, checks Exchange Online and Unified Audit Log access.
    For Azure, checks Microsoft Graph and Azure PowerShell connections.

    .PARAMETER Platform
    Specifies which platform connections to test. Valid values are:
    - All: Tests both M365 and Azure connections
    - Azure: Tests only Azure/Entra ID connections
    - M365: Tests only Microsoft 365 connections
    Default: All

    .EXAMPLE
    Test-RequiredConnections -Platform "All"
    Tests all required connections for both M365 and Azure platforms.

    .EXAMPLE
    Test-RequiredConnections -Platform "Azure"
    Tests only Azure-related connections (Graph API and Az PowerShell).
#>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet('All', 'Azure', 'M365')]
        [string]$Platform = 'All'
    )
    
    $allConnected = $true
    $errorMessage = "[ERROR] Missing connections detected:`n"

    # M365 Connection Tests
    if ($Platform -eq 'All' -or $Platform -eq 'M365') {
        # Check Exchange Online connection
        try {
            $null = Get-OrganizationConfig -ErrorAction Stop
        }
        catch {
            $allConnected = $false
            $errorMessage += "- Exchange Online not connected. Run 'Connect-ExchangeOnline'.`n"
        }

        # Check Unified Audit Log access
        try {
            $null = Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-1) -EndDate (Get-Date) -ResultSize 1 -ErrorAction Stop
        }
        catch {
            $allConnected = $false
            $errorMessage += "- Unified Audit Log access not available. Ensure you have appropriate permissions and Exchange Online is connected.`n"
        }
    }

    # Azure Connection Tests
    if ($Platform -eq 'All' -or $Platform -eq 'Azure') {
        # Check Microsoft Graph connection
        try {
            $graphContext = Get-MgContext
            if ($null -eq $graphContext) {
                $allConnected = $false
                $errorMessage += "- Microsoft Graph not connected. Run 'Connect-MgGraph' with the appropriate Scopes.`n"
            }
        }
        catch {
            $allConnected = $false
            $errorMessage += "- Microsoft Graph not connected. Run 'Connect-MgGraph' with the appropriate Scopes.`n"
        }
    }

    if (-not $allConnected) {
        Write-LogFile -Message $errorMessage -Color "Red"
        return $false
    }

    Write-LogFile -Message "[INFO] All required connections verified for $Platform platform." -Color "Green"
    return $true
}


function Show-CollectionMenu {
<#
    .SYNOPSIS
    Displays an interactive menu for selecting evidence collection tasks.

    .DESCRIPTION
    Presents a user interface for enabling or disabling specific collection tasks for Microsoft 365 and Azure/Entra ID.
    Supports filtering by platform and provides options to select all, deselect all, or toggle individual tasks.

    .PARAMETER Platform
    Specifies which platform's tasks to display. Valid values are:
    - All: Shows both M365 and Azure tasks
    - Azure: Shows only Azure/Entra ID tasks
    - M365: Shows only Microsoft 365 tasks
    Default: All
#>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Platform = "All",
        [Parameter(Mandatory=$false)]
        [bool]$Refresh = $false 
    )

    if (-not $Refresh) {
        $options = @{}
        $counter = 1

        Write-LogFile -Message "`nEvidence Collection Configuration Menu" -Color "Cyan" -Level Minimal
        Write-LogFile -Message "=================================" -Color "Cyan" -Level Minimal

        if ($Platform -eq "All" -or $Platform -eq "Azure") {
            Write-LogFile -Message "`nAzure/Entra ID Collections:" -Color "Yellow" -Level Minimal
            foreach ($task in $Global:CollectionTasks.Azure.GetEnumerator()) {
                $options[$counter] = @{
                    Platform = "Azure"
                    Key = $task.Key
                }
                $checkmark = if ($task.Value.Enabled) { "X" } else { " " }
                Write-LogFile -Message ("[{0}] [{1}] {2}" -f $counter, $checkmark, $task.Value.Name) -Level Minimal
                Write-LogFile -Message ("    {0}" -f $task.Value.Description) -Color "Gray" -Level Minimal
                $counter++
            }
        }

        if ($Platform -eq "All" -or $Platform -eq "M365") {
            Write-LogFile -Message "`nMicrosoft 365 Collections:" -Color "Yellow" -Level Minimal
            foreach ($task in $Global:CollectionTasks.M365.GetEnumerator()) {
                $options[$counter] = @{
                    Platform = "M365"
                    Key = $task.Key
                }
                $checkmark = if ($task.Value.Enabled) { "X" } else { " " }
                Write-LogFile -Message ("[{0}] [{1}] {2}" -f $counter, $checkmark, $task.Value.Name) -Level Minimal
                Write-LogFile -Message ("    {0}" -f $task.Value.Description) -Color "Gray" -Level Minimal
                $counter++
            }
        }

        Write-LogFile -Message "`nOptions:" -Color "Yellow" -Level Minimal
        Write-LogFile -Message "Enter number to toggle collection on/off" -Level Minimal
        Write-LogFile -Message "Enter 'A' to select all" -Level Minimal
        Write-LogFile -Message "Enter 'N' to deselect all" -Level Minimal
        Write-LogFile -Message "Enter 'S' to start collection" -Level Minimal
        Write-LogFile -Message "Enter 'Q' to quit" -Level Minimal
    }

    $choice = Read-Host "`nEnter choice"
    
    switch ($choice) {
        { $_ -match '^\d+$' -and $options.ContainsKey([int]$_) } {
            $opt = $options[[int]$_]
            $Global:CollectionTasks[$opt.Platform][$opt.Key].Enabled = !$Global:CollectionTasks[$opt.Platform][$opt.Key].Enabled
            Show-CollectionMenu -Platform $Platform -Refresh $false
        }
        'A' {
            if ($Platform -eq "All" -or $Platform -eq "Azure") {
                $Global:CollectionTasks.Azure.GetEnumerator() | ForEach-Object { $_.Value.Enabled = $true }
            }
            if ($Platform -eq "All" -or $Platform -eq "M365") {
                $Global:CollectionTasks.M365.GetEnumerator() | ForEach-Object { $_.Value.Enabled = $true }
            }
            Show-CollectionMenu -Platform $Platform -Refresh $false
        }
        'N' {
            if ($Platform -eq "All" -or $Platform -eq "Azure") {
                $Global:CollectionTasks.Azure.GetEnumerator() | ForEach-Object { $_.Value.Enabled = $false }
            }
            if ($Platform -eq "All" -or $Platform -eq "M365") {
                $Global:CollectionTasks.M365.GetEnumerator() | ForEach-Object { $_.Value.Enabled = $false }
            }
            Show-CollectionMenu -Platform $Platform -Refresh $false
        }
        'S' { return $true }
        'Q' { return $false }
        default { 
            Write-LogFile -Message "Invalid choice" -Color "Red" -Level Minimal
            Show-CollectionMenu -Platform $Platform -Refresh $true
        }
    }
}

function Start-EvidenceCollection {
    <#
    .SYNOPSIS
    Initiates the collection of evidence from Microsoft 365 and/or Azure/Entra ID environments.

    .DESCRIPTION
    Orchestrates the collection of various types of evidence from Microsoft 365 and Azure/Entra ID environments.
    Supports both interactive and automated collection modes, with options to filter by platform and specific users.
    Creates a structured output directory and provides detailed collection progress and summary information.

    .PARAMETER ProjectName
    The name of the project/case. Used to create the output directory structure.

    .PARAMETER Platform
    Specifies which platform to collect from. Valid values are:
    - All: Collects from both M365 and Azure
    - Azure: Collects only from Azure/Entra ID
    - M365: Collects only from Microsoft 365
    Default: All

    .PARAMETER LogLevel
    Specifies the level of logging detail. Valid values are:
    - None: No logging
    - Minimal: Critical errors only
    - Standard: Normal operational logging
    Default: Minimal

    .PARAMETER UserIds
    Optional. Comma-separated list of user IDs to filter the collection scope.

    .PARAMETER Output
    Output is the parameter specifying the CSV, JSON, JSONL or SOF-ELK output type. The SOF-ELK output can be imported into the platform of the same name.
	Default: CSV

    .PARAMETER Interactive
    Switch to enable interactive mode, showing the collection menu.

    .EXAMPLE
    Start-EvidenceCollection -ProjectName "Case123" -Platform "All" -Interactive
    Starts an interactive collection for all platforms with the project name "Case123".

    .EXAMPLE
    Start-EvidenceCollection -ProjectName "Investigation" -Platform "M365" -UserIds "user@domain.com"
    Starts an automated collection of M365 data for a specific user with standard logging.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ProjectName,
        [Parameter(Mandatory=$false)]
        [ValidateSet('All', 'Azure', 'M365')]
        [string]$Platform = 'All',
        [Parameter(Mandatory=$false)]
        [ValidateSet('None', 'Minimal', 'Standard', 'Debug')]
        [string]$LogLevel = 'Minimal',
        [Parameter(Mandatory=$false)]
        [string]$UserIds,
        [Parameter(Mandatory=$false)]
        [switch]$Interactive,
        [Parameter(Mandatory=$false)]
        [ValidateSet('CSV', 'JSON', 'SOF-ELK', "JSONL")]
        [string]$Output = 'CSV',
        [Parameter(Mandatory=$false)]
        [string]$OutputDir
    )

    if ($Interactive) {
        $proceed = Show-CollectionMenu -Platform $Platform
        if (-not $proceed) {
            Write-LogFile -Message "Collection cancelled by user" -Color "Yellow" -Level Minimal
            return
        }
    }

    $summary = @{
        StartTime = Get-Date
        ProcessingTime = $null
        SuccessfulTasks = 0
        FailedTasks = 0
        TotalTasks = 0
        Platform = $Platform
    }

    if (-not (Test-RequiredConnections -Platform $Platform)) {
        Write-LogFile -Message "[ERROR] Please establish all required connections before running this script" -Color "Red" -Level Minimal
        return
    }

    if ([string]::IsNullOrEmpty($OutputDir)) {
        $OutputDir = "Output\$ProjectName"
    } else {
        # Ensure the path ends with the project name
        $OutputDir = Join-Path $OutputDir $ProjectName
    }

    if (!(Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Force -Path $OutputDir > $null
        Write-LogFile -Message "[INFO] Creating output directory: $OutputDir" -Level Minimal
    }

    Write-LogFile -Message "`n=== Evidence Collection Overview ===" -Color "Cyan" -Level Minimal
    Write-LogFile -Message "Project: $ProjectName" -Level Minimal
    Write-LogFile -Message "Platform: $(if ($Platform -eq 'All') { 'Microsoft 365 and Azure/Entra ID' } else { $Platform })" -Level Minimal
    if ($UserIds) {
        Write-LogFile -Message "Target User(s): $UserIds" -Level Minimal
    }
    Write-LogFile -Message "Output Directory: $OutputDir" -Level Minimal
    Write-LogFile -Message "Start Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -Level Minimal
    Write-LogFile -Message "----------------------------------------" -Level Minimal

    if ($Platform -eq "All" -or $Platform -eq "Azure") {
        Write-LogFile -Message "`n==== Starting Azure/Entra ID Data Collection ====" -Color "Yellow" -Level Minimal
        foreach ($task in $Global:CollectionTasks.Azure.GetEnumerator()) {
            if ($task.Value.Enabled) {
                try {
                    $script:CollectionOutputDir = $OutputDir
                    $executed = & $task.Value.Function $OutputDir $LogLevel $UserIds $Output
                    if ($executed) {
                        $summary.TotalTasks++
                        $summary.SuccessfulTasks++
                    Write-TaskProgress -TaskName $task.Value.Name -Status 'Complete'
                    }
                }
                catch {
                    $summary.TotalTasks++
                    $summary.FailedTasks++
                    Write-TaskProgress -TaskName $task.Value.Name -Status 'Failed' -ErrorMessage $_.Exception.Message
                }
            }
        }
    }

    if ($Platform -eq "All" -or $Platform -eq "M365") {
        Write-LogFile -Message "`n==== Starting Microsoft 365 Data Collection ====" -Color "Yellow" -Level Minimal
        foreach ($task in $Global:CollectionTasks.M365.GetEnumerator()) {
            if ($task.Value.Enabled) {
                try {
                    $script:CollectionOutputDir = $OutputDir
                    $executed = & $task.Value.Function $OutputDir $LogLevel $UserIds $Output
                    if ($executed) {
                        $summary.TotalTasks++
                        $summary.SuccessfulTasks++
                        Write-TaskProgress -TaskName $task.Value.Name -Status 'Complete'
                    }
                }
                catch {
                    $summary.TotalTasks++
                    $summary.FailedTasks++
                    Write-TaskProgress -TaskName $task.Value.Name -Status 'Failed' -ErrorMessage $_.Exception.Message
                }
            }
        }
    }    

    $summary.ProcessingTime = (Get-Date) - $summary.StartTime
    $summaryData = [ordered]@{
        "Collection Details" = [ordered]@{
            "Project Name" = $ProjectName
            "Platform" = if ($Platform -eq 'All') { 'Microsoft 365 and Azure/Entra ID' } else { $Platform }
            "Target User(s)" = if ($UserIds) { $UserIds } else { "All Users" }
        }
        "Timing" = [ordered]@{
            "Start Time" = $summary.StartTime.ToString('yyyy-MM-dd HH:mm:ss')
            "End Time" = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
            "Duration" = $summary.ProcessingTime.ToString('hh\:mm\:ss')
        }
        "Task Status" = [ordered]@{
            "Total Tasks" = $summary.TotalTasks
            "Successful" = $summary.SuccessfulTasks
            "Failed" = $summary.FailedTasks
        }
    }

    Write-Summary -Summary $summaryData -Title "Collection Summary"
    Write-LogFile -Message "`nOutput Location: $OutputDir" -Level Minimal -Color "Cyan"
}