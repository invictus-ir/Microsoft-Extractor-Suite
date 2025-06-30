function Start-MESTriage {
<#
    .SYNOPSIS
    Performs a quick security triage for specific users across Entra ID and Microsoft 365 environments.

    .DESCRIPTION
    Executes triage tasks based on template files in the TriageTemplates directory.
    Automatically discovers all available templates (built-in and custom).
    Users can easily customize templates by commenting/uncommenting tasks. Default templates:
    - Quick: Critical security indicators only (fastest, essential data)
    - Default: Standard investigation data (balanced approach)
    - Full: Comprehensive data collection (everything available)

    .PARAMETER Template
    Template to use. Available templates are automatically discovered from TriageTemplates folder.
    Built-in: Quick, Standard, Comprehensive
    Custom: Any .psd1 file in TriageTemplates folder

    .PARAMETER TriageName
    TriageName is the mandatory parameter specifying the name of the triage project. This will be used as the folder name for outputs.

    .PARAMETER UserIds
    UserIds is the parameter specifying the target users for the triage. You can enter multiple email addresses separated by commas.

    .PARAMETER StartDate
    StartDate is the parameter specifying the start date of the date range for time-based queries.
    Default: Today -180 days

    .PARAMETER EndDate
    EndDate is the parameter specifying the end date of the date range for time-based queries.
    Default: Now

    .PARAMETER Output
    Output is the parameter specifying the CSV, JSON, or SOF-ELK output type. Note: Some tasks automatically use JSON format regardless of this setting.
    Default: CSV

    .PARAMETER MergeOutput
    MergeOutput is the parameter specifying if you wish to merge outputs to single files where applicable.

    .PARAMETER OutputDir
    OutputDir is the parameter specifying the output directory. If not specified, creates Output\[TriageName]
    Default: Output\[TriageName]

    .PARAMETER Encoding
    Encoding is the parameter specifying the encoding of the output files.
    Default: UTF8

    .PARAMETER LogLevel
    Specifies the level of logging:
    None: No logging
    Minimal: Critical errors only  
    Standard: Normal operational logging
    Debug: Verbose logging for debugging purposes
    Default: Minimal

     .EXAMPLE
    Start-MESTriage -Template Quick -TriageName "Investigation001" -UserIds "user@domain.com"
    Performs a quick triage for a single user with project name "Investigation001".

    .EXAMPLE
    Start-MESTriage -Template Default -TriageName "Standard" -UserIds "user1@domain.com,user2@domain.com"
    Performs a standard triage for multiple users.

    .EXAMPLE
    Start-MESTriage -Template Comprehensive -TriageName "Comprehensive" -UserIds "user@domain.com" -OutputDir "C:\Investigations"
    Performs a full comprehensive triage with custom output directory.
#>

    [CmdletBinding()]
        param (
            [string]$Template = "Standard",
            [string]$StartDate,
            [string]$EndDate,
            [Parameter(Mandatory=$true)]
            [string]$TriageName,
            [string]$UserIds,
            [ValidateSet("CSV", "JSON", "SOF-ELK")]
            [string]$Output = "CSV",
            [switch]$MergeOutput,
            [string]$OutputDir,
            [string]$Encoding = "UTF8",
            [ValidateSet('None', 'Minimal', 'Standard', 'Debug')]
            [string]$LogLevel = 'Minimal'
        )

    Set-LogLevel -Level ([LogLevel]::$LogLevel)
    $isDebugEnabled = $script:LogLevel -eq [LogLevel]::Debug

    $moduleRoot = (Get-Module Microsoft-Extractor-Suite).ModuleBase
    $templatesDir = Join-Path $moduleRoot "TriageTemplates"
    
    # Get all available templates
    $availableTemplates = @()
    if (Test-Path $templatesDir) {
        $templateFiles = Get-ChildItem $templatesDir -Filter "*.psd1"
        $availableTemplates = $templateFiles | ForEach-Object { 
            [System.IO.Path]::GetFileNameWithoutExtension($_.Name) 
        }
    }
    
    # Validate the template parameter
    if ($Template -notin $availableTemplates) {
        Write-LogFile -Message "[ERROR] Template '$Template' not found." -Color "Red" -Level Minimal
        Write-LogFile -Message "[INFO] Available templates: $($availableTemplates -join ', ')" -Level Minimal
        Write-LogFile -Message "[INFO] Create custom templates by adding .psd1 files to: $templatesDir" -Level Minimal
        return
    }

    # Build template path
    $templatePath = Join-Path $templatesDir "$Template.psd1"
    
    if (!(Test-Path $templatePath)) {
        Write-LogFile -Message "[ERROR] Template file not found: $templatePath" -Color "Red" -Level Minimal
        return
    }

    try {
        $templateConfig = Import-PowerShellDataFile -Path $templatePath
    }
    catch {
        Write-LogFile -Message "[ERROR] Failed to load template: $($_.Exception.Message)" -Color "Red" -Level Minimal
        return
    }

    $UserIdsArray = if ($UserIds -and $UserIds.Trim()) { 
        @($UserIds -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) 
    } else { 
        @() 
    }

    $triageSummary = @{
        StartTime = Get-Date
        ProcessingTime = $null
        SuccessfulTasks = 0
        FailedTasks = 0
        SkippedTasks = 0
        TotalTasks = 0
        TriageType = "$Template Template"
        TargetUsers = if ($UserIds) { $UserIds } else { "All users" }
        TemplateName = $Template
    }
    
    Write-LogFile -Message "=== Starting Quick Triage ===" -Color "Cyan" -Level Minimal
    Write-LogFile -Message "Project: $TriageName" -Level Minimal
    Write-LogFile -Message "Template: $Template" -Level Minimal

    if ($UserIdsArray.Count -eq 0) {
        Write-LogFile -Message "Target: All users" -Level Minimal 
    } elseif ($UserIdsArray.Count -eq 1) {
        Write-LogFile -Message "Target User: $($UserIdsArray[0])" -Level Minimal 
    } else {
        Write-LogFile -Message "Target Users:" -Level Minimal
        foreach ($user in $UserIdsArray) {
            Write-LogFile -Message "  - $user" -Level Minimal
        }
    }

    Write-LogFile -Message "Start Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -Level Minimal

    if ([string]::IsNullOrEmpty($OutputDir)) {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $OutputDir = "Output\$TriageName"
    }
    else {
        $OutputDir = Join-Path $OutputDir $TriageName
    }
    if (!(Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Force -Path $OutputDir > $null
        Write-LogFile -Message "[INFO] Creating output directory: $OutputDir" -Level Standard
    }

    # Validate template has tasks
    if (!$templateConfig.Tasks -or $templateConfig.Tasks.Count -eq 0) {
        Write-LogFile -Message "[ERROR] No tasks defined in template" -Color "Red" -Level Minimal
        return
    }

    Write-LogFile -Message "`n==== Executing Template Tasks ====" -Color "Yellow" -Level Minimal
    Write-LogFile -Message "[INFO] Total tasks to execute: $($templateConfig.Tasks.Count)`n" -Level Minimal

    foreach ($task in $templateConfig.Tasks) {
        $triageSummary.TotalTasks++
        
        if ($task -is [string]) {
            $willSkip = Test-TaskWillSkip -TaskName $task -UserIds $UserIdsArray
    
            if (-not $willSkip) {
                Write-TaskProgress -TaskName $task -Status 'InProgress'
            }
            
            try {
                $executed = Invoke-TriageTask -TaskName $task -OutputDir $OutputDir -LogLevel $LogLevel -UserIds $UserIdsArray -Output $Output -MergeOutput:$MergeOutput -StartDate $StartDate -EndDate $EndDate -Encoding $Encoding
                
                if ($executed -eq $true) {
                    $triageSummary.SuccessfulTasks++
                    Write-TaskProgress -TaskName $task -Status 'Complete'
                } elseif ($executed -eq $false) {
                    $triageSummary.FailedTasks++
                    Write-TaskProgress -TaskName $task -Status 'Failed' -ErrorMessage "Task failed"
                } elseif ($executed -eq 'SKIP') {
                    $triageSummary.SkippedTasks++
                } else {
                    $triageSummary.FailedTasks++
                    Write-TaskProgress -TaskName $task -Status 'Failed' -ErrorMessage "Task returned unexpected value"
                }
            }
            catch {
                $triageSummary.FailedTasks++
                Write-TaskProgress -TaskName $task -Status 'Failed' -ErrorMessage $_.Exception.Message
                Write-LogFile -Message "[ERROR] Task $task failed: $($_.Exception.Message)" -Color "Red" -Level Minimal
            }
        }
        elseif ($task -is [hashtable] -and $task.Task -eq "UALOperations") {
            if ($task.Operations.Count -eq 0) {
                $triageSummary.SkippedTasks++
                continue
            }
            else {
                Write-TaskProgress -TaskName "UAL Operations" -Status 'InProgress'
                try {
                    $userIdsString = if ($UserIdsArray.Count -gt 0) { $UserIdsArray -join ',' } else { $null }
                    Get-QuickUALOperations -Operations $task.Operations -UserIds $userIdsString -OutputDir $OutputDir -LogLevel $LogLevel -Output $Output -StartDate $StartDate -EndDate $EndDate
                    
                    $triageSummary.SuccessfulTasks++
                    Write-TaskProgress -TaskName "UAL Operations" -Status 'Complete'
                }
                catch {
                    $triageSummary.FailedTasks++
                    Write-TaskProgress -TaskName "UAL Operations" -Status 'Failed' -ErrorMessage $_.Exception.Message
                    Write-LogFile -Message "[ERROR] UAL Operations failed: $($_.Exception.Message)" -Color "Red" -Level Minimal
                }
            }  
        }
    }
    

    $triageSummary.ProcessingTime = (Get-Date) - $triageSummary.StartTime
    
    Write-LogFile -Message "`n=== $Template Triage Summary ===" -Color "Cyan" -Level Minimal
    Write-LogFile -Message "Start Time: $($triageSummary.StartTime.ToString('yyyy-MM-dd HH:mm:ss'))" -Level Minimal
    Write-LogFile -Message "End Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -Level Minimal
    Write-LogFile -Message "Duration: $($triageSummary.ProcessingTime.ToString('hh\:mm\:ss'))" -Level Minimal
    Write-LogFile -Message "`nTask Results:" -Level Minimal
    Write-LogFile -Message "  Successful: $($triageSummary.SuccessfulTasks)" -Level Minimal -Color "Green"
    Write-LogFile -Message "  Failed: $($triageSummary.FailedTasks)" -Level Minimal -Color $(if ($triageSummary.FailedTasks -gt 0) { "Red" } else { "Green" })
    Write-LogFile -Message "  Skipped: $($triageSummary.SkippedTasks)" -Level Minimal -Color "Yellow"
    Write-LogFile -Message "  Total: $($triageSummary.TotalTasks)" -Level Minimal
    
    Write-LogFile -Message "`nOutput Location: $OutputDir" -Level Minimal
    Write-LogFile -Message "=============================================" -Color "Cyan" -Level Minimal
}
    

function Invoke-TriageTask {
    param(
        [string]$TaskName,
        [string]$OutputDir,
        [string]$LogLevel,
        [array]$UserIds,
        [string]$Output,
        [bool]$MergeOutput,
        [string]$StartDate,
        [string]$EndDate,
        [string]$Encoding 
    )

    switch ($TaskName) {
        "Get-RiskyUsers" {
            if ($UserIds.Count -gt 0) {
                Get-RiskyUsers -OutputDir $OutputDir -LogLevel $LogLevel -UserIds $UserIds -Encoding $Encoding
            } else {
                Get-RiskyUsers -OutputDir $OutputDir -LogLevel $LogLevel -Encoding $Encoding
            }
            return $true
        }
        "Get-RiskyDetections" {
            if ($UserIds.Count -gt 0) {
                Get-RiskyDetections -OutputDir $OutputDir -LogLevel $LogLevel -UserIds $UserIds -Encoding $Encoding
            } else {
                Get-RiskyDetections -OutputDir $OutputDir -LogLevel $LogLevel -Encoding $Encoding
            }
            return $true
        }
        "Get-MFA" {
            if ($UserIds.Count -gt 0) {
                Get-MFA -OutputDir $OutputDir -LogLevel $LogLevel -UserIds $UserIds -Encoding $Encoding
            } else {
                Get-MFA -OutputDir $OutputDir -LogLevel $LogLevel -Encoding $Encoding
            }
            return $true
        }
        "Get-MailboxRules" {
            if ($UserIds.Count -gt 0) {
                Get-MailboxRules -OutputDir $OutputDir -LogLevel $LogLevel -UserIds $UserIds -Encoding $Encoding
            } else {
                Get-MailboxRules -OutputDir $OutputDir -LogLevel $LogLevel -Encoding $Encoding
            }
            return $true
        }
        "Get-OAuthPermissionsGraph" {
            if ($UserIds.Count -gt 0) {
                Get-EntraApplicationsForSpecificUsers -OutputDir $OutputDir -LogLevel $LogLevel -UserIds $UserIds -Encoding $Encoding
            } else {
                Get-OAuthPermissionsGraph -OutputDir $OutputDir -LogLevel $LogLevel -Encoding $Encoding
            }
            return $true
        }
        "Get-EntraAuditLogs" {
            if ($UserIds.Count -gt 0) {
                Get-EntraAuditLogs -OutputDir $OutputDir -LogLevel $LogLevel -UserIds $UserIds -Encoding $Encoding -MergeOutput -StartDate $StartDate -EndDate $EndDate
            } else {
                Get-EntraAuditLogs -OutputDir $OutputDir -LogLevel $LogLevel -Encoding $Encoding -MergeOutput -StartDate $StartDate -EndDate $EndDate
            }
            return $true
        }
        "Get-EntraSignInLogs" {
            if ($UserIds.Count -gt 0) {
                Get-EntraSignInLogs -OutputDir $OutputDir -LogLevel $LogLevel -UserIds $UserIds -Encoding $Encoding -MergeOutput -StartDate $StartDate -EndDate $EndDate
            } else {
                Get-EntraSignInLogs -OutputDir $OutputDir -LogLevel $LogLevel -Encoding $Encoding -MergeOutput -StartDate $StartDate -EndDate $EndDate
            }
            return $true
        }
        "Get-GraphEntraSignInLogs" {
            $finalOutput = if ($Output -eq 'CSV') { 'JSON' } else { $Output }            
            if ($UserIds.Count -gt 0) {
                Get-GraphEntraSignInLogs -OutputDir $OutputDir -LogLevel $LogLevel -UserIds $UserIds -Output $finalOutput -MergeOutput -Encoding $Encoding -StartDate $StartDate -EndDate $EndDate
            } else {
                Get-GraphEntraSignInLogs -OutputDir $OutputDir -LogLevel $LogLevel -Output $finalOutput -MergeOutput -Encoding $Encoding -StartDate $StartDate -EndDate $EndDate
            }
            return $true
        }
        "Get-GraphEntraAuditLogs" {
            $finalOutput = if ($Output -eq 'CSV') { 'JSON' } else { $Output }   
            $OutputDirAudit = "$OutputDir\Audit logs"
            New-Item -ItemType Directory -Force -Path $OutputDirAudit > $null       
            if ($UserIds.Count -gt 0) {
                Get-GraphEntraAuditLogs -OutputDir $OutputDirAudit -LogLevel $LogLevel -UserIds $UserIds -Output $finalOutput -MergeOutput -Encoding $Encoding -StartDate $StartDate -EndDate $EndDate
            } else {
                Get-GraphEntraAuditLogs -OutputDir $OutputDirAudit -LogLevel $LogLevel -Output $finalOutput -MergeOutput -Encoding $Encoding -StartDate $StartDate -EndDate $EndDate
            }
            return $true
        }
        "Get-UAL" {
            if ($UserIds.Count -gt 0) {
                $userIdsString = $UserIds -join ',' 
                 $OutputDirAudit = "$OutputDir\Unified Audit Logs"
                Get-UAL -OutputDir $OutputDirAudit -LogLevel $LogLevel -UserIds $userIdsString -Output $Output -Encoding $Encoding -StartDate $StartDate -EndDate $EndDate -MergeOutput
            } else {
                Get-UAL -OutputDir $OutputDirAudit -LogLevel $LogLevel -Output $Output -Encoding $Encoding -StartDate $StartDate -EndDate $EndDate -MergeOutput
            }
            return $true
        }
        "Get-UALStatistics" {
            if ($UserIds.Count -gt 0) {
                $userIdsString = $UserIds -join ','
                Get-UALStatistics -OutputDir $OutputDir -LogLevel $LogLevel -UserIds $userIdsString -StartDate $StartDate -EndDate $EndDate -WarningAction SilentlyContinue
            } else {
                Get-UALStatistics -OutputDir $OutputDir -LogLevel $LogLevel -StartDate $StartDate -EndDate $EndDate -WarningAction SilentlyContinue
            }           
            return $true
        }
        "Get-MailboxAuditLog" {
            if ($UserIds.Count -gt 0) {
                Get-MailboxAuditLog -OutputDir $OutputDir -LogLevel $LogLevel -UserIds $UserIds -Encoding $Encoding -StartDate $StartDate -EndDate $EndDate
            } else {
                Get-MailboxAuditLog -OutputDir $OutputDir -LogLevel $LogLevel -Encoding $Encoding -StartDate $StartDate -EndDate $EndDate
            }
            return $true
        }
        "Get-MessageTraceLog" {
            try {
                if ($UserIds.Count -gt 0) {
                    Get-MessageTraceLog -OutputDir $OutputDir -LogLevel $LogLevel -UserIds $UserIds -Encoding $Encoding -ErrorAction SilentlyContinue -StartDate $StartDate -EndDate $EndDate
                } else {
                    Get-MessageTraceLog -OutputDir $OutputDir -LogLevel $LogLevel -Encoding $Encoding -ErrorAction SilentlyContinue -StartDate $StartDate -EndDate $EndDate
                }
                return $true
            }
            catch {
                return $false
            }
        }
        "Get-ActivityLogs" {
            if ($UserIds.Count -gt 0) {
                Get-ActivityLogs -OutputDir $OutputDir -LogLevel $LogLevel -Encoding $Encoding -UserIds $UserIds -StartDate $StartDate -EndDate $EndDate
            } else {
                Get-ActivityLogs -OutputDir $OutputDir -LogLevel $LogLevel -Encoding $Encoding -StartDate $StartDate -EndDate $EndDate
            }
            return $true
        }
        "Get-DirectoryActivityLogs" {
            if ($UserIds.Count -gt 0) {
                return 'SKIP'
            }
            Get-DirectoryActivityLogs -OutputDir $OutputDir -LogLevel $LogLevel -Encoding $Encoding -StartDate $StartDate -EndDate $EndDate
            return $true
        }
        "Get-Users" {
            if ($UserIds.Count -gt 0) {
                $userIdsString = $UserIds -join ',' 
                Get-Users -OutputDir $OutputDir -LogLevel $LogLevel -UserIds $userIdsString -Encoding $Encoding
            } else {
                Get-Users -OutputDir $OutputDir -LogLevel $LogLevel -Encoding $Encoding
            }
            return $true
        }
        "Get-AdminUsers" {
            Get-AdminUsers -OutputDir $OutputDir -LogLevel $LogLevel -Encoding $Encoding
            return $true
        }
        "Get-Devices" {
            if ($UserIds.Count -gt 0) {
                $userIdsString = $UserIds -join ',' 
                Get-Devices -OutputDir $OutputDir -LogLevel $LogLevel -UserIds $userIdsString -Encoding $Encoding
            } else {
                Get-Devices -OutputDir $OutputDir -LogLevel $LogLevel -Encoding $Encoding
            }
            return $true
        }
        "Get-MailboxAuditStatus" {
            if ($UserIds.Count -gt 0) {
                Get-MailboxAuditStatus -OutputDir $OutputDir -LogLevel $LogLevel -UserIds $UserIds -Encoding $Encoding
            } else {
                Get-MailboxAuditStatus -OutputDir $OutputDir -LogLevel $LogLevel -Encoding $Encoding
            }
            return $true
        }
        "Get-MailboxPermissions" {
            if ($UserIds.Count -gt 0) {
                Get-MailboxPermissions -OutputDir $OutputDir -LogLevel $LogLevel -UserIds $UserIds -Encoding $Encoding
            } else {
                Get-MailboxPermissions -OutputDir $OutputDir -LogLevel $LogLevel -Encoding $Encoding
            }
            return $true
        }
        "Get-UALGraph" {
            if ($UserIds.Count -gt 0) {
                Get-UALGraph -OutputDir $OutputDir -LogLevel $LogLevel -UserIds $UserIds -Output $Output -Encoding $Encoding -StartDate $StartDate -EndDate $EndDate
            } else {
                Get-UALGraph -OutputDir $OutputDir -LogLevel $LogLevel -Output $Output -Encoding $Encoding -StartDate $StartDate -EndDate $EndDate
            }
            return $true
        }
        "Get-TransportRules" {
            if ($UserIds.Count -gt 0) {
                return 'SKIP'
            }
            Get-TransportRules -OutputDir $OutputDir -LogLevel $LogLevel -Encoding $Encoding
            return $true
        }
        "Get-ConditionalAccessPolicies" {
            if ($UserIds.Count -gt 0) {
                return 'SKIP'
            }
            Get-ConditionalAccessPolicies -OutputDir $OutputDir -LogLevel $LogLevel -Encoding $Encoding
            return $true
        }
        "Get-Licenses" {
            if ($UserIds.Count -gt 0) {
                return 'SKIP'
            }
            Get-Licenses -OutputDir $OutputDir -LogLevel $LogLevel
            return $true
        }
        "Get-LicenseCompatibility" {
            if ($UserIds.Count -gt 0) {
                return 'SKIP'
            }
            Get-LicenseCompatibility -OutputDir $OutputDir -LogLevel $LogLevel
            return $true
        }
        "Get-EntraSecurityDefaults" {
            if ($UserIds.Count -gt 0) {
                return 'SKIP'
            }
            Get-EntraSecurityDefaults -OutputDir $OutputDir -LogLevel $LogLevel
            return $true
        }
        "Get-LicensesByUser" {
            if ($UserIds.Count -gt 0) {
                return 'SKIP'
            }
            Get-LicensesByUser -OutputDir $OutputDir -LogLevel $LogLevel 
            return $true
        }
        "Get-Groups" {
            if ($UserIds.Count -gt 0) {
                return 'SKIP'
            }
            Get-Groups -OutputDir $OutputDir -LogLevel $LogLevel -Encoding $Encoding
            return $true
        }
        "Get-GroupMembers" {
            if ($UserIds.Count -gt 0) {
                return 'SKIP'
            }
            Get-GroupMembers -OutputDir $OutputDir -LogLevel $LogLevel -Encoding $Encoding
            return $true
        }
        "Get-DynamicGroups" {
            if ($UserIds.Count -gt 0) {
                return 'SKIP'
            }
            Get-DynamicGroups -OutputDir $OutputDir -LogLevel $LogLevel -Encoding $Encoding
            return $true
        }
        "Get-SecurityAlerts" {
            if ($UserIds.Count -gt 0) {
                return 'SKIP'
            }
            Get-SecurityAlerts -OutputDir $OutputDir -LogLevel $LogLevel -Encoding $Encoding
            return $true
            }
        "Get-PIMAssignments" {
            if ($UserIds.Count -gt 0) {
                return 'SKIP'
            }
            Get-PIMAssignments -OutputDir $OutputDir -LogLevel $LogLevel -Encoding $Encoding
            return $true
        }
        "Get-AllRoleActivity" {
            if ($UserIds.Count -gt 0) {
                return 'SKIP'
            }
            Get-AllRoleActivity -OutputDir $OutputDir -LogLevel $LogLevel -Encoding $Encoding
            return $true
        }
        default {
            Write-LogFile -Message "[ERROR] Unknown task: $TaskName" -Color "Red" -Level Minimal
            return $false
        }
    }
}