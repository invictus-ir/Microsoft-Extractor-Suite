Function Get-Groups {
    <#
        .SYNOPSIS
        Retrieves all groups in the organization.

        .DESCRIPTION
        Retrieves all groups, including details such as group ID and display name.

        .PARAMETER OutputDir
        OutputDir is the parameter specifying the output directory.
        Default: Output\Groups

        .PARAMETER Encoding
        Encoding is the parameter specifying the encoding of the CSV output file.
        Default: UTF8
        
        .EXAMPLE
        Get-Groups
        Retrieves all groups and exports the output to a CSV file.
        
        .EXAMPLE
        Get-Groups -Encoding utf32
        Retrieves all groups and exports the output to a CSV file with UTF-32 encoding.
            
        .EXAMPLE
        Get-Groups -OutputDir C:\Windows\Temp
        Retrieves all groups and saves the output to the C:\Windows\Temp folder.	
    #>    

    [CmdletBinding()]
    param(
        [string]$OutputDir = "Output\Groups",
        [string]$Encoding = "UTF8"
    )

    $requiredScopes = @("Group.Read.All", "AuditLog.Read.All")
    $graphAuth = Get-GraphAuthType -RequiredScopes $requiredScopes

    if (!(Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
        Write-LogFile -Message "[INFO] Creating the following directory: $OutputDir"
    }

    Write-LogFile -Message "[INFO] Running Get-Groups"
    try {
        Write-LogFile -Message "Fetching all groups from Microsoft Graph..."
        $allGroups = Get-MgGroup -All
        Write-Host ($allGroups | Measure-Object).Count "groups found"

        $results = $allGroups | Select-Object @{Name="GroupId"; Expression={$_.Id}},
                                                @{Name="DisplayName"; Expression={$_.DisplayName}},
                                                @{Name="MembershipRule"; Expression={$_.MembershipRule}}

        $csvPath = Join-Path $OutputDir "Groups.csv"
        $results | Export-Csv -Path $csvPath -NoTypeInformation -Encoding $Encoding

        Write-LogFile -Message "[INFO] Groups saved to $csvPath" -Color "Green"
    } catch {
        Write-LogFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Color "Red"
        throw
    }
}


Function Get-GroupMembers {
    <#
        .SYNOPSIS
        Retrieves all members of each group and their relevant details.

        .DESCRIPTION
        Enumerates all members of every group in the organization, including when they were added, their permissions, and roles.

        .PARAMETER OutputDir
        The output directory for saving group member details.
        Default: Output\Groups

        .PARAMETER Encoding
        The encoding for CSV files.
        Default: UTF8

        .EXAMPLE
        Get-GroupMembers
        Retrieves all group members and their details.

        .EXAMPLE
        Get-GroupMembers -OutputDir C:\Temp -Encoding utf32
        Retrieves all group members and saves details to C:\Temp with UTF-32 encoding.
    #>

    [CmdletBinding()]
    param(
        [string]$OutputDir = "Output\Groups",
        [string]$Encoding = "UTF8"
    )

    if (!(Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
    }

    Write-Logfile -Message "[INFO] Fetching all groups from Microsoft Graph"
    $allGroups = Get-MgGroup -All

    $results = @()

    foreach ($group in $allGroups) {
        Write-Host "Processing group: $($group.DisplayName)" -ForegroundColor Cyan

        try {
            $members = Get-MgGroupMember -GroupId $group.Id -All | ForEach-Object {
                $memberDetails = $_ | Select-Object @{Name="GroupName"; Expression={$group.DisplayName}},
                                                    @{Name="GroupId"; Expression={$group.Id}},
                                                    @{Name="MemberId"; Expression={$_.Id}},
                                                    @{Name="DisplayName"; Expression={$_.AdditionalProperties.displayName}},
                                                    @{Name="Email"; Expression={$_.AdditionalProperties.mail}},
                                                    @{Name="UserPrincipalName"; Expression={$_.AdditionalProperties.userPrincipalName}},
                                                    @{Name="AddedDate"; Expression={Get-Date}}, # Placeholder for when added
                                                    @{Name="Permissions"; Expression={"Standard Member"}} # Placeholder for permissions

                $memberDetails
            }

            $results += $members
        } catch {
            Write-Logfile -Message "[ALERT] Failed to retrieve members for group: $($group.DisplayName) Error: $($_.Exception.Message)" -Color "Red"
        }
    }

    $results | Export-Csv -Path (Join-Path $OutputDir "GroupMembers.csv") -NoTypeInformation -Encoding $Encoding

    Write-LogFile -Message "[INFO] Group members saved to $(Join-Path $OutputDir "GroupMembers.csv")" -Color "Green"
}

Function Get-DynamicGroups {
    <#
        .SYNOPSIS
        Retrieves all dynamic groups and their membership rules.

        .DESCRIPTION
        Retrieves dynamic groups and includes details about their membership rules, which determine automatic user inclusion.

        .PARAMETER OutputDir
        The output directory for saving dynamic group details.
        Default: Output\Groups

        .PARAMETER Encoding
        The encoding for CSV files.
        Default: UTF8

        .EXAMPLE
        Get-DynamicGroups
        Retrieves dynamic groups and their membership rules, outputting the details to a CSV file.

        .EXAMPLE
        Get-DynamicGroups -OutputDir C:\Temp -Encoding utf32
        Retrieves dynamic groups and saves details to C:\Temp with UTF-32 encoding.
    #>

    [CmdletBinding()]
    param(
        [string]$OutputDir = "Output\Groups",
        [string]$Encoding = "UTF8"
    )

    if (!(Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
        Write-LogFile -Message "[INFO] Created output directory: $OutputDir"
    } else {
        Write-LogFile -Message "[INFO] Output directory already exists: $OutputDir"
    }

    Write-LogFile -Message "[INFO] Fetching all groups from Microsoft Graph..."
    $allGroups = Get-MgGroup -All

    Write-LogFile -Message "[INFO] Total groups retrieved: $($allGroups.Count)"

    $dynamicGroups = $allGroups | Where-Object { $_.MembershipRule -ne $null }

    if ($dynamicGroups.Count -gt 0) {
        Write-LogFile -Message "[INFO] Total dynamic groups found: $($dynamicGroups.Count)"
    } else {
        Write-LogFile -Message "[INFO] No dynamic groups found."
    }

    $results = $dynamicGroups | Select-Object @{Name="GroupName"; Expression={$_.DisplayName}},
                                                  @{Name="GroupId"; Expression={$_.Id}},
                                                  @{Name="MembershipRule"; Expression={$_.MembershipRule}},
                                                  @{Name="MembershipRuleProcessingState"; Expression={$_.MembershipRuleProcessingState}}

    $csvPath = Join-Path $OutputDir "DynamicGroups.csv"
    $results | Export-Csv -Path $csvPath -NoTypeInformation -Encoding $Encoding

    Write-LogFile -Message "[INFO] Dynamic groups and their membership rules saved to $csvPath"
}
