$date = Get-Date -Format "yyyyMMddHHmm"
function Show-TransportRules
{
<#
    .SYNOPSIS
    Shows the transport rules in your organization.

    .DESCRIPTION
    Shows the transport rules in your organization.
    
    .Example
    Show-TransportRules
#>
	$transportRules = Get-TransportRule | Select-Object -Property Name,Description,CreatedBy,@{Name="WhenChanged";Expression={(Get-Date $_.WhenChanged).ToUniversalTime()}},State
	
	if ($null -ne $transportRules) {
		write-LogFile -Message "[INFO] Checking all TransportRules"
		foreach ($rule in $transportRules) {
			write-LogFile -Message "[INFO] Found a TransportRule" -Color "Green"
			write-LogFile -Message "Rule Name $($rule.name)" -Color "Yellow"
			write-LogFile -Message "Rule CreatedBy: $($rule.CreatedBy)" -Color "Yellow"
			write-LogFile -Message "When Changed: $($rule.WhenChanged)" -Color "Yellow"
			write-LogFile -Message "Rule State: $($rule.State)" -Color "Yellow"
			write-LogFile -Message "Description: $($rule.Description)" -Color "Yellow"
		}
	}
}

function Get-TransportRules
{
<#
    .SYNOPSIS
    Collects all transport rules in your organization.

    .DESCRIPTION
    Collects all transport rules in your organization.
	The output will be written to a CSV file called "TransportRules.csv".

	.PARAMETER OutputDir
	OutputDir is the parameter specifying the output directory.
	Default: Output\Rules

	.PARAMETER Encoding
	Encoding is the parameter specifying the encoding of the CSV output file.
	Default: UTF8

	.PARAMETER LogLevel
    Specifies the level of logging:
    None: No logging
    Minimal: Critical errors only
    Standard: Normal operational logging
	Debug: Verbose logging for debugging purposes
    Default: Standard
    
    .Example
    Get-TransportRules
#>

	[CmdletBinding()]
	param (
		[string]$OutputDir,
		[string]$Encoding = "UTF8",
        [ValidateSet('None', 'Minimal', 'Standard', 'Debug')]
        [string]$LogLevel = 'Standard'
	)

	Init-Logging
	Init-OutputDir -Component "Rules" -FilePostfix "TransportRules" -CustomOutputDir $OutputDir
    Write-LogFile -Message "=== Starting Transport Rules Collection ===" -Color "Cyan" -Level Standard

	if ($isDebugEnabled) {
		Write-LogFile -Message "[DEBUG] Retrieving transport rules from Exchange Online..." -Level Debug
		$performance = Measure-Command {
			$transportRules = Get-TransportRule | Select-Object -Property Name,Description,CreatedBy,@{Name="WhenChanged";Expression={(Get-Date $_.WhenChanged).ToUniversalTime()}},State,Priority,Mode
		}
		Write-LogFile -Message "[DEBUG] Transport rule retrieval took $([math]::round($performance.TotalSeconds, 2)) seconds" -Level Debug
	} else {
		$transportRules = Get-TransportRule | Select-Object -Property Name,Description,CreatedBy,@{Name="WhenChanged";Expression={(Get-Date $_.WhenChanged).ToUniversalTime()}},State,Priority,Mode
	}

	if ($null -eq $transportRules) {
		Write-LogFile -Message "[INFO] No transport rules found" -Color "Yellow" -Level Minimal
		return
	}

	if ($transportRules -isnot [array]) {
		$transportRules = @($transportRules)
	}

	$enabledCount = 0
	$disabledCount = 0

	$transportRules | ForEach-Object {
		if ($isDebugEnabled) {
			Write-LogFile -Message "[DEBUG] Processing rule: $($_.Name)" -Level Debug
			Write-LogFile -Message "[DEBUG]   State: $($_.State)" -Level Debug
			Write-LogFile -Message "[DEBUG]   Priority: $($_.Priority)" -Level Debug
			Write-LogFile -Message "[DEBUG]   Mode: $($_.Mode)" -Level Debug
			Write-LogFile -Message "[DEBUG]   Created By: $($_.CreatedBy)" -Level Debug
			Write-LogFile -Message "[DEBUG]   When Changed: $($_.WhenChanged)" -Level Debug
		}
		if ($_.State -eq "Enabled") {
			$enabledCount++
		}
		elseif ($_.State -eq "Disabled") {
			$disabledCount++
		}
		else {
			Write-LogFile -Message "[DEBUG] Unknown state value: $($_.State) for rule: $($_.Name)" -Level Standard
		}
	}

	$transportRules | Export-Csv -Path $script:outputFile -NoTypeInformation -Encoding $Encoding

	$summary = [ordered]@{
		"Transport Rules" = [ordered]@{
			"Total Rules" = $transportRules.Count
			"Enabled Rules" = $enabledCount
			"Disabled Rules" = $disabledCount
		}
	}

	Write-Summary -Summary $summary -Title "Transport Rules Summary"
}

function Show-MailboxRules
{
<#
    .SYNOPSIS
    Shows the mailbox rules in your organization.

    .DESCRIPTION
    Shows the mailbox rules in your organization.

	.PARAMETER UserIds
	UserIds is the Identity parameter specifying the mailbox(es) to check.
	Accepts a single UPN or multiple comma-separated UPNs.
	If omitted, all mailboxes in the organization are checked.

	.PARAMETER LogLevel
	Specifies the level of logging:
	None: No logging
	Minimal: Critical errors only
	Standard: Normal operational logging
	Debug: Verbose logging for debugging purposes
	Default: Standard

    .EXAMPLE
    Show-MailboxRules
    .EXAMPLE
    Show-MailboxRules -UserIds "HR@invictus-ir.com,Test@Invictus-ir.com"
#>
	[CmdletBinding()]
	param(
		[string]$UserIds,
		[ValidateSet('None', 'Minimal', 'Standard', 'Debug')]
		[string]$LogLevel = 'Standard'
	)

	Init-Logging

	$amountofRules = 0

	if ([string]::IsNullOrWhiteSpace($UserIds)) {
		Write-LogFile -Message "[INFO] Retrieving all mailboxes..." -Level Standard
		$mailboxList = Get-Mailbox -ResultSize Unlimited | Select-Object -ExpandProperty UserPrincipalName
	} else {
		$mailboxList = $UserIds -split ',' | ForEach-Object { $_.Trim() }
	}

	foreach ($identity in $mailboxList) {
		Write-LogFile -Message "[INFO] Checking $identity..." -Level Standard

		$inboxrule = Get-InboxRule -Mailbox $identity
		if ($inboxrule) {
			Write-LogFile -Message "[INFO] Found InboxRule(s) for: $identity" -Color "Green" -Level Standard
			foreach ($rule in $inboxrule) {
				$amountofRules++
				Write-LogFile -Message "Username: $identity" -Color "Yellow"
				Write-LogFile -Message "RuleName: $($rule.Name)" -Color "Yellow"
				Write-LogFile -Message "RuleEnabled: $($rule.Enabled)" -Color "Yellow"
				Write-LogFile -Message "CopyToFolder: $($rule.CopyToFolder)" -Color "Yellow"
				Write-LogFile -Message "MoveToFolder: $($rule.MoveToFolder)" -Color "Yellow"
				Write-LogFile -Message "RedirectTo: $($rule.RedirectTo)" -Color "Yellow"
				Write-LogFile -Message "ForwardTo: $($rule.ForwardTo)" -Color "Yellow"
				Write-LogFile -Message "ForwardAsAttachmentTo: $($rule.ForwardAsAttachmentTo)" -Color "Yellow"
				Write-LogFile -Message "SoftDeleteMessage: $($rule.SoftDeleteMessage)" -Color "Yellow"
				Write-LogFile -Message "Description: $($rule.Description)" -Color "Yellow"
			}
		}
	}

	if ($amountofRules -gt 0) {
		Write-LogFile -Message "[INFO] A total of $amountofRules Inbox Rules found" -Color "Green"
	} else {
		Write-LogFile -Message "[INFO] No Inbox Rules found!" -Color "Yellow"
	}
}

function Get-MailboxRules
{
<#
    .SYNOPSIS
    Collects all the mailbox rules in your organization.

    .DESCRIPTION
    Collects all the mailbox rules in your organization.
	The output will be written to a CSV file called "InboxRules.csv".
	
	.Parameter UserIds
    UserIds is the Identity parameter specifies the Inbox rule that you want to view.

	.PARAMETER OutputDir
	OutputDir is the parameter specifying the output directory.
	Default: Output\Rules

	.PARAMETER LogLevel
    Specifies the level of logging:
    None: No logging
    Minimal: Critical errors only
    Standard: Normal operational logging
	Debug: Verbose logging for debugging purposes
    Default: Standard

	.PARAMETER Encoding
	Encoding is the parameter specifying the encoding of the CSV output file.
	Default: UTF8
    
    .Example
	Get-MailboxRules -UserIds Test@Invictus-ir.com
    Get-MailboxRules -UserIds "HR@invictus-ir.com,Test@Invictus-ir.com"
#>
	[CmdletBinding()]
	param(
		[string[]]$UserIds,
		[string]$OutputDir,
		[string]$Encoding = "UTF8",
        [ValidateSet('None', 'Minimal', 'Standard', 'Debug')]
        [string]$LogLevel = 'Standard'
	)

	Init-Logging
	Init-OutputDir -Component "Rules" -FilePostfix "MailboxRules" -CustomOutputDir $OutputDir
    Write-LogFile -Message "=== Starting Mailbox Rules Collection ===" -Color "Cyan" -Level Standard

	$results = [System.Collections.Generic.List[object]]::new()
	$summary = @{
		TotalUsers = 0
        UsersWithRules = 0
        TotalRules = 0
        EnabledRules = 0
        ForwardingRules = 0
        ForwardAsAttachmentRules = 0
        RedirectRules = 0
        SoftDeleteRules = 0
		DeleteRules = 0
        HasAttachmentRules = 0
        StopProcessingRules = 0
        HighImportanceRules = 0
	}
	
	if ($null -eq $UserIds -or $UserIds.Count -eq 0 -or [string]::IsNullOrWhiteSpace($UserIds -join '')) {	
		if ($isDebugEnabled) {
			Write-LogFile -Message "[DEBUG] Processing scenario: All mailboxes" -Level Debug
			$performance = Measure-Command {
				$mailboxes = Get-Mailbox -ResultSize Unlimited
			}
			Write-LogFile -Message "[DEBUG] Get-Mailbox took $([math]::round($performance.TotalSeconds, 2)) seconds" -Level Debug
			Write-LogFile -Message "[DEBUG] Retrieved $($mailboxes.Count) mailboxes" -Level Debug
		} else {
			$mailboxes = Get-Mailbox -ResultSize Unlimited
		}
        $summary.TotalUsers = $mailboxes.Count

		foreach ($mailbox in $mailboxes) {
			Write-LogFile -Message "[INFO] Checking rules for: $($mailbox.UserPrincipalName)" -Level Standard
            $rules = Get-InboxRule -Mailbox $mailbox.UserPrincipalName
			
			if ($rules) {
				$summary.UsersWithRules++
				foreach ($rule in $rules) {
					if ($isDebugEnabled) {
						Write-LogFile -Message "[DEBUG]     Processing rule: $($rule.Name)" -Level Debug
						Write-LogFile -Message "[DEBUG]       Enabled: $($rule.Enabled)" -Level Debug
						Write-LogFile -Message "[DEBUG]       Priority: $($rule.Priority)" -Level Debug
						Write-LogFile -Message "[DEBUG]       Forward To: $($rule.ForwardTo)" -Level Debug
						Write-LogFile -Message "[DEBUG]       Redirect To: $($rule.RedirectTo)" -Level Debug
						Write-LogFile -Message "[DEBUG]       Delete Message: $($rule.DeleteMessage)" -Level Debug
						Write-LogFile -Message "[DEBUG]       Soft Delete: $($rule.SoftDeleteMessage)" -Level Debug
					}
					$summary.TotalRules++
					if ($rule.Enabled) { $summary.EnabledRules++ }
                    if ($rule.ForwardTo) { $summary.ForwardingRules++ }
                    if ($rule.ForwardAsAttachmentTo) { $summary.ForwardAsAttachmentRules++ }
                    if ($rule.RedirectTo) { $summary.RedirectRules++ }
                    if ($rule.SoftDeleteMessage) { $summary.SoftDeleteRules++ }
                    if ($rule.DeleteMessage) { $summary.DeleteRules++ }
                    if ($rule.HasAttachment) { $summary.HasAttachmentRules++ }
                    if ($rule.StopProcessingRules) { $summary.StopProcessingRules++ }
                    if ($rule.MarkImportance -eq "High") { $summary.HighImportanceRules++ }

					$results.Add([PSCustomObject]@{
						UserName = $mailbox.UserPrincipalName
                        RuleName = $rule.Name
                        Enabled = $rule.Enabled
                        Priority = $rule.Priority
                        RuleIdentity = $rule.RuleIdentity
                        StopProcessingRules = $rule.StopProcessingRules
                        CopyToFolder = ($rule.CopyToFolder -join ", ")
                        MoveToFolder = ($rule.MoveToFolder -join ", ")
                        RedirectTo = ($rule.RedirectTo -join ", ")
                        ForwardTo  = ($rule.ForwardTo -join ", ")
                        ForwardAsAttachmentTo = ($rule.ForwardAsAttachmentTo -join ", ")
                        ApplyCategory = ($rule.ApplyCategory -join ", ")
                        MarkImportance = $rule.MarkImportance
                        MarkAsRead = $rule.MarkAsRead
                        DeleteMessage = $rule.DeleteMessage
                        SoftDeleteMessage = $rule.SoftDeleteMessage
                        From = ($rule.From -join ", ")
                        SubjectContainsWords = ($rule.SubjectContainsWords -join ", ")
                        SubjectOrBodyContainsWords = ($rule.SubjectOrBodyContainsWords -join ", ")
                        BodyContainsWords = ($rule.BodyContainsWords -join ", ")
                        HasAttachment = $rule.HasAttachment
                        Description = $rule.Description
                        InError = $rule.InError
                        ErrorType = $rule.ErrorType
					})
				}
			}
		}
	}
	else {
		$userList = $UserIds -split ','
        $summary.TotalUsers = $userList.Count

		if ($isDebugEnabled) {
			Write-LogFile -Message "[DEBUG] Processing scenario: Specific users" -Level Debug
			Write-LogFile -Message "[DEBUG] Users to process: $($userList -join ', ')" -Level Debug
			Write-LogFile -Message "[DEBUG] User count: $($userList.Count)" -Level Debug
		}

		foreach ($user in $userList) {
			$trimmedUser = $user.Trim()
			Write-LogFile -Message "[INFO] Checking rules for: $user" -Level Standard

			if ($isDebugEnabled) {
				Write-LogFile -Message "[DEBUG]   Processing user: $trimmedUser" -Level Debug
				$rulePerformance = Measure-Command {
					$rules = Get-InboxRule -Mailbox $trimmedUser
				}
				Write-LogFile -Message "[DEBUG]   Get-InboxRule took $([math]::round($rulePerformance.TotalSeconds, 2)) seconds" -Level Debug
			} else {
				$rules = Get-InboxRule -Mailbox $trimmedUser
			}
			
			if ($rules) {
				$summary.UsersWithRules++
				if ($isDebugEnabled) {
					Write-LogFile -Message "[DEBUG]   Found $($rules.Count) rules for user: $trimmedUser" -Level Debug
				}
				foreach ($rule in $rules) {
					if ($isDebugEnabled) {
						Write-LogFile -Message "[DEBUG]     Processing rule: $($rule.Name)" -Level Debug
						Write-LogFile -Message "[DEBUG]       Enabled: $($rule.Enabled)" -Level Debug
						Write-LogFile -Message "[DEBUG]       Priority: $($rule.Priority)" -Level Debug
						Write-LogFile -Message "[DEBUG]       Forward To: $($rule.ForwardTo)" -Level Debug
						Write-LogFile -Message "[DEBUG]       Redirect To: $($rule.RedirectTo)" -Level Debug
					}
					$summary.TotalRules++
					if ($rule.Enabled) { $summary.EnabledRules++ }
                    if ($rule.ForwardTo) { $summary.ForwardingRules++ }
                    if ($rule.ForwardAsAttachmentTo) { $summary.ForwardAsAttachmentRules++ }
                    if ($rule.RedirectTo) { $summary.RedirectRules++ }
                    if ($rule.SoftDeleteMessage) { $summary.SoftDeleteRules++}
                    if ($rule.DeleteMessage) { $summary.DeleteRules++ }
                    if ($rule.HasAttachment) { $summary.HasAttachmentRules++ }
                    if ($rule.StopProcessingRules) { $summary.StopProcessingRules++ }
                    if ($rule.MarkImportance -eq "High") { $summary.HighImportanceRules++ }  

					$results.Add([PSCustomObject]@{
						UserName = $user
                        RuleName = $rule.Name
                        Enabled = $rule.Enabled
                        Priority = $rule.Priority
                        RuleIdentity = $rule.RuleIdentity
                        StopProcessingRules = $rule.StopProcessingRules
                        CopyToFolder = ($rule.CopyToFolder -join ", ")
                        MoveToFolder = ($rule.MoveToFolder -join ", ")
                        RedirectTo = ($rule.RedirectTo -join ", ")
                        ForwardTo = ($rule.ForwardTo -join ", ")
                        ForwardAsAttachmentTo = ($rule.ForwardAsAttachmentTo -join ", ")
                        ApplyCategory = ($rule.ApplyCategory -join ", ")
                        MarkImportance = $rule.MarkImportance
                        MarkAsRead = $rule.MarkAsRead
                        DeleteMessage = $rule.DeleteMessage
                        SoftDeleteMessage = $rule.SoftDeleteMessage
                        From = ($rule.From -join ", ")
                        SubjectContainsWords = ($rule.SubjectContainsWords -join ", ")
                        SubjectOrBodyContainsWords = ($rule.SubjectOrBodyContainsWords -join ", ")
                        BodyContainsWords = ($rule.BodyContainsWords -join ", ")
                        HasAttachment = $rule.HasAttachment
                        Description = $rule.Description
                        InError = $rule.InError
                        ErrorType = $rule.ErrorType
					})
				}
			}
		}
	}

	if ($results.Count -gt 0) {
		$results | Export-Csv -Path $script:outputFile -NoTypeInformation -Encoding $Encoding
	}

	$summaryOutput = [ordered]@{
		"User Statistics" = [ordered]@{
			"Users Processed" = $summary.TotalUsers
			"Users with Rules" = $summary.UsersWithRules
			"Total Rules Found" = $summary.TotalRules
			"Enabled Rules" = $summary.EnabledRules
		}
	}

	# Only add rule types that have counts > 0
	$ruleTypes = [ordered]@{}
	if ($summary.ForwardingRules -gt 0) { $ruleTypes["Forwarding Rules"] = $summary.ForwardingRules }
	if ($summary.ForwardAsAttachmentRules -gt 0) { $ruleTypes["Forward As Attachment Rules"] = $summary.ForwardAsAttachmentRules }
	if ($summary.RedirectRules -gt 0) { $ruleTypes["Redirect Rules"] = $summary.RedirectRules }
	if ($summary.SoftDeleteRules -gt 0) { $ruleTypes["Soft Delete Rules"] = $summary.SoftDeleteRules }
	if ($summary.DeleteRules -gt 0) { $ruleTypes["Delete Rules"] = $summary.DeleteRules }
	if ($summary.HasAttachmentRules -gt 0) { $ruleTypes["Has Attachment Rules"] = $summary.HasAttachmentRules }
	if ($summary.StopProcessingRules -gt 0) { $ruleTypes["Stop Processing Rules"] = $summary.StopProcessingRules }
	if ($summary.HighImportanceRules -gt 0) { $ruleTypes["High Importance Rules"] = $summary.HighImportanceRules }

	if ($ruleTypes.Count -gt 0) {
		$summaryOutput["Rule Types"] = $ruleTypes
	}

	Write-Summary -Summary $summaryOutput -Title "Mailbox Rules Summary"
}

function Get-MailboxRulesGraph
{
<#
    .SYNOPSIS
    Retrieves mailbox rules (Inbox Rules) for users using Microsoft Graph API.

    .DESCRIPTION
    Retrieves the mailbox rules for all users or specific users using the Graph API.
    The output identifies conditions (e.g., Subject contains) and actions (e.g., Forward to, Delete).
    
    .PARAMETER OutputDir
    OutputDir is the parameter specifying the output directory.
    Default: Output\Rules

    .PARAMETER Encoding
    Encoding is the parameter specifying the encoding of the CSV output file.
    Default: UTF8

    .PARAMETER LogLevel
    Specifies the level of logging:
    None, Minimal, Standard, Debug
    Default: Standard

    .PARAMETER UserIds
    UserId is the parameter specifying a single user ID or UPN to filter the results.
    Default: All users will be included if not specified.
    
    .EXAMPLE
    Get-MailboxRulesGraph
    Retrieves rules for all users.

    .EXAMPLE
    Get-MailboxRulesGraph -UserIds "HR@invictus-ir.com"
#>
    [CmdletBinding()]
    param(
        [string]$OutputDir,
        [string]$Encoding = "UTF8",
        [string]$UserIds,
        [ValidateSet('None', 'Minimal', 'Standard', 'Debug')]
        [string]$LogLevel = 'Standard'
    )

    Init-Logging
    Init-OutputDir -Component "Rules" -FilePostfix "MailboxRulesGraph" -CustomOutputDir $OutputDir

    $requiredScopes = @("User.Read.All", "MailboxSettings.Read")
    $graphAuth = Get-GraphAuthType -RequiredScopes $RequiredScopes
    
    Write-LogFile -Message "=== Starting Mailbox Rules Collection (Graph API) ===" -Color "Cyan" -Level Standard

    # Initialize Summary Trackers
    $summary = @{
        TotalUsers = 0
        UsersWithRules = 0
        TotalRules = 0
        EnabledRules = 0
        ForwardingRules = 0
        ForwardAsAttachmentRules = 0
        RedirectRules = 0
        DeleteRules = 0
        StopProcessingRules = 0
        Errors = 0
    }
    $results = [System.Collections.Generic.List[object]]::new()

    try {
        $usersToProcess = [System.Collections.Generic.List[object]]::new()

        if ($UserIds) {
            Write-LogFile -Message "[INFO] Filtering results for user: $UserIds" -Level Standard
            try {
                $userObj = Get-MgUser -UserId $UserIds -ErrorAction Stop
                $usersToProcess.Add($userObj)
            } catch {
                Write-LogFile -Message "[WARNING] User not found or error retrieving: $UserIds - $($_.Exception.Message)" -Color "Yellow" -Level debug
            }
        } else {
            Write-LogFile -Message "[INFO] Retrieving all users from tenant..." -Level Standard
			
            $allUsers = Get-MgUser -All -Property Id, UserPrincipalName, Mail, UserType
                $usersToProcess = $allUsers | Where-Object {
                    (-not [string]::IsNullOrWhiteSpace($_.Mail)) -and 
                    ($_.UserType -ne 'Guest') -and 
                    ($_.UserPrincipalName -notmatch '^HealthMailbox') -and
                    ($_.UserPrincipalName -notmatch '^DiscoverySearchMailbox')
                }

            Write-LogFile -Message "[INFO] Found $($usersToProcess.Count) enabled users" -Level Standard
        }
        
        $summary.TotalUsers = $usersToProcess.Count

        foreach ($user in $usersToProcess) {
            $upn = $user.UserPrincipalName
            Write-LogFile -Message "[INFO] Checking rules for: $upn" -Level Standard
            
            try {
                $rules = $null
                $retryCount = 0
                $maxRetries = 3
                $completed = $false

                while (-not $completed -and $retryCount -lt $maxRetries) {
                    try {
                        if ($isDebugEnabled) {
                            $perf = Measure-Command {
                                $rules = Get-MgUserMailFolderMessageRule -UserId $user.Id -MailFolderId "inbox" -ErrorAction Stop
                            }
                            Write-LogFile -Message "[DEBUG]   API Call took $([math]::round($perf.TotalSeconds, 2))s" -Level Debug
                        } else {
                            $rules = Get-MgUserMailFolderMessageRule -UserId $user.Id -MailFolderId "inbox" -ErrorAction Stop
                        }
                        $completed = $true
                    }
                    catch {
                        $isThrottled = $false
                        $retryAfter  = $null

                        if ($_.Exception.Response -and $_.Exception.Response.StatusCode -eq 429) {
                            $isThrottled = $true
                            if ($_.Exception.Response.Headers -and $_.Exception.Response.Headers['Retry-After']) {
                                $retryAfter = [int]($_.Exception.Response.Headers['Retry-After'])
                            }
                        }
                        elseif ($_.Exception.Message -match 'TooManyRequests|throttl|429') {
                            $isThrottled = $true
                        }

                        if ($isThrottled) {
                            $retryCount++
                            $sleepTime = if ($retryAfter -and $retryAfter -gt 0) { $retryAfter } else { 5 * $retryCount }
                            Write-LogFile -Message "[WARNING] Throttled for user $upn. Retrying in $sleepTime seconds..." -Color "Yellow" -Level Standard
                            Start-Sleep -Seconds $sleepTime
                        } else {
                            throw $_
                        }
                    }
                }

                if ($rules) {
                    $summary.UsersWithRules++
                    $summary.TotalRules += @($rules).Count

                    if ($isDebugEnabled) {
                        Write-LogFile -Message "[DEBUG]   Found $($rules.Count) rules" -Level Debug
                    }

                    foreach ($rule in $rules) {
                        if ($rule.IsEnabled) { $summary.EnabledRules++ }
                        if ($rule.Actions.ForwardTo) { $summary.ForwardingRules++ }
                        if ($rule.Actions.ForwardAsAttachmentTo) { $summary.ForwardAsAttachmentRules++ }
                        if ($rule.Actions.RedirectTo) { $summary.RedirectRules++ }
                        if ($rule.Actions.Delete) { $summary.DeleteRules++ }
                        if ($rule.Actions.StopProcessingRules) { $summary.StopProcessingRules++ }
                        
                        $forwardTo = if ($rule.Actions.ForwardTo) { ($rule.Actions.ForwardTo.EmailAddress.Address -join "; ") } else { $null }
                        $redirectTo = if ($rule.Actions.RedirectTo) { ($rule.Actions.RedirectTo.EmailAddress.Address -join "; ") } else { $null }
                        $forwardAsAttach = if ($rule.Actions.ForwardAsAttachmentTo) { ($rule.Actions.ForwardAsAttachmentTo.EmailAddress.Address -join "; ") } else { $null }
                        $moveTo = if ($rule.Actions.MoveToFolder) { "FolderID: $($rule.Actions.MoveToFolder)" } else { $null }
                        
                        $fromAddresses = if ($rule.Conditions.SenderContains) { ($rule.Conditions.SenderContains -join "; ") } else { $null }
                        $subjectContains = if ($rule.Conditions.SubjectContains) { ($rule.Conditions.SubjectContains -join "; ") } else { $null }
                        $bodyContains = if ($rule.Conditions.BodyContains) { ($rule.Conditions.BodyContains -join "; ") } else { $null }

                        $results.Add([PSCustomObject]@{
                            UserPrincipalName      = $upn
                            RuleName               = $rule.DisplayName
                            Sequence               = $rule.Sequence
                            Enabled                = $rule.IsEnabled
                            # Actions
                            ForwardTo              = $forwardTo
                            RedirectTo             = $redirectTo
                            ForwardAsAttachment    = $forwardAsAttach
                            Delete                 = $rule.Actions.Delete
                            PermanentDelete        = $rule.Actions.PermanentDelete
                            MoveToFolder           = $moveTo
                            StopProcessingRules    = $rule.Actions.StopProcessingRules
                            MarkAsRead             = $rule.Actions.MarkAsRead
                            # Conditions
                            From                   = $fromAddresses
                            SubjectContains        = $subjectContains
                            BodyContains           = $bodyContains
                            HasAttachments         = $rule.Conditions.HasAttachments
                            IsImportant            = $rule.Conditions.Importance
                            RuleId                 = $rule.Id
                        })
                    }
                }
            }
            catch {
                Write-LogFile -Message "[WARNING] Failed to retrieve rules for $upn`: $($_.Exception.Message)" -Color "Yellow" -Level Standard
                $summary.Errors++
            }
        }

        if ($results.Count -gt 0) {
            $results | Export-Csv -Path $script:outputFile -NoTypeInformation -Encoding $Encoding
        }

        $summaryOutput = [ordered]@{
            "Collection Statistics" = [ordered]@{
                "Total Users Scanned" = $summary.TotalUsers
                "Users with Rules"    = $summary.UsersWithRules
                "Total Rules Found"   = $summary.TotalRules
                "Errors"              = $summary.Errors
            }
            "Rule Types" = [ordered]@{
                "Enabled Rules"                  = $summary.EnabledRules
                "Forwarding Rules"               = $summary.ForwardingRules
                "Forward As Attachment Rules"    = $summary.ForwardAsAttachmentRules
                "Redirect Rules"                 = $summary.RedirectRules
                "Delete Rules"                   = $summary.DeleteRules
                "Stop Processing Rules"          = $summary.StopProcessingRules
            }
        }

        Write-Summary -Summary $summaryOutput -Title "Mailbox Rules (Graph) Summary"

    }
    catch {
        Write-LogFile -Message "[ERROR] Fatal error in Main Block: $($_.Exception.Message)" -Color "Red" -Level Minimal
        throw
    }
}