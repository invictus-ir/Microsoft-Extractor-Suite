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
	
	.Parameter UserIds
    UserIds is the Identity parameter specifies the Inbox rule that you want to view.
    
    .Example
    Show-MailboxRules -UserIds "HR@invictus-ir.com,Test@Invictus-ir.com"
#>
	[CmdletBinding()]
	param(
		[string]$UserIds
	)
		
	$amountofRules = 0
	if ($UserIds -eq "") {		
		Get-mailbox -resultsize unlimited  |
		ForEach-Object {
			write-LogFile -Message "[INFO] Checking $($_.UserPrincipalName)..."
			
			$inboxrule = Get-inboxrule -Mailbox $_.UserPrincipalName  
			if ($inboxrule) {
				write-LogFile -Message "[INFO] Found InboxRule(s) for: $($_.UserPrincipalName)..." -Color "Green"
				foreach($rule in $inboxrule){
					$amountofRules = $amountofRules + 1
					write-LogFile -Message "Username: $($_.UserPrincipalName)" -Color "Yellow"
					write-LogFile -Message "RuleName: $($rule.name)" -Color "Yellow"
					write-LogFile -Message "RuleEnabled: $($rule.Enabled)" -Color "Yellow"
					write-LogFile -Message "CopytoFolder: $($rule.CopyToFolder)" -Color "Yellow"
					write-LogFile -Message "MovetoFolder: $($rule.MoveToFolder)" -Color "Yellow"
					write-LogFile -Message "RedirectTo $($rule.RedirectTo)" -Color "Yellow"
					write-LogFile -Message "ForwardTo: $($rule.ForwardTo)" -Color "Yellow"
					write-LogFile -Message "TextDescription: $($rule.Description)" -Color "Yellow"
					write-LogFile -Message "ForwardAsAttachmentTo: $($rule.ForwardAsAttachmentTo)" -Color "Yellow"
                    write-LogFile -Message "SoftDeleteMessage: $($rule.SoftDeleteMessage)" -Color "Yellow"
                    write-LogFile -Message "TextDescription: $($rule.Description)" -Color "Yellow"
				}
			}
		}
	}

	else {	
		if ($UserIds -match ",") {
			$UserIds.Split(",") | ForEach-Object {
				$user = $_
				Write-Output ('[INFO] Checking {0}...' -f $user)
				
				$inboxrule = get-inboxrule -Mailbox $user 
				if ($inboxrule) {
					write-LogFile -Message "[INFO] Found InboxRule(s) for: $UserIds..." -Color "Green"
					foreach($rule in $inboxrule){
						$amountofRules = $amountofRules + 1
						write-LogFile -Message "Username: $user" -Color "Yellow"
						write-LogFile -Message "RuleName: $($rule.name)" -Color "Yellow"
						write-LogFile -Message "RuleEnabled: $($rule.Enabled)" -Color "Yellow"
						write-LogFile -Message "CopytoFolder: $($rule.CopyToFolder)" -Color "Yellow"
						write-LogFile -Message "MovetoFolder: $($rule.MoveToFolder)" -Color "Yellow"
						write-LogFile -Message "RedirectTo $($rule.RedirectTo)" -Color "Yellow"
						write-LogFile -Message "ForwardTo: $($rule.ForwardTo)" -Color "Yellow"
						write-LogFile -Message "TextDescription: $($rule.Description)" -Color "Yellow"
						write-LogFile -Message "ForwardAsAttachmentTo: $($rule.ForwardAsAttachmentTo)" -Color "Yellow"
						write-LogFile -Message "SoftDeleteMessage: $($rule.SoftDeleteMessage)" -Color "Yellow"
						write-LogFile -Message "TextDescription: $($rule.Description)" -Color "Yellow"
					}
				}
			}
		}
				
		else {
			Write-Output ('[INFO] Checking {0}...' -f $UserIds)
			$inboxrule = get-inboxrule -Mailbox $UserIds 
			if ($inboxrule) {
				write-LogFile -Message "[INFO] Found InboxRule(s) for: $UserIds..." -Color "Green"
				foreach($rule in $inboxrule){
					$amountofRules = $amountofRules + 1
					write-LogFile -Message "Username: $UserIds" -Color "Yellow"
					write-LogFile -Message "RuleName: $($rule.name)" -Color "Yellow"
					write-LogFile -Message "RuleEnabled: $($rule.Enabled)" -Color "Yellow"
					write-LogFile -Message "CopytoFolder: $($rule.CopyToFolder)" -Color "Yellow"
					write-LogFile -Message "MovetoFolder: $($rule.MoveToFolder)" -Color "Yellow"
					write-LogFile -Message "RedirectTo $($rule.RedirectTo)" -Color "Yellow"
					write-LogFile -Message "ForwardTo: $($rule.ForwardTo)" -Color "Yellow"
					write-LogFile -Message "TextDescription: $($rule.Description)" -Color "Yellow"
					write-LogFile -Message "ForwardAsAttachmentTo: $($rule.ForwardAsAttachmentTo)" -Color "Yellow"
                    write-LogFile -Message "SoftDeleteMessage: $($rule.SoftDeleteMessage)" -Color "Yellow"
                    write-LogFile -Message "TextDescription: $($rule.Description)" -Color "Yellow"
				}
			}
		}
	}

	if ($amountofRules -gt 0) {
		write-LogFile -Message "[INFO] A total of $amountofRules Inbox Rules found" -Color "Green"
	}
	else {
		write-LogFile -Message "[INFO] No Inbox Rules found!" -Color "Yellow"
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

					[PSCustomObject]@{
						UserName = $mailbox.UserPrincipalName
                        RuleName = $rule.Name
                        Enabled = $rule.Enabled
                        Priority = $rule.Priority
                        RuleIdentity = $rule.RuleIdentity
                        StopProcessingRules = $rule.StopProcessingRules
                        CopyToFolder = $rule.CopyToFolder
                        MoveToFolder = $rule.MoveToFolder
                        RedirectTo = $rule.RedirectTo
                        ForwardTo = $rule.ForwardTo
                        ForwardAsAttachmentTo = $rule.ForwardAsAttachmentTo
                        ApplyCategory = ($rule.ApplyCategory -join ", ")
                        MarkImportance = $rule.MarkImportance
                        MarkAsRead = $rule.MarkAsRead
                        DeleteMessage = $rule.DeleteMessage
                        SoftDeleteMessage = $rule.SoftDeleteMessage
                        From = $rule.From
                        SubjectContainsWords = ($rule.SubjectContainsWords -join ", ")
                        SubjectOrBodyContainsWords = ($rule.SubjectOrBodyContainsWords -join ", ")
                        BodyContainsWords = ($rule.BodyContainsWords -join ", ")
                        HasAttachment = $rule.HasAttachment
                        Description = $rule.Description
                        InError = $rule.InError
                        ErrorType = $rule.ErrorType
					} | Export-Csv -Path $script:outputFile -Append -NoTypeInformation -Encoding $Encoding
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

					[PSCustomObject]@{
						UserName = $user
                        RuleName = $rule.Name
                        Enabled = $rule.Enabled
                        Priority = $rule.Priority
                        RuleIdentity = $rule.RuleIdentity
                        StopProcessingRules = $rule.StopProcessingRules
                        CopyToFolder = $rule.CopyToFolder
                        MoveToFolder = $rule.MoveToFolder
                        RedirectTo = $rule.RedirectTo
                        ForwardTo = $rule.ForwardTo
                        ForwardAsAttachmentTo = $rule.ForwardAsAttachmentTo
                        ApplyCategory = ($rule.ApplyCategory -join ", ")
                        MarkImportance = $rule.MarkImportance
                        MarkAsRead = $rule.MarkAsRead
                        DeleteMessage = $rule.DeleteMessage
                        SoftDeleteMessage = $rule.SoftDeleteMessage
                        From = $rule.From
                        SubjectContainsWords = ($rule.SubjectContainsWords -join ", ")
                        SubjectOrBodyContainsWords = ($rule.SubjectOrBodyContainsWords -join ", ")
                        BodyContainsWords = ($rule.BodyContainsWords -join ", ")
                        HasAttachment = $rule.HasAttachment
                        Description = $rule.Description
                        InError = $rule.InError
                        ErrorType = $rule.ErrorType
					} | Export-Csv -Path $script:outputFile -Append -NoTypeInformation -Encoding $Encoding
				}
			}
		}
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
