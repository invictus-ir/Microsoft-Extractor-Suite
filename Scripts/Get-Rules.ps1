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
	$transportRules = Get-TransportRule | Select-Object -Property Name,Description,CreatedBy,WhenChanged,State
	
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
    Default: Standard
    
    .Example
    Get-TransportRules
#>

	[CmdletBinding()]
	param (
		[string]$OutputDir = "Output\Rules"	,
		[string]$Encoding = "UTF8",
        [ValidateSet('None', 'Minimal', 'Standard')]
        [string]$LogLevel = 'Standard'
	)

	Set-LogLevel -Level ([LogLevel]::$LogLevel)
    Write-LogFile -Message "=== Starting Transport Rules Collection ===" -Color "Cyan" -Level Minimal

	if (!(test-path $OutputDir)) {
		New-Item -ItemType Directory -Force -Path $OutputDir > $null
	}
	else {
        if (!(Test-Path -Path $OutputDir)) {
            Write-Error "[Error] Custom directory invalid: $OutputDir exiting script" -ErrorAction Stop
            Write-LogFile -Message "[Error] Custom directory invalid: $OutputDir exiting script" -Level Minimal
        }
    }
    
	$filename = "$($date)-TransportRules.csv"
	$outputDirectory = Join-Path $OutputDir $filename		
	$transportRules = Get-TransportRule | Select-Object -Property Name,Description,CreatedBy,WhenChanged,State, Priority, Mode

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

	$summary = @{
		TotalRules = $transportRules.Count
		EnabledRules = $enabledCount
		DisabledRules = $disabledCount
	}

	$transportRules | Export-Csv -Path $outputDirectory -NoTypeInformation -Encoding $Encoding

	Write-LogFile -Message "`nTransport Rules Summary:" -Color "Cyan" -Level Standard
    Write-LogFile -Message "Total Rules: $($summary.TotalRules)" -Level Standard
    Write-LogFile -Message "  - Enabled: $($summary.EnabledRules)" -Level Standard
    Write-LogFile -Message "  - Disabled: $($summary.DisabledRules)" -Level Standard
    
    Write-LogFile -Message "`nExported File:" -Level Standard
    Write-LogFile -Message "  - $outputDirectory" -Level Standard
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
		[string]$UserIds,
		[string]$OutputDir = "Output\Rules",
		[string]$Encoding = "UTF8",
        [ValidateSet('None', 'Minimal', 'Standard')]
        [string]$LogLevel = 'Standard'
	)

	Set-LogLevel -Level ([LogLevel]::$LogLevel)
    Write-LogFile -Message "=== Starting Mailbox Rules Collection ===" -Color "Cyan" -Level Minimal
	
	if (!(test-path $OutputDir)) {
		New-Item -ItemType Directory -Force -Path $OutputDir > $null
	}
	else {
        if (!(Test-Path -Path $OutputDir)) {
            Write-Error "[Error] Custom directory invalid: $OutputDir exiting script" -ErrorAction Stop
            Write-LogFile -Message "[Error] Custom directory invalid: $OutputDir exiting script" -Level Minimal
        }
    }
    
	$date = [datetime]::Now.ToString('yyyyMMddHHmmss')
    $outputPath = Join-Path $OutputDir "$($date)-MailboxRules.csv"

	$summary = @{
		TotalUsers = 0
		UsersWithRules = 0
		TotalRules = 0
		EnabledRules = 0
		ForwardingRules = 0
		RedirectRules = 0
	}
	
	if ($UserIds -eq "") {		
		$mailboxes = Get-Mailbox -ResultSize Unlimited
        $summary.TotalUsers = $mailboxes.Count

		foreach ($mailbox in $mailboxes) {
			Write-LogFile -Message "[INFO] Checking rules for: $($mailbox.UserPrincipalName)" -Level Standard
            $rules = Get-InboxRule -Mailbox $mailbox.UserPrincipalName
			
			if ($rules) {
				$summary.UsersWithRules++
				foreach ($rule in $rules) {
					$summary.TotalRules++
					if ($rule.Enabled) { $summary.EnabledRules++ }
					if ($rule.ForwardTo) { $summary.ForwardingRules++ }
					if ($rule.RedirectTo) { $summary.RedirectRules++ }

					[PSCustomObject]@{
						UserName = $mailbox.UserPrincipalName
						RuleName = $rule.Name
						Enabled = $rule.Enabled
						CopyToFolder = $rule.CopyToFolder
						MoveToFolder = $rule.MoveToFolder
						RedirectTo = $rule.RedirectTo
						ForwardTo = $rule.ForwardTo
						Description = $rule.Description
					} | Export-Csv -Path $outputPath -Append -NoTypeInformation -Encoding $Encoding
				}
			}
		}
	}
	else {	
		$userList = $UserIds -split ','
        $summary.TotalUsers = $userList.Count

		foreach ($user in $userList) {
			Write-LogFile -Message "[INFO] Checking rules for: $user" -Level Standard
			$rules = Get-InboxRule -Mailbox $user.Trim()
			
			if ($rules) {
				$summary.UsersWithRules++
				foreach ($rule in $rules) {
					$summary.TotalRules++
					if ($rule.Enabled) { $summary.EnabledRules++ }
					if ($rule.ForwardTo) { $summary.ForwardingRules++ }
					if ($rule.RedirectTo) { $summary.RedirectRules++ }

					[PSCustomObject]@{
						UserName = $user
						RuleName = $rule.Name
						Enabled = $rule.Enabled
						CopyToFolder = $rule.CopyToFolder
						MoveToFolder = $rule.MoveToFolder
						RedirectTo = $rule.RedirectTo
						ForwardTo = $rule.ForwardTo
						Description = $rule.Description
					} | Export-Csv -Path $outputPath -Append -NoTypeInformation -Encoding $Encoding
				}
			}
		}
	}

	Write-LogFile -Message "`nMailbox Rules Summary:" -Color "Cyan" -Level Standard
    Write-LogFile -Message "Users Processed: $($summary.TotalUsers)" -Level Standard
    Write-LogFile -Message "Users with Rules: $($summary.UsersWithRules)" -Level Standard
    Write-LogFile -Message "Total Rules Found: $($summary.TotalRules)" -Level Standard
    Write-LogFile -Message "  - Enabled Rules: $($summary.EnabledRules)" -Level Standard
	if ($summary.ForwardingRules -ne 0) {
        Write-LogFile -Message "  - Forwarding Rules: $($summary.ForwardingRules)" -Level Standard
    }

    if ($summary.RedirectRules -ne 0) {
        Write-LogFile -Message "  - Redirect Rules: $($summary.RedirectRules)" -Level Standard
    }
    Write-LogFile -Message "`nExported File:" -Level Standard
    Write-LogFile -Message "  - $outputPath" -Level Standard
}
