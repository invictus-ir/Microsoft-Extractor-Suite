function Get-ADSignInLogsGraph {
    <#
    .SYNOPSIS
    Gets of sign-ins logs.

    .DESCRIPTION
    The Get-ADSignInLogsGraph GraphAPI cmdlet collects the contents of the Azure Active Directory sign-in logs.

    .PARAMETER startDate
	The startDate parameter specifies the date from which all logs need to be collected.

	.PARAMETER endDate
    The Before parameter specifies the date endDate which all logs need to be collected.

    .PARAMETER OutputDir
    outputDir is the parameter specifying the output directory.
    Default: The output will be written to: Output\AzureAD\{date_SignInLogs}\SignInLogs.json

    .PARAMETER Encoding
    Encoding is the parameter specifying the encoding of the JSON output file.
    Default: UTF8

    .PARAMETER UserIds
    UserIds is the UserIds parameter filtering the log entries by the account of the user who performed the actions.

    .EXAMPLE
    Get-ADSignInLogsGraph
    Get all audit logs of sign-ins.

    .EXAMPLE
    Get-ADSignInLogsGraph -Application
    Get all audit logs of sign-ins via application authentication.

    .EXAMPLE
    Get-ADSignInLogsGraph -endDate 2023-04-12
    Get audit logs before 2023-04-12.

    .EXAMPLE
    Get-ADSignInLogsGraph -startDate 2023-04-12
    Get audit logs after 2023-04-12.
#>
    [CmdletBinding()]
    param(
        [string]$startDate,
		[string]$endDate,
        [string]$OutputDir,
        [string]$UserIds,
        [string]$Encoding = "UTF8"
	)

	$authType = Get-GraphAuthType
	if ($authType -eq "Delegated") {
		Connect-MgGraph -Scopes AuditLog.Read.All, Directory.Read.All > $null
	}

	write-logFile -Message "[INFO] Running Get-ADSignInLogsGraph" -Color "Green"

	$date = [datetime]::Now.ToString('yyyyMMdd') 
	if ($OutputDir -eq "" ){
		$OutputDir = "Output\AzureAD\$($date)-SignInLogs"
		if (!(test-path $OutputDir)) {
			write-logFile -Message "[INFO] Creating the following output directory: $OutputDir"
			New-Item -ItemType Directory -Force -Name $OutputDir > $null
		}
	}
	else {
		if (Test-Path -Path $OutputDir) {
			write-LogFile -Message "[INFO] Custom directory set to: $OutputDir"
		}
		else {
			write-Error "[Error] Custom directory invalid: $OutputDir exiting script" -ErrorAction Stop
			write-LogFile -Message "[Error] Custom directory invalid: $OutputDir exiting script"
		}
	}

	StartDate
	EndDate

	$StartDate = $script:StartDate.ToString('yyyy-MM-ddTHH:mm:ssZ')
    $EndDate = $script:EndDate.ToString('yyyy-MM-ddTHH:mm:ssZ')

	$filterQuery = "createdDateTime ge $StartDate and createdDateTime le $EndDate"
	if ($UserIds) {
		$filterQuery += " and startsWith(userPrincipalName, '$UserIds')"
	}

    $encodedFilterQuery = [System.Web.HttpUtility]::UrlEncode($filterQuery)
    $apiUrl = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=$encodedFilterQuery"

	try {
        Do {
            $response = Invoke-MgGraphRequest -Method Get -Uri $apiUrl -ContentType 'application/json'
            if ($response.value) {
				$date = [datetime]::Now.ToString('yyyyMMddHHmmss') 
                $filePath = Join-Path -Path $OutputDir -ChildPath "$($date)-SignInLogsGraph.json"
                $response.value | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath -Append -Encoding $Encoding
                Write-LogFile -Message "[INFO] Sign-in logs written to $filePath" -ForegroundColor Green
            } else {
                Write-LogFile -Message "[INFO] No data to write for current batch."
            }
            $apiUrl = $response.'@odata.nextLink'
        } While ($apiUrl)
    }
    catch {
		write-logFile -Message "[INFO] Ensure you are connected to Microsoft Graph by running the Connect-MgGraph command before executing this script" -Color "Yellow"
        Write-logFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Color "Red"
    }
	Write-LogFile -Message "[INFO] Acquisition complete, check the $($OutputDir) directory for your files.." -Color "Green"		
}

function Get-ADAuditLogsGraph {
	<#
	.SYNOPSIS
	Get directory audit logs.

	.DESCRIPTION
	The Get-ADAuditLogsGraph GraphAPI cmdlet to collect the contents of the Azure Active Directory Audit logs.

	.PARAMETER startDate
	The startDate parameter specifies the date from which all logs need to be collected.

	.PARAMETER endDate
    The Before parameter specifies the date endDate which all logs need to be collected.

	.PARAMETER OutputDir
	outputDir is the parameter specifying the output directory.
	Default: The output will be written to: "Output\AzureAD\{date_AuditLogs}\Auditlogs.json

	.PARAMETER UserIds
	UserIds is the UserIds parameter filtering the log entries by the account of the user who performed the actions.

	.PARAMETER Encoding
	Encoding is the parameter specifying the encoding of the JSON output file.
	Default: UTF8
	
	.EXAMPLE
	Get-ADAuditLogsGraph
	Get directory audit logs.

	.EXAMPLE
	Get-ADAuditLogsGraph -Application
	Get directory audit logs via application authentication.

	.EXAMPLE
	Get-ADAuditLogsGraph -Before 2023-04-12
	Get directory audit logs before 2023-04-12.

	.EXAMPLE
	Get-ADAuditLogsGraph -After 2023-04-12
	Get directory audit logs after 2023-04-12.
	#>
	[CmdletBinding()]
	param(
		[string]$startDate,
		[string]$endDate,
		[string]$OutputDir,
		[string]$Encoding = "UTF8",
		[string]$UserIds
	)

	$authType = Get-GraphAuthType
	if ($authType -eq "Delegated") {
		Connect-MgGraph -Scopes AuditLog.Read.All, Directory.Read.All > $null
	}

	Write-logFile -Message "[INFO] Running Get-ADAuditLogsGraph" -Color "Green"
	
	$date = [datetime]::Now.ToString('yyyyMMdd') 
	if ($OutputDir -eq "" ){
		$OutputDir = "Output\AzureAD\$($date)-Auditlogs"
		if (!(test-path $OutputDir)) {
			New-Item -ItemType Directory -Force -Name $OutputDir > $null
			write-logFile -Message "[INFO] Creating the following directory: $OutputDir"
		}
	}
	else {
		if (Test-Path -Path $OutputDir) {
			write-LogFile -Message "[INFO] Custom directory set to: $OutputDir"
		}
		else {
			write-Error "[Error] Custom directory invalid: $OutputDir exiting script" -ErrorAction Stop
			write-LogFile -Message "[Error] Custom directory invalid: $OutputDir exiting script"
		}
	}

	StartDateAz
	EndDate

	$StartDate = $script:StartDate.ToString('yyyy-MM-ddTHH:mm:ssZ')
	$EndDate = $script:EndDate.ToString('yyyy-MM-ddTHH:mm:ssZ')

	$filterQuery = "activityDateTime ge $StartDate and activityDateTime le $EndDate"
	if ($UserIds) {
		$filterQuery += " and startsWith(initiatedBy/user/userPrincipalName, '$UserIds')"
	}

	$encodedFilterQuery = [System.Web.HttpUtility]::UrlEncode($filterQuery)
	$apiUrl = "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?`$filter=$encodedFilterQuery"

	try {
		Do {
			$response = Invoke-MgGraphRequest -Method Get -Uri $apiUrl -ContentType 'application/json'
			if ($response.value) {
				$date = [datetime]::Now.ToString('yyyyMMddHHmmss') 
				$filePath = Join-Path -Path $OutputDir -ChildPath "$($date)-AuditLogs.json"
				$response.value | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath -Append -Encoding $Encoding
				Write-LogFile -Message "[INFO] Audit logs written to $filePath" -ForegroundColor Green
			} else {
				Write-LogFile -Message "[INFO] No data to write for current batch."
			}
			$apiUrl = $response.'@odata.nextLink'
		} While ($apiUrl)
	}
	catch {
		write-logFile -Message "[INFO] Ensure you are connected to Microsoft Graph by running the Connect-MgGraph command before executing this script" -Color "Yellow"
		Write-logFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Color "Red"
    }	
	Write-LogFile -Message "[INFO] Acquisition complete, check the $($OutputDir) directory for your files.." -Color "Green"		
}
	
