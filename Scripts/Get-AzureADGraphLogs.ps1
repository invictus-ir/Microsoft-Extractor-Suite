function Get-GraphEntraSignInLogs {
    <#
    .SYNOPSIS
    Gets of sign-ins logs.

    .DESCRIPTION
    The Get-GraphEntraSignInLogs GraphAPI cmdlet collects the contents of the Azure Active Directory sign-in logs.

    .PARAMETER startDate
	The startDate parameter specifies the date from which all logs need to be collected.

	.PARAMETER endDate
    The Before parameter specifies the date endDate which all logs need to be collected.

	.PARAMETER MergeOutput
	MergeOutput is the parameter specifying if you wish to merge outputs to a single file
	Default: No

	.PARAMETER Output
    Output is the parameter specifying the JSON or SOF-ELK output type. The SOF-ELK output can be imported into the platform of the same name.
	Default: JSON

	.PARAMETER LogLevel
    Specifies the level of logging:
    None: No logging
    Minimal: Critical errors only
    Standard: Normal operational logging
    Default: Standard

    .PARAMETER OutputDir
    outputDir is the parameter specifying the output directory.
    Default: The output will be written to: Output\EntraID\{date_SignInLogs}\SignInLogs.json

    .PARAMETER Encoding
    Encoding is the parameter specifying the encoding of the JSON output file.
    Default: UTF8

    .PARAMETER UserIds
    UserIds is the UserIds parameter filtering the log entries by the account of the user who performed the actions.

    .EXAMPLE
    Get-GraphEntraSignInLogs
    Get all audit logs of sign-ins.

    .EXAMPLE
    Get-GraphEntraSignInLogs -Application
    Get all audit logs of sign-ins via application authentication.

    .EXAMPLE
    Get-GraphEntraSignInLogs -endDate 2024-04-12
    Get audit logs before 2024-04-12.

    .EXAMPLE
    Get-GraphEntraSignInLogs -startDate 2024-04-12
    Get audit logs after 2024-04-12.

	.EXAMPLE
    Get-GraphEntraSignInLogs -Output SOF-ELK -MergeOutput
    Get the Azure Active Directory SignIn Log in a format compatible with the SOF-ELK platform and merge all data into a single file.
#>
    [CmdletBinding()]
    param(
        [string]$startDate,
		[string]$endDate,
		[string]$Output = "JSON",
        [string]$OutputDir,
        [string]$UserIds,
		[switch]$MergeOutput,
        [string]$Encoding = "UTF8",
        [ValidateSet('None', 'Minimal', 'Standard')]
        [string]$LogLevel = 'Standard'
	)

	Set-LogLevel -Level ([LogLevel]::$LogLevel)
    $summary = @{
        TotalRecords = 0
        StartTime = Get-Date
        ProcessingTime = $null
        TotalFiles = 0
    }

	Write-LogFile -Message "=== Starting Sign-in Log Collection ===" -Color "Cyan" -Level Minimal
	$requiredScopes = @("AuditLog.Read.All", "Directory.Read.All")
    $graphAuth = Get-GraphAuthType -RequiredScopes $RequiredScopes

	$date = [datetime]::Now.ToString('yyyyMMdd') 
	if ($OutputDir -eq "" ){
		$OutputDir = "Output\EntraID\$($date)-SignInLogs"
		if (!(test-path $OutputDir)) {
			New-Item -ItemType Directory -Force -path $OutputDir > $null
		}
	}
	else {
        if (!(Test-Path -Path $OutputDir)) {
            Write-LogFile -Message "[Error] Custom directory invalid: $OutputDir" -Level Minimal -Color "Red"
            return
        }
    }

	StartDateAz -Quiet
    EndDate -Quiet

	$StartDate = $script:StartDate.ToString('yyyy-MM-ddTHH:mm:ssZ')
    $EndDate = $script:EndDate.ToString('yyyy-MM-ddTHH:mm:ssZ')

	Write-LogFile -Message "Start Date: $StartDate" -Level Standard
    Write-LogFile -Message "End Date: $EndDate" -Level Standard
    Write-LogFile -Message "Output Format: $Output" -Level Standard
    Write-LogFile -Message "Output Directory: $OutputDir" -Level Standard
    if ($UserIds) {
        Write-LogFile -Message "Filtering for User: $UserIds" -Level Standard
    }
    Write-LogFile -Message "----------------------------------------`n" -Level Standard

	$filterQuery = "createdDateTime ge $StartDate and createdDateTime le $EndDate"
	if ($UserIds) {
		$filterQuery += " and startsWith(userPrincipalName, '$UserIds')"
	}

    $encodedFilterQuery = [System.Web.HttpUtility]::UrlEncode($filterQuery)
    $apiUrl = "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=$encodedFilterQuery"

	try {
        Do {
			$retryCount = 0
            $maxRetries = 3
            $success = $false

			while (-not $success -and $retryCount -lt $maxRetries) {
                try {
					$response = Invoke-MgGraphRequest -Uri $apiUrl -Method Get -ContentType "application/json; odata.metadata=minimal; odata.streaming=true;" -OutputType Json
					$responseJson = $response | ConvertFrom-Json 
					$success = $true
				}
				catch {
                    $retryCount++
                    if ($retryCount -lt $maxRetries) {
                        Write-LogFile -Message "[WARNING] Failed to acquire logs. Retrying... Attempt $retryCount of $maxRetries" -Level Standard -Color "Yellow"
                        Start-Sleep -Seconds 15
                    }
                    else {
                        Write-LogFile -Message "[ERROR] Failed to acquire logs after $maxRetries attempts. Error: $($_.Exception.Message)" -Level Minimal -Color "Red"
                        throw
                    }
                }
			}
           
			if ($responseJson.value) {
				$date = [datetime]::Now.ToString('yyyyMMddHHmmss') 
				$filePath = Join-Path -Path $OutputDir -ChildPath "$($date)-SignInLogs.json"

				if ($Output -eq "JSON" ) {
					$responseJson.value | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath -Append -Encoding $Encoding	
				} 
				elseif ($Output -eq "SOF-ELK"){
					# UTF8 is fixed, as it is required by SOF-ELK
					foreach ($item in $responseJson.value) {
						$item | ConvertTo-Json -Depth 100 -Compress | Out-File -FilePath $filePath -Append -Encoding UTF8	
					}
				}

				$currentBatchCount = ($responseJson.value | Measure-Object).Count
				$summary.TotalRecords += $currentBatchCount
				$summary.TotalFiles++

				$dates = $responseJson.value | ForEach-Object {
					[DateTime]::Parse($_.CreatedDateTime, [System.Globalization.CultureInfo]::InvariantCulture)
				} | Sort-Object
				
				$from =  $dates | Select-Object -First 1
				$to = ($dates | Select-Object -Last 1)
				Write-LogFile -Message "[INFO] Retrieved $currentBatchCount records between $from and $to" -Level Standard -Color "Green"
			}
			$apiUrl = $responseJson.'@odata.nextLink'
		} While ($apiUrl)
		
		if ($Output -eq "JSON" -and ($MergeOutput.IsPresent)) {
			Write-LogFile -Message "[INFO] Merging output files into one file"
			Merge-OutputFiles -OutputDir $OutputDir -OutputType "JSON" -MergedFileName "SignInLogs-Combined.json"
		}

		elseif ($Output -eq "SOF-ELK" -and ($MergeOutput.IsPresent)) {
			Write-LogFile -Message "[INFO] Merging output files into one file"
			Merge-OutputFiles -OutputDir $OutputDir -OutputType "SOF-ELK" -MergedFileName "SignInLogs-Combined.json"
		}

		$summary.ProcessingTime = (Get-Date) - $summary.StartTime
		Write-LogFile -Message "`nCollection Summary:" -Color "Cyan" -Level Standard
		Write-LogFile -Message "  Total Records: $($summary.TotalRecords)" -Level Standard
		Write-LogFile -Message "  Files Created: $($summary.TotalFiles)" -Level Standard
		Write-LogFile -Message "  Output Directory: $OutputDir" -Level Standard
		Write-LogFile -Message "  Processing Time: $($summary.ProcessingTime.ToString('mm\:ss'))" -Level Standard -Color "Green"
	}
	
	catch {
		Write-LogFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Level Minimal -Color "Red"
		throw
	}
}

function Get-GraphEntraAuditLogs {
	<#
	.SYNOPSIS
	Get directory audit logs.

	.DESCRIPTION
	The Get-GraphEntraAuditLogs GraphAPI cmdlet to collect the contents of the Azure Active Directory Audit logs.

	.PARAMETER startDate
	The startDate parameter specifies the date from which all logs need to be collected.

	.PARAMETER endDate
    The Before parameter specifies the date endDate which all logs need to be collected.

	.PARAMETER OutputDir
	outputDir is the parameter specifying the output directory.
	Default: The output will be written to: "Output\EntraID\{date_AuditLogs}\Auditlogs.json

	.PARAMETER UserIds
	UserIds is the UserIds parameter filtering the log entries by the account of the user who performed the actions.

	.PARAMETER All
    When specified along with UserIds, this parameter filters the results to include events where the provided UserIds match any user principal name found in either the userPrincipalNames or targetResources fields.

	.PARAMETER Encoding
	Encoding is the parameter specifying the encoding of the JSON output file.
	Default: UTF8

	.PARAMETER MergeOutput
	MergeOutput is the parameter specifying if you wish to merge outputs to a single file
	Default: No

	.PARAMETER Output
    Output is the parameter specifying the JSON or SOF-ELK output type. The SOF-ELK output can be imported into the platform of the same name.
	Default: JSON

	.EXAMPLE
	Get-GraphEntraAuditLogs
	Get directory audit logs.

	.EXAMPLE
	Get-GraphEntraAuditLogs -Application
	Get directory audit logs via application authentication.

	.PARAMETER LogLevel
    Specifies the level of logging:
    None: No logging
    Minimal: Critical errors only
    Standard: Normal operational logging
    Default: Standard

	.EXAMPLE
    Get-GraphEntraAuditLogs -UserIds 'user@example.com' -All
    Get sign-in logs for 'user@example.com', including both userPrincipalName and targetResources in the filter.

	.EXAMPLE
	Get-GraphEntraAuditLogs -Before 2024-04-12
	Get directory audit logs before 2024-04-12.

	.EXAMPLE
	Get-GraphEntraAuditLogs -After 2024-04-12
	Get directory audit logs after 2024-04-12.
	#>
	[CmdletBinding()]
	param(
		[string]$startDate,
		[string]$endDate,
		[string]$OutputDir,
		[string]$Output = "JSON",
		[string]$Encoding = "UTF8",
		[switch]$MergeOutput,
		[string]$UserIds,
        [switch]$All,
        [ValidateSet('None', 'Minimal', 'Standard')]
        [string]$LogLevel = 'Standard'
	)

	Set-LogLevel -Level ([LogLevel]::$LogLevel)
    $summary = @{
        TotalRecords = 0
        StartTime = Get-Date
        ProcessingTime = $null
        TotalFiles = 0
    }

    Write-LogFile -Message "=== Starting Sign-in Log Collection ===" -Color "Cyan" -Level Minimal
    $requiredScopes = @("AuditLog.Read.All", "Directory.Read.All")
    $graphAuth = Get-GraphAuthType -RequiredScopes $RequiredScopes
	
	$date = [datetime]::Now.ToString('yyyyMMdd') 
	if ($OutputDir -eq "" ){
		$OutputDir = "Output\EntraID\$($date)-Auditlogs"
		if (!(test-path $OutputDir)) {
			New-Item -ItemType Directory -Force -Name $OutputDir > $null
			write-logFile -Message "[INFO] Creating the following directory: $OutputDir"
		}
	}
	else {
        if (!(Test-Path -Path $OutputDir)) {
            Write-LogFile -Message "[Error] Custom directory invalid: $OutputDir" -Level Minimal -Color "Red"
            return
        }
    }

	StartDateAz -Quiet
    EndDate -Quiet

	$StartDate = $script:StartDate.ToString('yyyy-MM-ddTHH:mm:ssZ')
	$EndDate = $script:EndDate.ToString('yyyy-MM-ddTHH:mm:ssZ')

	Write-LogFile -Message "Start Date: $StartDate" -Level Standard
    Write-LogFile -Message "End Date: $EndDate" -Level Standard
    Write-LogFile -Message "Output Format: $Output" -Level Standard
    Write-LogFile -Message "Output Directory: $OutputDir" -Level Standard
    if ($UserIds) {
        Write-LogFile -Message "Filtering for User: $UserIds" -Level Standard
    }
    Write-LogFile -Message "----------------------------------------`n" -Level Standard

	$filterQuery = "activityDateTime ge $StartDate and activityDateTime le $EndDate"
	if ($UserIds) {
		$filterQuery += " and startsWith(initiatedBy/user/userPrincipalName, '$UserIds')"

		if ($All.IsPresent) {
            $filterQuery = "($filterQuery) or (targetResources/any(tr: tr/userPrincipalName eq '$UserIds'))"
        }
	}
	else {
        if ($All.IsPresent) {
            Write-LogFile -Message "[WARNING] '-All' switch has no effect without specifying UserIds"
        }
    }

	$encodedFilterQuery = [System.Web.HttpUtility]::UrlEncode($filterQuery)
	$apiUrl = "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?`$filter=$encodedFilterQuery"

	try {
		Do {
			$retryCount = 0
            $maxRetries = 3
            $success = $false

			while (-not $success -and $retryCount -lt $maxRetries) {
				try { 
					$response = Invoke-MgGraphRequest -Uri $apiUrl -Method Get -ContentType "application/json; odata.metadata=minimal; odata.streaming=true;" -OutputType Json
					$responseJson = $response | ConvertFrom-Json 
					$success = $true
				}
				catch {
					$retryCount++
					if ($retryCount -lt $maxRetries) {
						Write-LogFile -Message "[WARNING] Failed to acquire logs. Retrying... Attempt $retryCount of $maxRetries" -Level Standard -Color "Yellow"
						Start-Sleep -Seconds 15
					}
					else {
						Write-LogFile -Message "[ERROR] Failed to acquire logs after $maxRetries attempts. Error: $($_.Exception.Message)" -Level Minimal -Color "Red"
						throw
					}
				}
			}

			if ($responseJson.value) {
				$date = [datetime]::Now.ToString('yyyyMMddHHmmss') 
				$filePath = Join-Path -Path $OutputDir -ChildPath "$($date)-AuditLogs.json"

				if ($Output -eq "JSON") {
                    $responseJson.value | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath -Append -Encoding $Encoding
                }
                elseif ($Output -eq "SOF-ELK") {
                    # UTF8 is fixed, as it is required by SOF-ELK
                    foreach ($item in $responseJson.value) {
                        $item | ConvertTo-Json -Depth 100 -Compress | Out-File -FilePath $filePath -Append -Encoding UTF8
                    }
                }

				$currentBatchCount = ($responseJson.value | Measure-Object).Count
                $summary.TotalRecords += $currentBatchCount
                $summary.TotalFiles++
				
				$dates = $responseJson.value | ForEach-Object {
					[DateTime]::Parse($_.activityDateTime, [System.Globalization.CultureInfo]::InvariantCulture)
				} | Sort-Object

                $from =  $dates | Select-Object -First 1
                $fromstr =  $from.ToString('yyyy-MM-ddTHH:mmZ')
                $to = ($dates | Select-Object -Last 1).ToString('yyyy-MM-ddTHH:mmZ')
				Write-LogFile -Message "[INFO] Retrieved $currentBatchCount records between $fromstr and $to" -Level Standard -Color "Green"
			}
			$apiUrl = $responseJson.'@odata.nextLink'
		} While ($apiUrl)

		if ($Output -eq "JSON" -and ($MergeOutput.IsPresent)) {
			Merge-OutputFiles -OutputDir $OutputDir -OutputType "JSON" -MergedFileName "AuditLogs-Combined.json"
		}
		elseif ($Output -eq "SOF-ELK" -and ($MergeOutput.IsPresent)) {
			Merge-OutputFiles -OutputDir $OutputDir -OutputType "SOF-ELK" -MergedFileName "AuditLogs-Combined.json"
		}

		$summary.ProcessingTime = (Get-Date) - $summary.StartTime
        Write-LogFile -Message "`nCollection Summary:" -Color "Cyan" -Level Standard
        Write-LogFile -Message "  Total Records: $($summary.TotalRecords)" -Level Standard
        Write-LogFile -Message "  Files Created: $($summary.TotalFiles)" -Level Standard
        Write-LogFile -Message "  Output Directory: $OutputDir" -Level Standard
        Write-LogFile -Message "  Processing Time: $($summary.ProcessingTime.ToString('mm\:ss'))" -Level Standard -Color "Green"
    }
	catch {
		Write-logFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Color "Red" -Level Minimal
		throw
    }
}
	
