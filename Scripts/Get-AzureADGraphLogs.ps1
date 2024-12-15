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

	.PARAMETER MergeOutput
	MergeOutput is the parameter specifying if you wish to merge outputs to a single file
	Default: No

	.PARAMETER Output
    Output is the parameter specifying the JSON or SOF-ELK output type. The SOF-ELK output can be imported into the platform of the same name.
	Default: JSON

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

	.EXAMPLE
    Get-ADSignInLogsGraph -Output SOF-ELK -MergeOutput
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
        [string]$Encoding = "UTF8"
	)

	$requiredScopes = @("AuditLog.Read.All", "Directory.Read.All")
    $graphAuth = Get-GraphAuthType -RequiredScopes $RequiredScopes

	write-logFile -Message "[INFO] Running Get-ADSignInLogsGraph" -Color "Green"

	$date = [datetime]::Now.ToString('yyyyMMdd') 
	if ($OutputDir -eq "" ){
		$OutputDir = "Output\AzureAD\$($date)-SignInLogs"
		if (!(test-path $OutputDir)) {
			write-logFile -Message "[INFO] Creating the following output directory: $OutputDir"
			New-Item -ItemType Directory -Force -path $OutputDir > $null
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
    $apiUrl = "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=$encodedFilterQuery"

	try {
        Do {
			$response = Invoke-MgGraphRequest -Uri $apiUrl -Method Get -ContentType "application/json; odata.metadata=minimal; odata.streaming=true;" -OutputType Json
			$responseJson = $response | ConvertFrom-Json 
           
			if ($responseJson.value) {
				$date = [datetime]::Now.ToString('yyyyMMddHHmmss') 
                $filePath = Join-Path -Path $OutputDir -ChildPath "$($date)-SignInLogsGraph.json"
				if ($Output -eq "JSON" )
				{
					$responseJson.value | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath -Append -Encoding $Encoding	
				} 
				elseif ($Output -eq "SOF-ELK"){
					# UTF8 is fixed, as it is required by SOF-ELK
					foreach ($item in $responseJson.value) {
						$item | ConvertTo-Json -Depth 100 -Compress | Out-File -FilePath $filePath -Append -Encoding UTF8	
					}
				}
				#$dates = $responseJson.value | ForEach-Object { [DateTime]::Parse($_.CreatedDateTime) } | Sort-Object

				$dates = $responseJson.value | ForEach-Object {
					[DateTime]::Parse($_.CreatedDateTime, [System.Globalization.CultureInfo]::InvariantCulture)
				} | Sort-Object
				
                $from =  $dates | Select-Object -First 1
               # $fromstr =  $from.ToString('yyyy-MM-ddTHH:mmZ')
                $to = ($dates | Select-Object -Last 1) #.ToString('yyyy-MM-ddTHH:mmZ')
                $count = ($responseJson.value | measure).Count
                Write-LogFile -Message "[INFO] Sign-in logs written to $filePath ($count records between $from and $to)" -Color Green
            }
            $apiUrl = $responseJson.'@odata.nextLink'
        } While ($apiUrl)
    }
    catch {
        Write-logFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Color "Red"
    }

	if ($Output -eq "JSON" -and ($MergeOutput.IsPresent)) {
		Write-LogFile -Message "[INFO] Merging output files into one file"
		Merge-OutputFiles -OutputDir $OutputDir -OutputType "JSON" -MergedFileName "SignInLogs-Combined.json"
	}
	elseif ($Output -eq "SOF-ELK" -and ($MergeOutput.IsPresent)) {
		Write-LogFile -Message "[INFO] Merging output files into one file"
		Merge-OutputFiles -OutputDir $OutputDir -OutputType "SOF-ELK" -MergedFileName "SignInLogs-Combined.json"
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

	.PARAMETER All
    When specified along with UserIds, this parameter filters the results to include events where the provided UserIds match any user principal name found in either the userPrincipalNames or targetResources fields.

	.PARAMETER Encoding
	Encoding is the parameter specifying the encoding of the JSON output file.
	Default: UTF8

	.PARAMETER MergeOutput
	MergeOutput is the parameter specifying if you wish to merge outputs to a single file
	Default: No

	.EXAMPLE
	Get-ADAuditLogsGraph
	Get directory audit logs.

	.EXAMPLE
	Get-ADAuditLogsGraph -Application
	Get directory audit logs via application authentication.

	.EXAMPLE
    Get-ADAuditLogsGraph -UserIds 'user@example.com' -All
    Get sign-in logs for 'user@example.com', including both userPrincipalName and targetResources in the filter.

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
		[switch]$MergeOutput,
		[string]$UserIds,
        [switch]$All
	)

	$requiredScopes = @("AuditLog.Read.All", "Directory.Read.All")
    $graphAuth = Get-GraphAuthType -RequiredScopes $RequiredScopes

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
			$response = Invoke-MgGraphRequest -Uri $apiUrl -Method Get -ContentType "application/json; odata.metadata=minimal; odata.streaming=true;" -OutputType Json
			$responseJson = $response | ConvertFrom-Json 
			if ($responseJson.value) {
				$date = [datetime]::Now.ToString('yyyyMMddHHmmss') 
				$filePath = Join-Path -Path $OutputDir -ChildPath "$($date)-AuditLogs.json"
                $responseJson.value | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath -Append -Encoding $Encoding
                
				#$dates = $responseJson.value | ForEach-Object { [DateTime]::Parse($_.activityDateTime) } | Sort-Object
				
				$dates = $responseJson.value | ForEach-Object {
					[DateTime]::Parse($_.activityDateTime, [System.Globalization.CultureInfo]::InvariantCulture)
				} | Sort-Object

                $from =  $dates | Select-Object -First 1
                $fromstr =  $from.ToString('yyyy-MM-ddTHH:mmZ')
                $to = ($dates | Select-Object -Last 1).ToString('yyyy-MM-ddTHH:mmZ')
                $count = ($responseJson.value | measure).Count
    			Write-LogFile -Message "[INFO] Audit logs written to $filePath ($count records between $fromstr and $to)" -Color Green
			}
			$apiUrl = $responseJson.'@odata.nextLink'
		} While ($apiUrl)
	}
	catch {
		Write-logFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Color "Red"
    }
	
	if ($MergeOutput.IsPresent) {
		Write-LogFile -Message "[INFO] Merging output files into one file"
		Merge-OutputFiles -OutputDir $OutputDir -OutputType "JSON" -MergedFileName "AuditLogs-Combined.json"
	}
	
	Write-LogFile -Message "[INFO] Acquisition complete, check the $($OutputDir) directory for your files.." -Color "Green"		
}
	
