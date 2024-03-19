# This contains functions for getting Azure AD logging

function Get-ADSignInLogs {
<#
    .SYNOPSIS
    Get sign-in logs.

    .DESCRIPTION
    The Get-ADSignInLogs cmdlet collects the contents of the Azure Active Directory sign-in logs.
	The output will be written to: Output\AzureAD\SignInLogs.json

	.PARAMETER After
	The After parameter specifies the date from which all logs need to be collected.

	.PARAMETER Before
    The Before parameter specifies the date before which all logs need to be collected.

	.PARAMETER OutputDir
    OutputDir is the parameter specifying the output directory.
	Default: Output\AzureAD

	.PARAMETER Encoding
    Encoding is the parameter specifying the encoding of the JSON output file.
	Default: UTF8

	.PARAMETER UserIds
    UserIds is the UserIds parameter filtering the log entries by the account of the user who performed the actions.
    
    .EXAMPLE
    Get-ADSignInLogs
	Get all sign-in logs.

    .EXAMPLE
    Get-ADAuditLogs -UserIds Test@invictus-ir.com
    Get sign-in logs for the user Test@invictus-ir.com.

	.EXAMPLE
    Get-ADSignInLogs -endDate 2023-04-12
	Get sign-in logs before 2023-04-12.

	.EXAMPLE
    Get-ADSignInLogs -startDate 2023-04-12
	Get sign-in logs after 2023-04-12.
#>
	[CmdletBinding()]
	param(
		[string]$startDate,
		[string]$endDate,
		[string]$outputDir,
		[string]$UserIds,
		[string]$Encoding,
		[string]$Interval
	)

	try {
		import-module AzureADPreview -force -ErrorAction stop
		$areYouConnected = Get-AzureADAuditSignInLogs -ErrorAction stop
	}
	catch {
		Write-logFile -Message "[WARNING] You must call Connect-Azure or install AzureADPreview before running this script" -Color "Red"
		break
	}

	Write-logFile -Message "[INFO] Running Get-AADSignInLogs" -Color "Green"

	StartDateAz
	EndDate

	if ($Interval -eq "") {
		$Interval = 1440
		Write-LogFile -Message "[INFO] Setting the Interval to the default value of 1440"
	}

	if ($Encoding -eq "" ){
		$Encoding = "UTF8"
	}

	$date = [datetime]::Now.ToString('yyyyMMddHHmmss') 
	if ($OutputDir -eq "" ){
		$OutputDir = "Output\AzureAD\$date"
		if (!(test-path $OutputDir)) {
			write-logFile -Message "[INFO] Creating the following directory: $OutputDir"
			New-Item -ItemType Directory -Force -Name $OutputDir | Out-Null
		}
	}

	if ($UserIds){
		Write-LogFile -Message "[INFO] UserID's eq $($UserIds)"
	}


	$filePath = "$OutputDir\SignInLogs.json"
		
	[DateTime]$currentStart = $script:StartDate
	[DateTime]$currentEnd = $script:EndDate
	[DateTime]$lastLog = $script:EndDate
	$currentDay = 0  

	Write-LogFile -Message "[INFO] Extracting all available Directory Sign In Logs between $($currentStart.ToUniversalTime().ToString("yyyy-MM-dd")) and $($currentEnd.ToUniversalTime().ToString("yyyy-MM-dd"))" -Color "Green"
	if($currentStart -gt $script:EndDate){
		Write-LogFile -Message "[ERROR] $($currentStart.ToString("yyyy-MM-dd")) is greather than $($script:EndDate.ToString("yyyy-MM-dd")) - are you sure you put in the correct year? Exiting!" -Color "Red"
		return
	}

	while ($currentStart -lt $script:EndDate) {			
		$currentEnd = $currentStart.AddMinutes($Interval)       
		if ($UserIds){
			Write-LogFile -Message "[INFO] Collecting Directory Sign In logs between $($currentStart.ToUniversalTime().ToString("yyyy-MM-dd")) and $($currentEnd.ToUniversalTime().ToString("yyyy-MM-dd"))."
			try{
				[Array]$results =  Get-AzureADAuditSignInLogs -All $true -Filter "UserPrincipalName eq '$($Userids)' and createdDateTime lt $($currentEnd.ToString("yyyy-MM-dd")) and createdDateTime gt $($currentStart.ToString("yyyy-MM-dd"))"
			}
			catch{
				Start-Sleep -Seconds 20
				[Array]$results =  Get-AzureADAuditSignInLogs -All $true -Filter "UserPrincipalName eq '$($Userids)' and createdDateTime lt $($currentEnd.ToString("yyyy-MM-dd")) and createdDateTime gt $($currentStart.ToString("yyyy-MM-dd"))"
			}
		}
		else {
			try{
				[Array]$results =  Get-AzureADAuditSignInLogs -All $true -Filter "createdDateTime lt $($currentEnd.ToString("yyyy-MM-dd")) and createdDateTime gt $($currentStart.ToString("yyyy-MM-dd"))"
			}
			catch{
				Start-Sleep -Seconds 20
				[Array]$results =  Get-AzureADAuditSignInLogs -All $true -Filter "createdDateTime lt $($currentEnd.ToString("yyyy-MM-dd")) and createdDateTime gt $($currentStart.ToString("yyyy-MM-dd"))"
			}
		}
		if ($null -eq $results -or $results.Count -eq 0) {
			Write-LogFile -Message "[WARNING] Empty data set returned between $($currentStart.ToUniversalTime().ToString("yyyy-MM-dd")) and $($currentEnd.ToUniversalTime().ToString("yyyy-MM-dd")). Moving On!"				
		}
		else {					
			$currentCount = $results.Count
			if ($currentDay -ne 0){
				$currentTotal = $currentCount + $results.Count
			}
			else {
				$currentTotal = $currentCount 
			}
			
			Write-LogFile -Message "[INFO] Found $currentCount Directory Sign In Logs between $($currentStart.ToUniversalTime().ToString("yyyy-MM-dd")) and $($currentEnd.ToUniversalTime().ToString("yyyy-MM-dd"))" -Color "Green"
				
			$filePath = "$OutputDir\SignInLogs-$($CurrentStart.ToString("yyyyMMdd"))-$($CurrentEnd.ToString("yyyyMMdd"))"
			$results | ConvertTo-Json -Depth 100 | Out-File -Append $filePath -Encoding $Encoding

			Write-LogFile -Message "[INFO] Successfully retrieved $($currentCount) records out of total $($currentTotal) for the current time range."							
		}
		[Array]$results = @()
		$CurrentStart = $CurrentEnd
  		$currentDay++
	}
	Write-LogFile -Message "[INFO] Acquisition complete, check the $($OutputDir) directory for your files.." -Color "Green"		
}

function Get-ADAuditLogs {
<#
    .SYNOPSIS
    Get directory audit logs.

    .DESCRIPTION
    The Get-ADAuditLogs cmdlet collects the contents of the Azure Active Directory Audit logs.
	The output will be written to: "Output\AzureAD\Auditlogs.json

	.PARAMETER After
	The After parameter specifies the date from which all logs need to be collected.

	.PARAMETER Before
    The Before parameter specifies the date before which all logs need to be collected.

	.PARAMETER OutputDir
    outputDir is the parameter specifying the output directory.
	Default: Output\AzureAD

	.PARAMETER Encoding
    Encoding is the parameter specifying the encoding of the JSON output file.
	Default: UTF8

    .PARAMETER UserIds
    UserIds is the UserIds parameter filtering the log entries by the account of the user who performed the actions.
    
    .EXAMPLE
    Get-ADAuditLogs
	Get directory audit logs.

    .EXAMPLE
    Get-ADAuditLogs -UserIds Test@invictus-ir.com
    Get directory audit logs for the user Test@invictus-ir.com.

	.EXAMPLE
    Get-ADAuditLogs -Before 2023-04-12
	Get directory audit logs before 2023-04-12.

	.EXAMPLE
    Get-ADAuditLogs -After 2023-04-12
	Get directory audit logs after 2023-04-12.
#>
	[CmdletBinding()]
	param(
		[string]$After,
		[string]$Before,
		[string]$OutputDir,
        [string]$UserIds,
		[string]$Encoding
	)

	try {
		$areYouConnected = Get-AzureADAuditDirectoryLogs -ErrorAction stop
	}
	catch {
		Write-logFile -Message "[WARNING] You must call Connect-Azure before running this script" -Color "Red"
		break
	}

	if ($Encoding -eq "" ){
		$Encoding = "UTF8"
	}

	Write-logFile -Message "[INFO] Running Get-ADAuditLogs" -Color "Green"
	
	$date = [datetime]::Now.ToString('yyyyMMddHHmmss') 
	if ($OutputDir -eq "" ){
		$OutputDir = "Output\AzureAD\$date"
		if (!(test-path $OutputDir)) {
			New-Item -ItemType Directory -Force -Name $OutputDir | Out-Null
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

	$filePath = "$OutputDir\Auditlogs.json"

	if (($After -eq "") -and ($Before -eq "")) {
		Write-logFile -Message "[INFO] Collecting the Directory audit logs"

        if ($UserIds){
            try{
                $auditLogs = Get-AzureADAuditDirectoryLogs -All $true -Filter "initiatedBy/user/userPrincipalName eq '$Userids'" | Select-Object Id,Category,CorrelationId,Result,ResultReason,ActivityDisplayName,@{N='ActivityDateTime';E={$_.ActivityDateTime.ToString()}},LoggedByService,OperationType,InitiatedBy,TargetResources,AdditionalDetails
				$auditLogs | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath -Encoding $Encoding

				Write-logFile -Message "[INFO] Directory audit logs written to $filePath" -Color "Green"
            }
            catch{
                Start-Sleep -Seconds 20
				$auditLogs = Get-AzureADAuditDirectoryLogs -All $true -Filter "initiatedBy/user/userPrincipalName eq '$Userids'" | Select-Object Id,Category,CorrelationId,Result,ResultReason,ActivityDisplayName,@{N='ActivityDateTime';E={$_.ActivityDateTime.ToString()}},LoggedByService,OperationType,InitiatedBy,TargetResources,AdditionalDetails
				$auditLogs | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath -Encoding $Encoding

				Write-logFile -Message "[INFO] Directory audit logs written to $filePath" -Color "Green"
            }
        }
        else{
		    try{
			    $auditLogs = Get-AzureADAuditDirectoryLogs -All $true | Select-Object Id,Category,CorrelationId,Result,ResultReason,ActivityDisplayName,@{N='ActivityDateTime';E={$_.ActivityDateTime.ToString()}},LoggedByService,OperationType,InitiatedBy,TargetResources,AdditionalDetails
			    $auditLogs | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath -Encoding $Encoding
			
			    Write-logFile -Message "[INFO] Directory audit logs written to $filePath" -Color "Green"
		    }
		    catch{
			    Start-Sleep -Seconds 20
			    $auditLogs = Get-AzureADAuditDirectoryLogs -All $true | Select-Object Id,Category,CorrelationId,Result,ResultReason,ActivityDisplayName,@{N='ActivityDateTime';E={$_.ActivityDateTime.ToString()}},LoggedByService,OperationType,InitiatedBy,TargetResources,AdditionalDetails
			    $auditLogs | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath -Encoding $Encoding
			
			    Write-logFile -Message "[INFO] Directory audit logs written to $filePath" -Color "Green"
		    }
        }
	}

	elseif (($After -ne "") -and ($Before -eq "")) {
		Write-logFile -Message "[INFO] Collecting the Directory audit logs on or after $After"

        if ($Userids){
            try{
                $auditLogs = Get-AzureADAuditDirectoryLogs -All $true -Filter "initiatedBy/user/userPrincipalName eq '$Userids' and activityDateTime gt $After" | Select-Object Id,Category,CorrelationId,Result,ResultReason,ActivityDisplayName,@{N='ActivityDateTime';E={$_.ActivityDateTime.ToString()}},LoggedByService,OperationType,InitiatedBy,TargetResources,AdditionalDetails
				$auditLogs | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath -Encoding $Encoding

				Write-logFile -Message "[INFO] Directory audit logs written to $filePath" -Color "Green"
            }
            catch{
                Start-Sleep -Seconds 20
				$auditLogs = Get-AzureADAuditDirectoryLogs -All $true -Filter "initiatedBy/user/userPrincipalName eq '$Userids' and activityDateTime lt $Before" | Select-Object Id,Category,CorrelationId,Result,ResultReason,ActivityDisplayName,@{N='ActivityDateTime';E={$_.ActivityDateTime.ToString()}},LoggedByService,OperationType,InitiatedBy,TargetResources,AdditionalDetails
				$auditLogs | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath -Encoding $Encoding

				Write-logFile -Message "[INFO] Directory audit logs written to $filePath" -Color "Green"
            }
        }     
		else{
		    try{
			    $auditLogs = Get-AzureADAuditDirectoryLogs -All $true -Filter "activityDateTime gt $After" | Select-Object Id,Category,CorrelationId,Result,ResultReason,ActivityDisplayName,@{N='ActivityDateTime';E={$_.ActivityDateTime.ToString()}},LoggedByService,OperationType,InitiatedBy,TargetResources,AdditionalDetails
			    $auditLogs | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath -Encoding $Encoding
			
			    Write-logFile -Message "[INFO] Directory audit logs written to $filePath" -Color "Green"
		    }
		    catch{
			    Start-Sleep -Seconds 20
			    $auditLogs = Get-AzureADAuditDirectoryLogs -All $true -Filter "activityDateTime gt $After" | Select-Object Id,Category,CorrelationId,Result,ResultReason,ActivityDisplayName,@{N='ActivityDateTime';E={$_.ActivityDateTime.ToString()}},LoggedByService,OperationType,InitiatedBy,TargetResources,AdditionalDetails
			    $auditLogs | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath -Encoding $Encoding
			
			    Write-logFile -Message "[INFO] Directory audit logs written to $filePath" -Color "Green"
		    }
        }
	}

	elseif (($Before -ne "") -and ($After -eq "")) {
		Write-logFile -Message "[INFO] Collecting the Directory audit logs logs on or before $Before"

        if ($UserIds){
            try{
                $auditLogs = Get-AzureADAuditDirectoryLogs -All $true -Filter "initiatedBy/user/userPrincipalName eq '$Userids' and activityDateTime lt $Before" | Select-Object Id,Category,CorrelationId,Result,ResultReason,ActivityDisplayName,@{N='ActivityDateTime';E={$_.ActivityDateTime.ToString()}},LoggedByService,OperationType,InitiatedBy,TargetResources,AdditionalDetails
				$auditLogs | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath -Encoding $Encoding

				Write-logFile -Message "[INFO] Directory audit logs written to $filePath" -Color "Green"
            }
            catch{
                Start-Sleep -Seconds 20
				$auditLogs = Get-AzureADAuditDirectoryLogs -All $true -Filter "initiatedBy/user/userPrincipalName eq '$Userids' and createdDateTime lt $Before" | Select-Object Id,Category,CorrelationId,Result,ResultReason,ActivityDisplayName,@{N='ActivityDateTime';E={$_.ActivityDateTime.ToString()}},LoggedByService,OperationType,InitiatedBy,TargetResources,AdditionalDetails
				$auditLogs | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath -Encoding $Encoding

				Write-logFile -Message "[INFO] Directory audit logs written to $filePath" -Color "Green"
            }
        }
        else{
		    try{
			    $auditLogs = Get-AzureADAuditDirectoryLogs -All $true -Filter "activityDateTime lt $Before" | Select-Object Id,Category,CorrelationId,Result,ResultReason,ActivityDisplayName,@{N='ActivityDateTime';E={$_.ActivityDateTime.ToString()}},LoggedByService,OperationType,InitiatedBy,TargetResources,AdditionalDetails
			    $auditLogs | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath -Encoding $Encoding
			
			    Write-logFile -Message "[INFO] Directory audit logs written to $filePath" -Color "Green"
		    }
		    catch{
			    Start-Sleep -Seconds 20
			    $auditLogs = Get-AzureADAuditDirectoryLogs -All $true -Filter "activityDateTime lt $Before" | Select-Object Id,Category,CorrelationId,Result,ResultReason,ActivityDisplayName,@{N='ActivityDateTime';E={$_.ActivityDateTime.ToString()}},LoggedByService,OperationType,InitiatedBy,TargetResources,AdditionalDetails
			    $auditLogs | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath -Encoding $Encoding
			
			    Write-logFile -Message "[INFO] Directory audit logs written to $filePath" -Color "Green"
		    }
        }
	}

	else {
		Write-logFile -Message "[WARNING] Please only provide a start date or end date" -Color "Red"
	}
}
